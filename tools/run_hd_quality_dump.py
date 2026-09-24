"""
run_hd_quality_dump.py

Spawns the game, loads a Frida agent that exposes getCount()/getRecords()
via rpc.exports (i.e. dump_hd_quality_list.js or dump_recommend_config.js,
bundled), and streams its console output live. Press Enter at any point to
pull the accumulated table via RPC, write it to a JSON file, and detach.

Pick the target script with --agent (default: AGENT_PATH below). It must be an
agent that exposes rpc.exports (getCount/getRecords/clear): that is
dump_hd_quality_list.js or dump_recommend_config.js. dump_selection_logic.js,
the probe and list_il2cpp_exports.js don't, and would fail at the
get_count() call.

The agent must be the *bundled* one under dist/, built with
`npm run build` from the corresponding scripts/*.js source (see README.md's
"Building the agents") - not scripts/ directly, which uses ES module
imports that only resolve after bundling.

TARGET, REMOTE_ADDR, and FRIDA_OFFSET (an RVA - the hooked function's Ghidra
address with Image Base = 0, not a file offset; see README.md's "RVA vs file
offset") default to the values in config.py, and
can be overridden per run - which is what you want while probing offsets, so
you don't have to edit a file between attempts:

    CLI flag       env var             config.py
    --target ID    FRIDA_TARGET        TARGET
    --remote H:P   FRIDA_REMOTE_ADDR   REMOTE_ADDR
    --offset HEX   FRIDA_OFFSET        FRIDA_OFFSET

Precedence is CLI > env > config.py, and the resolved values (with their
source) are printed at startup. The offset is injected into the loaded
agent's own FRIDA_OFFSET constant automatically, and recorded in the exported
JSON's `meta`. Offsets are hex, with or without a 0x prefix.

The exported JSON is wrapped as `{"meta": {...}, "records": [...]}` rather
than a bare array, so a records.json from one dump can't get silently
mixed up with one from a different build/offset later - see `meta` below.
When trying several offsets in a row, give each run its own --out so the
next run doesn't overwrite the previous dump.

Lifecycle: if anything fails between spawn and resume (attach, script
creation, script load - e.g. a hook that can't be installed at the given
offset), the still-suspended process is killed rather than left frozen, and
the session is always detached on the way out (both handled by
_common.spawn_agent(), shared with list_exports.py). Ctrl+C at the "press
Enter" prompt is treated like Enter: the records collected so far are exported.

Usage:
    python run_hd_quality_dump.py --offset 0xab68fc8
    python run_hd_quality_dump.py --offset ab68fc8 --out records_ab68fc8.json
    FRIDA_OFFSET=0xab68fc8 python run_hd_quality_dump.py
    python run_hd_quality_dump.py --agent ../dist/dump_recommend_config.js --offset 0x...

AGENT_PATH's default is resolved from this file's own location (via
__file__), not the current working directory, so the driver finds dist/
whether you run it as `python run_hd_quality_dump.py` from inside tools/,
`python tools/run_hd_quality_dump.py` from the repo root, or anything
else. An explicit `--agent some/relative/path.js`, by contrast, IS taken
relative to your current directory, same as any other CLI path argument -
that's expected, not the same bug.

OUT_PATH's default ("records.json") is deliberately left relative to the
current directory instead - unlike the agent, an *output* file should
land wherever you happen to be running the command from, not next to the
script. Pass an absolute --out if you want it to land somewhere fixed
regardless of CWD.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import frida

from _common import (add_override_args, is_gitignored, load_agent_source,
                     resolve_settings, spawn_agent)

if TYPE_CHECKING:
    # Only needed to resolve the type comment on `recs` below - guarding it
    # this way keeps the import out of the runtime path entirely (unlike a
    # bare `noqa: F401`, which only silences the linter but still executes
    # the import). Some pyflakes versions still flag names that are only
    # referenced in a `# type:` comment, hence the noqa staying here too.
    from records import DeviceQualityRecord, RecommendConfigRecord  # noqa: F401

# Anchored to this file's location, not the CWD - see the module docstring.
REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_PATH = str(REPO_ROOT / "dist" / "dump_hd_quality_list.js")
OUT_PATH = "records.json"


def on_message(message, data):
    if message.get("type") == "error":
        print("[agent error]", message.get("stack") or message.get("description"))
    elif message.get("type") == "send":
        print(message.get("payload"))


def export_records(script, settings, args):
    """Pull the accumulated table over RPC and write it, wrapped with `meta`,
    to args.out. Errors are reported, not raised: the caller still has to
    detach."""
    try:
        count = script.exports_sync.get_count()
        print(f"[*] Collected {count} unique records. Exporting...")
        # Shape depends on which agent was loaded (--agent): a list of
        # DeviceQualityRecord for dump_hd_quality_list.js, or
        # RecommendConfigRecord for dump_recommend_config.js - see
        # tools/records.py. Not asserted/validated at runtime, same as the
        # rest of this RPC round-trip - just documents what to expect.
        recs = script.exports_sync.get_records()  # type: list[DeviceQualityRecord] | list[RecommendConfigRecord]
        output = {
            "meta": {
                "target": settings.target,
                "agent": os.path.basename(args.agent),
                "offset": hex(settings.offset),
                "dumped_at": datetime.now(timezone.utc).isoformat(),
            },
            "records": recs,
        }
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, indent=2)
        print(f"[+] Wrote {args.out}")
    except Exception as e:
        print("[!] Error retrieving data (does the loaded agent expose rpc.exports?):", e)


def main():
    ap = argparse.ArgumentParser(
        description="Spawn the game, stream a bundled Frida agent's output, and "
                    "export its collected records to JSON when you press Enter.")
    add_override_args(ap, offset=True)
    ap.add_argument("--agent", default=AGENT_PATH, metavar="PATH",
                    help=f"bundled agent under dist/ to load "
                         f"(default: {Path(AGENT_PATH).relative_to(REPO_ROOT)})")
    ap.add_argument("--out", default=OUT_PATH, metavar="PATH",
                    help=f"where to write the exported JSON (default: {OUT_PATH})")
    args = ap.parse_args()
    settings = resolve_settings(args, offset=True)

    if settings.offset == 0:
        # Fail here rather than after spawning the app: the agent itself
        # refuses to hook at 0x0, so there's nothing useful to do with it.
        sys.exit("[!] RVA is 0x0 - pass --offset, set $FRIDA_OFFSET, or set "
                 "FRIDA_OFFSET in config.py. Not spawning the app.")

    if is_gitignored(args.out) is False:
        # The export's `meta` records the real target and offset, and
        # check_placeholders.py deliberately doesn't scan .json - so a dump
        # under a name .gitignore doesn't cover is one `git add -A` away from
        # being committed. (`records*.json` is covered.)
        print(f"[!] --out {args.out} is NOT covered by .gitignore, and the export records "
              f"the real target + offset in `meta`. Keep it out of git - or use a "
              f"records*.json name.")

    source = load_agent_source(args.agent, settings.offset)

    device = frida.get_device_manager().add_remote_device(settings.remote_addr)

    def on_detached(reason):
        print(f"[!] Session detached, reason: {reason}")

    print(f"[*] Spawning {settings.target}...")
    with spawn_agent(device, settings.target, source, on_message, on_detached) as run:
        run.resume()
        print(f"[*] Spawned and resumed, pid={run.pid}")
        print("[*] Listening - new records print immediately. Play through the game normally.")
        print("[*] Press Enter at any point to export the records and exit.\n")

        try:
            input()
        except KeyboardInterrupt:
            print("\n[*] Interrupted - exporting what was collected so far.")

        export_records(run.script, settings, args)


if __name__ == "__main__":
    main()
