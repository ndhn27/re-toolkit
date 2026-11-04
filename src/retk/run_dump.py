"""
run_dump.py

Spawns the target app, loads a Frida agent that exposes getCount()/getRecords()
via rpc.exports (i.e. dump_table_a.js or dump_table_b.js, bundled), hands it
what it needs to know through rpc.exports.init(), and streams its console
output live. Press Enter at any point to pull the accumulated table via RPC,
write it to a JSON file, and detach.

What the agent needs - the RVA to hook, the module, the record layout - comes
from your PROFILE (--profile NAME; see profiles.py and README.md's
"Profiles"): a JSON file kept outside git. Nothing target-specific is ever
compiled into an agent or written into this repo.

Pick the agent with --agent (default: AGENT_PATH below). It must expose
rpc.exports.getCount/getRecords/clear: that is dump_table_a.js or
dump_table_b.js. trace_lookup.js, probe_record.js and list_il2cpp_exports.js
don't - they only print - and this driver says so right after the agent has
been loaded, before the app is resumed (and kills the still-suspended app),
instead of letting you use the app for a while and fail at export. Run those
with `frida -P` (see README.md's "Usage"; `retk profile params NAME --offset
KEY=HEX` takes the same overrides as --offset here) or, for
list_il2cpp_exports.js, `retk exports`. The agent must be the *bundled*
one (dist/ in a checkout, built with `npm run build` from the corresponding
scripts/*.js source - see README.md's "Building the agents"; inside the package
when installed) - not scripts/ directly, which uses ES module imports that only
resolve after bundling. --agent takes a path or just the bundle's name
(`--agent dump_table_b.js`), looked up where the bundles are.

Each agent asks the profile for the offsets it needs by name (dump_table_a.js:
`table_a`, dump_table_b.js: `table_b`) and refuses to hook at 0 - the agent
fails, and this driver kills the still-suspended app and says which key is
missing. An RVA is the hooked function's Ghidra address with Image Base = 0,
not a file offset; see README.md's "RVA vs file offset". Any value can be
overridden for one run - which is what you want while probing offsets, so you
don't have to edit the profile between attempts:

    --profile NAME      profiles/NAME.json
    --target ID         overrides the profile's target
    --remote H:P        overrides the profile's frida-server address
    --offset KEY=HEX    overrides one RVA (repeatable), hex with or without 0x; it also
                        beats the profile's `names` entry for that key
    --resolve MODE      auto (default) | names | rva: how the hook point is found when the
                        profile names it (`names.methods`) - see below

    --attach PROCESS    attaches to an app that is ALREADY running (a name or a pid) instead of
                        spawning it; it is never resumed or killed, only detached from at the end
    --snapshot [RECORD] reads the table out of the running app (the profile's `names.snapshot`: a static
                        field and/or the live instances of the record's class) instead of hooking the
                        unpack - for an attach that comes after the app unpacked everything. Needs
                        --attach; uses dist/snapshot_records.js; exits 5, writing nothing, when it finds no
                        record (README.md's "Snapshot"). --snapshot-timeout SECONDS (default 120)

A profile may also NAME its hook points (`Namespace.Class::Method`): the agent then asks the
IL2CPP runtime for the address first and uses the RVA only as the fallback (scripts/_resolve.js;
README.md's "Looking things up by name"). This driver prints where each hook point came from,
records the RVAs that were really hooked in `meta.offsets` and the evidence in `meta.resolution`,
and exits with status 4 - after writing what it has - when a hook point ended with no address at
all (the name did not resolve and the profile has no RVA to fall back to, or `--resolve names`).

The resolved values (with their source) are printed at startup, and the
offsets in use are recorded in the exported JSON's `meta`.

Layout self-check: the agent counts how often what it read contradicted the
profile's layout (the class word at +0, string sanity, the `expect` a profile
puts on a field, ... - scripts/_canary.js), and this driver judges the counts
(layout_check.py) when it exports. The verdict is printed, recorded in
`meta.layout_check`, and a FAILED check makes the exit status 3 - the file is
still written (so nothing is lost) but marked, so a dump read with the wrong
layout can't be mistaken for a good one later:

    --no-layout-check         skip it
    --layout-tolerance F      how large a fraction of reads may contradict a check
                              before it fails (default 0.05; 0 = none at all)

Early gate: the agent also sends a snapshot of those counts once it has read the first N
records (--layout-gate N, default 16, 0 = off), and this driver judges it at once - with the
same rules but a looser line (layout_check.GATE_TOLERANCE: it is for a layout that is wrong
about nearly everything, not for one stray record). A table is dumped for minutes while
someone plays the game; finding out after the Enter key that the layout was wrong from
record 1 wastes all of it. The agent also probes where the fields WOULD be if the whole
layout had moved (every offset shifted by -32..+32 bytes), so the report can say "LAYOUT MAY
HAVE CHANGED: the fields fit 8 bytes further in - the header would be 24 bytes, not 16"
rather than only "failed" (layout_check.py explains what is and isn't claimed):

    --layout-gate N           judge the first N records right away (0 = off)
    --on-drift stop|warn      stop (default): end the run on a failing gate and write the records
                              read so far to OUT.suspect.json - never to OUT; warn: report, go on,
                              and let the export-time check decide

The exported JSON is wrapped as `{"meta": {...}, "records": [...]}` rather
than a bare array, so a records.json from one dump can't get silently
mixed up with one from a different build/offset later - see `meta` below.

Unreadable strings: when the agent cannot read a string field (an unmapped
pointer, an absurd length) the field is `null` in its record and the record
carries `_unreadable: ["field", ...]`, so a read error cannot pass for data. The
driver prints those records by key, and `meta.unreadable_count` /
`meta.unreadable_records` list them (the first 100) whether or not the layout
check passed or ran: a stray one is under the layout check's tolerance by design.
A record with nothing unreadable has no `_unreadable` key at all.
When trying several offsets in a row, give each run its own --out so the
next run doesn't overwrite the previous dump.

Lifecycle: if anything fails between spawn and resume (attach, script
creation, script load, the agent's init - e.g. a missing offset), the
still-suspended process is killed rather than left frozen, and the session is
always detached on the way out (both handled by _common.spawn_agent(), shared
with list_exports.py). Ctrl+C at the "press Enter" prompt is treated like
Enter: the records collected so far are exported.

Usage:
    retk dump --profile myapp
    retk dump --profile myapp --offset table_a=0xab68fc8 --out records_ab68fc8.json
    retk dump --profile myapp --agent dump_table_b.js

AGENT_PATH's default is found by resources.agent_path(), not from the current
working directory, so the driver finds the bundles wherever you run it from. An
explicit `--agent some/relative/path.js`, by contrast, IS taken relative to your
current directory, same as any other CLI path argument - that's expected, not
the same bug (a bare name like `dump_table_b.js` is a bundle name, see above).

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
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import frida

from . import layout_check, resources
from ._common import (AgentInitError, ProcessNotFound, add_override_args, attach_agent, is_gitignored,
                     load_agent_source, resolve_settings, spawn_agent, wait_for_enter)

# Found where the bundles are, not relative to the CWD - see the module docstring.
AGENT_PATH = resources.agent_path("dump_table_a.js")
SNAPSHOT_AGENT_PATH = resources.agent_path("snapshot_records.js")
OUT_PATH = "records.json"
SNAPSHOT_TIMEOUT = 120           # seconds a snapshot may take (a heap scan of a big game is the slow case)

UNREADABLE_KEY = "_unreadable"   # keep equal to UNREADABLE_KEY in scripts/_lib.js (tests check it)
UNREADABLE_IN_META = 100         # how many unreadable records `meta` lists (the count is always exact)
UNREADABLE_PRINTED = 20          # how many the console lists
EXIT_NOT_HOOKED = 4              # exit status when a hook point ended with no address (see render_resolution)
EXIT_SNAPSHOT_FAILED = 5         # exit status when a snapshot found no record (nothing is written: see take_snapshot)


def on_message(message, data):
    if message.get("type") == "error":
        print("[agent error]", message.get("stack") or message.get("description"))
    elif message.get("type") == "send":
        print(message.get("payload"))


ON_DRIFT_ACTIONS = ("stop", "warn")


class LayoutGate:
    """Judges the snapshot the agent sends after its first N records (--layout-gate N)
    and, on a failure, either ends the run on the spot (`stop`) or only says so (`warn`).

    The agent counts; the verdict is made here, by layout_check.judge_gate(), so the rule
    is the same plain Python as the export-time check. It arrives on a Frida thread, so
    the outcome is left in attributes and an Event for the main thread to act on."""

    def __init__(self, sample, tolerance, action):
        self.sample = sample
        self.tolerance = tolerance
        self.action = action
        self.verdict = None                    # the verdict on the snapshot, once it arrived
        self.tripped = threading.Event()       # set when the run should stop now

    def handle(self, payload):
        health = payload.get("health") if isinstance(payload, dict) else None
        self.verdict = layout_check.judge_gate(health, self.tolerance)
        for line in layout_check.render_gate(self.verdict, self.sample):
            print(line)
        if self.verdict.status == layout_check.FAIL:
            if self.action == "stop":
                print("    Stopping now; what was read goes to a .suspect file, not to --out "
                      "(--on-drift warn keeps collecting and leaves the decision to the export-time check).")
                self.tripped.set()
            else:
                print("    Continuing (--on-drift warn); the export-time check decides the final verdict.")

    def meta(self):
        return {"sample": self.sample, "action": self.action,
                "status": self.verdict.status if self.verdict else None,
                "stopped": self.tripped.is_set()}

    def message_handler(self):
        """The `on_message` to give spawn_agent(): the gate's snapshot goes to handle(), the rest as before."""
        def on_gate_message(message, data):
            payload = message.get("payload") if message.get("type") == "send" else None
            if isinstance(payload, dict) and payload.get("type") == "layout-sample":
                self.handle(payload)
            else:
                on_message(message, data)
        return on_gate_message


def suspect_path(out):
    """Where a stopped run's records go instead of `out`: records.json -> records.suspect.json."""
    stem, ext = os.path.splitext(out)
    return f"{stem}.suspect{ext}"


class NotADumpAgent(RuntimeError):
    """The loaded agent has no getCount()/getRecords(): it prints, it does not collect."""


def require_dump_agent(run, agent_path):
    """Fail BEFORE the app is resumed if the agent can't be exported from.

    trace_lookup.js, probe_record.js and list_il2cpp_exports.js stream their
    findings to the console and expose no getCount(); without this the driver
    would spawn the app, stream the log, and only after you pressed Enter say
    that there was nothing to export (and exit 0). getCount() is the cheapest
    call the export itself makes first, so asking for it now tests exactly that.
    Raising inside the `with` block makes spawn_agent() kill the suspended app.
    """
    try:
        run.script.exports_sync.get_count()
    except Exception as e:  # frida raises a generic error for a missing export
        raise NotADumpAgent(
            f"{os.path.basename(agent_path)} exposes no getCount()/getRecords() ({e}), so there is "
            f"nothing for this driver to export. run_dump.py is for dump_table_a.js / "
            f"dump_table_b.js; attach the others with `frida -P \"$(retk profile "
            f"params NAME --offset KEY=HEX)\"` (README.md, \"Usage\") or use `retk exports`") from e


def take_snapshot(script, timeout, poll=0.25, sleep=time.sleep, clock=time.monotonic, say=print):
    """Ask the snapshot agent (scripts/snapshot_records.js) to take its snapshot and wait for it. Returns the
    agent's final status - {"state": "done" | "failed", "count", "sources": [...], "why"} - and never raises for
    a snapshot that failed: that is a status. Progress changes are printed through `say`."""
    try:
        ack = script.exports_sync.snapshot()
    except Exception as e:
        return {"state": "failed", "count": 0, "sources": [], "why": f"the agent has no snapshot(): {e}"}
    if isinstance(ack, dict) and ack.get("started") is False:
        return {"state": "failed", "count": 0, "sources": [], "why": ack.get("why") or "the agent did not start a snapshot"}
    deadline, last = clock() + timeout, None
    while True:
        try:
            status = script.exports_sync.get_snapshot()
        except Exception as e:
            return {"state": "failed", "count": 0, "sources": [], "why": f"could not ask the agent for its status: {e}"}
        if status.get("state") != last:
            last = status.get("state")
            if last in ("waiting", "running"):
                say(f"[*] Snapshot {last}...")
        if status.get("state") in ("done", "failed"):
            return status
        if clock() >= deadline:
            return {**status, "state": "failed", "why": f"no result after {timeout:g}s (the agent still says {status.get('state')!r})"}
        sleep(poll)


def render_snapshot(status):
    """Console lines for a snapshot status: one per source, then the verdict."""
    lines = []
    for src in status.get("sources", []):
        what = {"ok": "[+]", "empty": "[!]"}.get(src.get("status"), "[!]")
        detail = [f"{src.get('accepted', 0)} record(s)"]
        if src.get("source") == "heap":
            detail = [f"{src.get('accepted', 0)} of {src.get('candidates', 0)} candidate(s) fit the layout",
                      f"{src.get('rejected', 0)} rejected", f"{(src.get('scanned_bytes') or 0) / 1048576:.0f} MiB scanned"]
        if src.get("unreadable"):
            detail.append(f"{src['unreadable']} unreadable")
        lines.append(f"{what} {src.get('source')}: {src.get('status')} - {', '.join(detail)}"
                     + (f" ({src['why']})" if src.get("why") else "") + (f" [{src['note']}]" if src.get("note") else ""))
        for ex in src.get("examples", [])[:3]:
            lines.append(f"      rejected {ex.get('at')}: {'; '.join(ex.get('problems', []))}")
    if status.get("state") == "done":
        lines.append(f"[+] Snapshot: {status.get('count', 0)} unique record(s) in {status.get('elapsed_ms', 0) / 1000:.1f}s")
    else:
        lines.append(f"[!] Snapshot found nothing to export: {status.get('why') or 'no reason given'}")
    return lines


def collect_resolution(script):
    """What the agent says about where its hook points came from (scripts/_resolve.js's
    getResolution): {"mode", "methods": [...], "fields": [...], "api": {...}}. None when the
    agent has no such export or cannot answer - the dump is then reported without it."""
    try:
        report = script.exports_sync.get_resolution()
    except Exception:
        return None
    return report if isinstance(report, dict) and isinstance(report.get("methods"), list) else None


def _hex(value):
    return hex(value) if isinstance(value, int) and not isinstance(value, bool) else value


def not_hooked(report):
    """The keys of `report` (collect_resolution) that ended with no address, i.e. nothing was hooked."""
    return [m["key"] for m in (report or {}).get("methods", []) if m.get("source") == "none"]


def render_resolution(report):
    """Console lines saying, per hook point the profile NAMES, how it was found - or nothing for a
    run that only used RVAs, which is what every run was before names existed."""
    lines = []
    for m in (report or {}).get("methods", []):
        if not m.get("name"):
            continue
        key, name = m.get("key"), m.get("name")
        if m.get("source") == "name":
            lines.append(f"[+] {key}: {name} -> {_hex(m.get('rva'))}, asked of the IL2CPP runtime")
            if m.get("agrees") is False:
                lines.append(f"[!] {key}: the profile's RVA {_hex(m.get('profile_rva'))} is out of date for this build - "
                             f"set offsets.{key} to {_hex(m.get('rva'))}")
        elif m.get("source") == "rva":
            lines.append(f"[i] {key}: hooked the profile's RVA {_hex(m.get('rva'))} - the name {name} was not used: "
                         f"{m.get('reason') or 'no reason given'}")
        else:
            lines.append(f"[!] {key}: NOTHING WAS HOOKED - {name} did not resolve ({m.get('reason') or 'no reason given'}) "
                         f"and there is no RVA to fall back to")
    return lines


def resolution_meta(report):
    """`report` for the export's `meta`: addresses as 0x strings, like `meta.offsets`."""
    if report is None:
        return None
    out = dict(report)
    out["methods"] = [{k: (_hex(v) if k in ("rva", "name_rva", "profile_rva") else v) for k, v in m.items()}
                      for m in report["methods"]]
    out["fields"] = [{k: (_hex(v) if k in ("layout_offset", "runtime_offset") else v) for k, v in f.items()}
                     for f in report.get("fields", [])]
    return out


def collect_unreadable(script, recs):
    """The records that have fields the agent could not read, as
    [{"key": ..., "fields": [...]}], in the order the agent stores them.

    The agent knows which fields make a key, so it names them (getUnreadable()).
    An agent built before that existed can't: the records themselves still carry
    `_unreadable`, so they are found from there, with `key` None."""
    try:
        entries = script.exports_sync.get_unreadable()
        if isinstance(entries, list):
            return [{"key": e.get("key"), "fields": list(e.get("fields") or [])} for e in entries]
    except Exception:  # an agent without getUnreadable()
        pass
    return [{"key": None, "fields": list(r[UNREADABLE_KEY])}
            for r in recs if isinstance(r, dict) and r.get(UNREADABLE_KEY)]


def render_unreadable(entries, total):
    """The console report for collect_unreadable()'s result, as a list of lines."""
    if not entries:
        return []
    lines = [f"[!] {len(entries)} of {total} record(s) have string field(s) the agent could not read - "
             f"null in the export, named in each record's `{UNREADABLE_KEY}`:"]
    for e in entries[:UNREADABLE_PRINTED]:
        who = f"key {e['key']}" if e["key"] is not None else "(key unknown: agent too old)"
        lines.append(f"      - {who}: {', '.join(e['fields'])}")
    if len(entries) > UNREADABLE_PRINTED:
        lines.append(f"      ... and {len(entries) - UNREADABLE_PRINTED} more (see meta.unreadable_records)")
    return lines


def check_layout(script, args):
    """Ask the agent how well the profile's layout held up and judge it."""
    if args.no_layout_check:
        return layout_check.skipped(args.layout_tolerance)
    health, why = None, None
    try:
        health = script.exports_sync.get_health()
    except Exception as e:  # an agent without getHealth(), or one that failed
        why = f"could not ask the agent ({e})"
    return layout_check.judge(health, args.layout_tolerance, why_missing=why)


def export_records(script, settings, args, gate=None, suspect=False):
    """Pull the accumulated table over RPC and write it, wrapped with `meta`
    (including the layout check's verdict), to args.out - or, when `suspect` (the
    layout gate stopped the run), to suspect_path(args.out) - and return that
    verdict (None if the export itself failed). Errors are reported, not
    raised: the caller still has to detach."""
    out_path = suspect_path(args.out) if suspect else args.out
    try:
        count = script.exports_sync.get_count()
        print(f"[*] Collected {count} unique records. Exporting...")
        # A list of records shaped by the layout in your profile (one dict per
        # record, keyed by field name). Not validated at runtime, same as the
        # rest of this RPC round-trip - which is what the layout check is for.
        recs = script.exports_sync.get_records()
        resolution = collect_resolution(script)
        settings.resolution = resolution
        for line in render_resolution(resolution):
            print(line)
        cache = settings.build_cache
        for line in (cache.render(resolution) if cache else []):
            print(line)
        verdict = check_layout(script, args)
        for line in layout_check.render(verdict):
            print(line)
        if cache:
            # only a dump that passed its layout check proves the addresses it was hooked at
            for line in cache.remember(resolution, verified=verdict.status == layout_check.OK and not suspect and bool(recs),
                                       records=len(recs)):
                print(line)
        unreadable = collect_unreadable(script, recs)
        for line in render_unreadable(unreadable, len(recs)):
            print(line)
        output = {
            "meta": {
                "profile": settings.profile.name if settings.profile else None,
                "target": settings.target,
                "module": settings.params["module"],
                "agent": os.path.basename(args.agent),
                # the RVAs that were hooked: the profile's, or what the IL2CPP runtime said for a name
                "offsets": {k: hex(v) for k, v in sorted(
                    {**settings.offsets,
                     **{m["key"]: m["rva"] for m in (resolution or {}).get("methods", []) if m.get("rva")}}.items()) if v},
                "resolution": resolution_meta(resolution),
                # how the table was found when it was read from a running app instead of hooked (null otherwise)
                "snapshot": settings.snapshot,
                "layout_check": verdict.as_meta(),
                "layout_gate": gate.meta() if gate else None,
                "suspect": suspect,
                "unreadable_count": len(unreadable),
                "unreadable_records": unreadable[:UNREADABLE_IN_META],
                "dumped_at": datetime.now(timezone.utc).isoformat(),
            },
            "records": recs,
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, indent=2)
        print(f"[+] Wrote {out_path}" + (" (SUSPECT: the layout gate stopped this run - do not use it as a dump)"
                                         if suspect else ""))
        return verdict
    except Exception as e:
        print("[!] Error retrieving data (does the loaded agent expose rpc.exports?):", e)
        return None


def tolerance(text):
    """argparse type for --layout-tolerance: a fraction from 0 to 1."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not 0 <= value <= 1:
        raise argparse.ArgumentTypeError(f"must be between 0 and 1, got {text!r}")
    return value


def gate_size(text):
    """argparse type for --layout-gate: a number of records, 0 = off."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text!r}") from None
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be 0 (off) or more, got {text!r}")
    return value


def main(argv=None, prog=None):
    ap = argparse.ArgumentParser(
        prog=prog,
        description="Spawn the target app (or attach to a running one), stream a bundled Frida agent's output, and "
                    "export its collected records to JSON when you press Enter.")
    add_override_args(ap, offsets=True, resolve=True, build_cache=True)
    ap.add_argument("--agent", default=None, metavar="PATH|NAME",
                    help=f"bundled agent to load, as a path or just its name, e.g. dump_table_b.js (default: "
                         f"{Path(AGENT_PATH).name}, or {Path(SNAPSHOT_AGENT_PATH).name} with --snapshot)")
    ap.add_argument("--attach", metavar="PROCESS",
                    help="attach to an app that is ALREADY running (a process name or a pid) instead of spawning it; "
                         "it is never killed or resumed, only detached from at the end")
    ap.add_argument("--snapshot", nargs="?", const="", default=None, metavar="RECORD",
                    help="read the table out of the running app (static field / live instances, as the profile's "
                         "names.snapshot says) instead of hooking its unpack; needs --attach. RECORD names the "
                         "names.snapshot entry when the profile has several")
    ap.add_argument("--snapshot-timeout", type=float, default=SNAPSHOT_TIMEOUT, metavar="SECONDS",
                    help=f"how long to wait for the snapshot (default: {SNAPSHOT_TIMEOUT})")
    ap.add_argument("--out", default=OUT_PATH, metavar="PATH",
                    help=f"where to write the exported JSON (default: {OUT_PATH})")
    ap.add_argument("--no-layout-check", action="store_true",
                    help="don't judge the agent's layout self-check (the export is then marked unverified)")
    ap.add_argument("--layout-tolerance", type=tolerance, default=layout_check.DEFAULT_TOLERANCE, metavar="F",
                    help="fraction of reads (0-1) that may contradict a layout check before it fails "
                         f"(default: {layout_check.DEFAULT_TOLERANCE}); a failed check exits with status "
                         f"{layout_check.EXIT_LAYOUT_FAILED}")
    ap.add_argument("--layout-gate", type=gate_size, default=layout_check.DEFAULT_GATE, metavar="N",
                    help="judge the first N records as soon as they have been read, so a layout that no "
                         f"longer fits the build is reported at once, not after the dump (default: "
                         f"{layout_check.DEFAULT_GATE}; 0 = off)")
    ap.add_argument("--on-drift", choices=ON_DRIFT_ACTIONS, default="stop",
                    help="what a failing --layout-gate does: 'stop' (default) ends the run and writes the "
                         "records read so far to a .suspect file instead of --out; 'warn' only reports and "
                         f"goes on (the export-time check then decides; exit status {layout_check.EXIT_LAYOUT_FAILED} "
                         "if it fails)")
    args = ap.parse_args(argv)
    if args.snapshot is not None and not args.attach:
        ap.error("--snapshot reads a running app: add --attach PROCESS (a name or a pid)")
    if args.snapshot_timeout <= 0:
        ap.error("--snapshot-timeout must be more than 0")
    args.agent = resources.resolve_agent(args.agent) if args.agent else (
        SNAPSHOT_AGENT_PATH if args.snapshot is not None else AGENT_PATH)
    try:                                     # first: an install built without Node has no agent, and that is the whole answer
        source = load_agent_source(args.agent)
    except FileNotFoundError as e:
        sys.exit(f"[!] {e}")
    settings = resolve_settings(args)
    settings.snapshot = None
    gate = None
    if args.layout_gate and not args.no_layout_check and args.snapshot is None:
        gate = LayoutGate(args.layout_gate, args.layout_tolerance, args.on_drift)
        settings.params["check"] = {"sample": args.layout_gate, "gate": True}

    if is_gitignored(args.out) is False:
        # The export's `meta` records the real target and offsets, so a dump
        # under a name .gitignore doesn't cover is one `git add -A` away from
        # being committed. (`records*.json` is covered.)
        print(f"[!] --out {args.out} is NOT covered by .gitignore, and the export records "
              f"the real target + offsets in `meta`. Keep it out of git - or use a "
              f"records*.json name.")

    device = frida.get_device_manager().add_remote_device(settings.remote_addr)

    def on_detached(reason):
        print(f"[!] Session detached, reason: {reason}")

    handler = gate.message_handler() if gate else on_message
    if args.attach:
        print(f"[*] Attaching to {args.attach}...")
        session = attach_agent(device, args.attach, source, handler, on_detached, params=settings.params)
    else:
        print(f"[*] Spawning {settings.target}...")
        session = spawn_agent(device, settings.target, source, handler, on_detached, params=settings.params)
    verdict = None
    stopped = False
    snapshot_failed = False
    try:
        with session as run:
            require_dump_agent(run, args.agent)
            if args.snapshot is not None:
                print(f"[*] Attached, pid={run.pid}. Taking the snapshot (the app keeps running)...")
                status = take_snapshot(run.script, args.snapshot_timeout)
                for line in render_snapshot(status):
                    print(line)
                settings.snapshot = status
                if status.get("state") == "done":
                    verdict = export_records(run.script, settings, args, None)
                else:
                    # Nothing is written: an empty snapshot must not replace a good records file.
                    snapshot_failed = True
            elif args.attach:
                print(f"[*] Attached, pid={run.pid}. The app keeps running; it is not restarted or killed.")
                print("[*] Listening - records print as the app unpacks them (a table it unpacked before this "
                      "attach will not be seen: use --snapshot for that).")
                print("[*] Press Enter at any point to export the records and detach.\n")
                how = "enter"
                try:
                    how = wait_for_enter(gate.tripped if gate else None)
                except KeyboardInterrupt:
                    print("\n[*] Interrupted - exporting what was collected so far.")
                stopped = how == "stop"
                verdict = export_records(run.script, settings, args, gate, suspect=stopped)
            else:
                run.resume()
                print(f"[*] Spawned and resumed, pid={run.pid}")
                print("[*] Listening - new records print immediately. Use the app normally.")
                print("[*] Press Enter at any point to export the records and exit.\n")

                how = "enter"
                try:
                    how = wait_for_enter(gate.tripped if gate else None)
                except KeyboardInterrupt:
                    print("\n[*] Interrupted - exporting what was collected so far.")

                stopped = how == "stop"
                verdict = export_records(run.script, settings, args, gate, suspect=stopped)
    except (AgentInitError, NotADumpAgent, ProcessNotFound) as e:
        sys.exit(f"[!] {e}" + ("" if args.attach else " (the app was not left running)"))

    if snapshot_failed:
        sys.exit(EXIT_SNAPSHOT_FAILED)

    # After the session is detached, so a failed check never leaves the app attached.
    if not_hooked(settings.resolution):
        sys.exit(EXIT_NOT_HOOKED)
    if stopped or (verdict is not None and verdict.status == layout_check.FAIL):
        sys.exit(layout_check.EXIT_LAYOUT_FAILED)


if __name__ == "__main__":
    main()
