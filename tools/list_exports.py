"""
list_exports.py

Spawns the target app, loads the bundled dist/list_il2cpp_exports.js (built with
`npm run build` from scripts/list_il2cpp_exports.js - see README.md's
"Building the agents"), and waits until the agent reports `scan-complete`
(or until --wait seconds elapse). No RPC call involved - it reads console
messages, plus one `{event: "scan-complete"}` send from the agent when
UnityFramework has been enumerated.

A fixed sleep is the wrong tool here: UnityFramework is often not loaded at
resume, and an 8-second wait both overshoots a fast scan and undershoots a
slow Unity boot. The agent sends `scan-complete` when it is actually done.

TARGET and REMOTE_ADDR default to the values in config.py; override them per
run with --target / --remote or the FRIDA_TARGET / FRIDA_REMOTE_ADDR
environment variables (precedence: CLI > env > config.py).

Usage:
    python list_exports.py
    python list_exports.py --target com.example.other --remote 127.0.0.1:1234
    python list_exports.py --wait 120

AGENT_PATH is resolved from this file's own location (via __file__), not
the current working directory - see run_hd_quality_dump.py's docstring
for why (a "../dist/..." path would be resolved against the CWD and raise
FileNotFoundError when run from the repo root).

Lifecycle: same as run_hd_quality_dump.py, via _common.spawn_agent(). If
anything fails between spawn and resume (attach, script creation, script
load) the still-suspended process is killed rather than left frozen, and the
session is always detached on the way out. Ctrl+C during the wait just ends
it early - the session is detached either way.
"""
import argparse
import threading
from pathlib import Path

import frida

from _common import add_override_args, load_agent_source, resolve_settings, spawn_agent

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_PATH = str(REPO_ROOT / "dist" / "list_il2cpp_exports.js")
WAIT_SECONDS = 60


def wait_for_scan(event, timeout):
    """Block until the agent reports scan-complete, or `timeout` seconds pass.

    Split out so tests can patch it (a real Event.wait would block the
    suite for WAIT_SECONDS). Returns True if the event was set.
    """
    return event.wait(timeout)


def main():
    ap = argparse.ArgumentParser(
        description="Spawn the target app, load the bundled export-listing agent, "
                    "and print the exports/symbols it finds.")
    add_override_args(ap, offset=False)
    ap.add_argument(
        "--wait", type=float, default=WAIT_SECONDS, metavar="SEC",
        help="max seconds to wait for UnityFramework to load and the scan to "
             f"finish (default: {WAIT_SECONDS})")
    args = ap.parse_args()
    settings = resolve_settings(args, offset=False)

    source = load_agent_source(AGENT_PATH)

    device = frida.get_device_manager().add_remote_device(settings.remote_addr)
    completed = threading.Event()

    def on_message(message, data):
        if message.get("type") == "error":
            print("[agent error]", message.get("stack") or message.get("description"))
        elif message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("event") == "scan-complete":
                completed.set()
                return
            print("[agent]", payload)

    def on_detached(reason):
        print(f"[!] Session detached, reason: {reason}")

    print(f"[*] Spawning {settings.target}...")
    with spawn_agent(device, settings.target, source, on_message, on_detached) as run:
        run.resume()
        print(f"[*] Spawned and resumed, pid={run.pid}")
        print(f"[*] Waiting up to {args.wait:g}s for UnityFramework to load and the scan to finish...")
        try:
            if not wait_for_scan(completed, args.wait):
                print(f"[!] Timed out after {args.wait:g}s waiting for scan-complete "
                      f"(UnityFramework may still be loading - pass --wait to wait longer).")
        except KeyboardInterrupt:
            print("\n[*] Interrupted - detaching early.")

    print("[*] See the log above.")


if __name__ == "__main__":
    main()
