"""
list_exports.py

Spawns the target app, loads the bundled dist/list_il2cpp_exports.js (built with
`npm run build` from scripts/list_il2cpp_exports.js - see docs/INSTALL.md), and waits until the agent reports `scan-complete`
(or until --wait seconds elapse). No RPC call involved - it reads console
messages, plus one `{event: "scan-complete"}` send from the agent when
the IL2CPP module has been enumerated.

A fixed sleep is the wrong tool here: the module (UnityFramework on iOS) is
often not loaded at resume, and an 8-second wait both overshoots a fast scan
and undershoots a slow Unity boot. The agent sends `scan-complete` when it is actually done.

The target, frida-server address and module name come from your profile
(--profile NAME, see profiles.py); --target / --remote / --module / --platform
override the profile's values, and with no profile at all --target and --module
(or --platform) are enough. There is no default module - it depends on the
platform (UnityFramework on iOS, libil2cpp.so on Android, GameAssembly.dll on
Windows), so say it with --module or --platform. No offset or layout is involved.

Usage:
    retk exports --profile myapp
    retk exports --target com.example.other --module libil2cpp.so --remote 127.0.0.1:1234
    retk exports --profile myapp --wait 120

AGENT_PATH is found by resources.agent_path(), not from the current working
directory - see run_dump.py's docstring for why.

Lifecycle: same as run_dump.py, via _common.spawn_agent(). If
anything fails between spawn and resume (attach, script creation, script
load) the still-suspended process is killed rather than left frozen, and the
session is always detached on the way out. Ctrl+C during the wait just ends
it early - the session is detached either way.
"""
import argparse
import sys
import threading

import frida

from . import resources
from ._common import AgentInitError, add_override_args, load_agent_source, resolve_settings, spawn_agent

AGENT_PATH = resources.agent_path("list_il2cpp_exports.js")
WAIT_SECONDS = 60


def wait_for_scan(event, timeout):
    """Block until the agent reports scan-complete, or `timeout` seconds pass.

    Split out so tests can patch it (a real Event.wait would block the
    suite for WAIT_SECONDS). Returns True if the event was set.
    """
    return event.wait(timeout)


def main(argv=None, prog=None):
    ap = argparse.ArgumentParser(
        prog=prog,
        description="Spawn the target app, load the bundled export-listing agent, "
                    "and print the exports/symbols it finds.")
    add_override_args(ap, offsets=False)
    ap.add_argument(
        "--wait", type=float, default=WAIT_SECONDS, metavar="SEC",
        help="max seconds to wait for the module to load and the scan to "
             f"finish (default: {WAIT_SECONDS})")
    args = ap.parse_args(argv)
    try:                                     # first: an install built without Node has no agent, and that is the whole answer
        source = load_agent_source(AGENT_PATH)
    except FileNotFoundError as e:
        sys.exit(f"[!] {e}")
    settings = resolve_settings(args)

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
    try:
        with spawn_agent(device, settings.target, source, on_message, on_detached,
                         params=settings.params) as run:
            run.resume()
            print(f"[*] Spawned and resumed, pid={run.pid}")
            print(f"[*] Waiting up to {args.wait:g}s for {settings.params['module']} to load "
                  f"and the scan to finish...")
            try:
                if not wait_for_scan(completed, args.wait):
                    print(f"[!] Timed out after {args.wait:g}s waiting for scan-complete "
                          f"({settings.params['module']} may still be loading - "
                          f"pass --wait to wait longer).")
            except KeyboardInterrupt:
                print("\n[*] Interrupted - detaching early.")
    except AgentInitError as e:
        sys.exit(f"[!] {e} (the app was not left running)")

    print("[*] See the log above.")


if __name__ == "__main__":
    main()
