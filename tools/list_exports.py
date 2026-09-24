"""
list_exports.py

Spawns the target app, loads the bundled dist/list_il2cpp_exports.js (built with
`npm run build` from scripts/list_il2cpp_exports.js - see README.md's
"Building the agents"), waits a few seconds for it to print export/symbol
matches, then detaches. No RPC call involved - just reads the console
messages.

TARGET and REMOTE_ADDR default to the values in config.py; override them per
run with --target / --remote or the FRIDA_TARGET / FRIDA_REMOTE_ADDR
environment variables (precedence: CLI > env > config.py).

Usage:
    python list_exports.py
    python list_exports.py --target com.example.other --remote 127.0.0.1:1234

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
import time
from pathlib import Path

import frida

from _common import add_override_args, load_agent_source, resolve_settings, spawn_agent

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_PATH = str(REPO_ROOT / "dist" / "list_il2cpp_exports.js")
WAIT_SECONDS = 8


def on_message(message, data):
    if message.get("type") == "error":
        print("[agent error]", message.get("stack") or message.get("description"))
    elif message.get("type") == "send":
        print("[agent]", message.get("payload"))


def main():
    ap = argparse.ArgumentParser(
        description="Spawn the target app, load the bundled export-listing agent, "
                    "and print the exports/symbols it finds.")
    add_override_args(ap, offset=False)
    settings = resolve_settings(ap.parse_args(), offset=False)

    source = load_agent_source(AGENT_PATH)

    device = frida.get_device_manager().add_remote_device(settings.remote_addr)

    def on_detached(reason):
        print(f"[!] Session detached, reason: {reason}")

    print(f"[*] Spawning {settings.target}...")
    with spawn_agent(device, settings.target, source, on_message, on_detached) as run:
        run.resume()
        print(f"[*] Spawned and resumed, pid={run.pid}")
        print(f"[*] Waiting {WAIT_SECONDS}s for the agent to list exports...")
        try:
            time.sleep(WAIT_SECONDS)
        except KeyboardInterrupt:
            print("\n[*] Interrupted - detaching early.")

    print("[*] See the log above.")


if __name__ == "__main__":
    main()
