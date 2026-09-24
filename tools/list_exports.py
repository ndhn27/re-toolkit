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
for why (`python tools/list_exports.py` from the repo root used to raise
a FileNotFoundError because "../dist/..." was resolved against the CWD).
"""
import argparse
import time
from pathlib import Path

import frida

from _common import add_override_args, load_agent_source, resolve_settings

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
    pid = device.spawn([settings.target])
    session = device.attach(pid)
    session.on("detached", on_detached)

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()

    device.resume(pid)
    print(f"[*] Spawned and resumed, pid={pid}")
    print(f"[*] Waiting {WAIT_SECONDS}s for the agent to list exports...")
    time.sleep(WAIT_SECONDS)

    session.detach()
    print("[*] Detached. See the log above.")


if __name__ == "__main__":
    main()
