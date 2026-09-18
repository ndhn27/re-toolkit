"""
list_exports.py

Spawns com.example.unitygame, loads scripts/list_il2cpp_exports.js, waits a
few seconds for it to print export/symbol matches, then detaches. No RPC
call involved - just reads the console messages.

Usage:
    python list_exports.py
"""
import time
import frida

TARGET = "com.example.unitygame"
AGENT_PATH = "../scripts/list_il2cpp_exports.js"
REMOTE_ADDR = "127.0.0.1:27042"
WAIT_SECONDS = 8


def on_message(message, data):
    if message.get("type") == "error":
        print("[agent error]", message.get("stack") or message.get("description"))
    elif message.get("type") == "send":
        print("[agent]", message.get("payload"))


def main():
    with open(AGENT_PATH, "r", encoding="utf-8") as f:
        source = f.read()

    device = frida.get_device_manager().add_remote_device(REMOTE_ADDR)

    def on_detached(reason):
        print(f"[!] Session detached, reason: {reason}")

    print(f"[*] Spawning {TARGET}...")
    pid = device.spawn([TARGET])
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
