"""
run_hd_quality_dump.py

Spawns the game, loads a Frida agent that exposes getCount()/getRecords()
via rpc.exports (i.e. scripts/dump_hd_quality_list.js or
scripts/dump_recommend_config.js), and streams its console output live.
Press Enter at any point to pull the accumulated table via RPC, write it to
a JSON file, and detach.

NOTE: the original version of this script had a mismatched docstring/
AGENT_PATH (it said "v5" but actually loaded dump_selection_logic.js, which
has no rpc.exports and would fail on script.exports_sync.get_count()). This
version makes the target script explicit via AGENT_PATH below - point it at
whichever agent you're currently running.

Usage:
    python run_hd_quality_dump.py
"""
import json
import frida

TARGET = "com.example.unitygame"
AGENT_PATH = "../scripts/dump_hd_quality_list.js"
REMOTE_ADDR = "127.0.0.1:27042"
OUT_PATH = "records.json"


def on_message(message, data):
    if message.get("type") == "error":
        print("[agent error]", message.get("stack") or message.get("description"))
    elif message.get("type") == "send":
        print(message.get("payload"))


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
    print("[*] Listening - new records print immediately. Play through the game normally.")
    print("[*] Press Enter at any point to export records.json and exit.\n")

    input()

    try:
        count = script.exports_sync.get_count()
        print(f"[*] Collected {count} unique records. Exporting...")
        recs = script.exports_sync.get_records()
        with open(OUT_PATH, "w", encoding="utf-8") as f:
            json.dump(recs, f, ensure_ascii=False, indent=2)
        print(f"[+] Wrote {OUT_PATH}")
    except Exception as e:
        print("[!] Error retrieving data (does the loaded agent expose rpc.exports?):", e)

    session.detach()
    print("[*] Detached.")


if __name__ == "__main__":
    main()
