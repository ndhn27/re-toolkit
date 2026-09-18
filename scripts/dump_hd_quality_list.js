// dump_hd_quality_list.js
//
// Frida hook for ExampleNamespace.DeviceQualityAllowList$$unpack.
//
// Layout confirmed experimentally (see docs/MEMORY_LAYOUT.md for the full
// investigation history — this went through several wrong guesses before
// landing here):
//
//   Il2CppObject headers in this build are only 8 bytes (just the klass
//   pointer, no separate monitor word) — that's true for every object in
//   this build, not just this record type.
//
// Record layout (DeviceQualityAllowList entry):
//   +0x00 : klass
//   +0x08 : dwID      (uint32)  - numeric record id
//   +0x18 : chEnable  (int8)    - HD render quality on/off flag
//   +0x20 : name      (System.String*) - device name/identifier
//
// System.String layout in this build:
//   +0x00 : klass (8 bytes)
//   +0x08 : length (int32, NOT padded to 8 bytes)
//   +0x0C : UTF-16LE characters, starting immediately, no gap
//
// Usage: set FRIDA_OFFSET to the file offset of the unpack function (from
// Ghidra's Symbol Table, using Image Base = 0), then run this with Frida
// against a running instance of the game.

const FRIDA_OFFSET = 0x0; // <-- SET THIS: build-specific, find via Ghidra

const OFFSETS = {
    dwID: 0x08,
    chEnable: 0x18,
    namePtr: 0x20,
};

const records = new Map(); // dwID -> {dwID, chEnable, name}

function readIl2CppString(strPtr) {
    if (strPtr.isNull()) return null;
    const len = strPtr.add(0x08).readS32();
    if (len < 0 || len > 512) return `<unexpected len: ${len}>`;
    if (len === 0) return "";
    try {
        return strPtr.add(0x0c).readUtf16String(len);
    } catch (e) {
        return `<read error: ${e.message}>`;
    }
}

function main() {
    let mod;
    try {
        mod = Process.getModuleByName("UnityFramework");
        installHook(mod);
    } catch (e) {
        console.log("[i] UnityFramework not loaded yet - waiting for module observer...");
        const observer = Process.attachModuleObserver({
            onAdded(m) {
                if (m.name === "UnityFramework") {
                    observer.detach();
                    installHook(m);
                }
            },
        });
    }
}

function installHook(mod) {
    const addr = mod.base.add(FRIDA_OFFSET);
    console.log("[+] Hooking unpack at", addr);

    Interceptor.attach(addr, {
        onEnter(args) {
            this.recordPtr = args[0];
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) return; // unpack failed, skip silently

            const rec = this.recordPtr;
            try {
                const dwID = rec.add(OFFSETS.dwID).readU32();
                const chEnable = rec.add(OFFSETS.chEnable).readS8();
                const namePtr = rec.add(OFFSETS.namePtr).readPointer();
                const name = readIl2CppString(namePtr);

                const isNew = !records.has(dwID);
                records.set(dwID, { dwID, chEnable, name });

                // Only log on a brand-new dwID - avoids spamming re-sent
                // records (the server may push the whole table again).
                if (isNew) {
                    console.log(`[new] dwID=${dwID}  chEnable=${chEnable}  name="${name}"  (total: ${records.size})`);
                }
            } catch (e) {
                console.log("[!] Error reading record:", e.message);
            }
        },
    });

    console.log("[+] Hook installed. Waiting for the server to push DeviceQualityAllowList data...");
}

rpc.exports = {
    getCount: function () {
        return records.size;
    },
    getRecords: function () {
        return Array.from(records.values());
    },
    clear: function () {
        records.clear();
        return true;
    },
};

main();
