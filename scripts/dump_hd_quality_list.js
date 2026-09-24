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
//   +0x08 : id      (uint32)  - numeric record id
//   +0x18 : enabled  (int8)    - HD render quality on/off flag
//   +0x20 : name      (System.String*) - device name/identifier
//
// System.String layout: see readIl2CppString in scripts/_lib.js.
//
// Usage: set FRIDA_OFFSET to the file offset of the unpack function (from
// Ghidra's Symbol Table, using Image Base = 0), then build this with
// `npm run build` and run the bundled dist/dump_hd_quality_list.js with
// Frida against a running instance of the game. See README.md's
// "Building the agents" section.

import { readIl2CppString, waitForModule, createRecordStore } from "./_lib.js";

const FRIDA_OFFSET = 0x0; // <-- SET THIS: build-specific, find via Ghidra

if (FRIDA_OFFSET === 0x0) {
    throw new Error("FRIDA_OFFSET is still 0x0 - set it to your build's real offset " +
        "(or set config.FRIDA_OFFSET and run this via tools/run_hd_quality_dump.py) " +
        "before running. See docs/ITERATION_HISTORY.md for how to find it.");
}

const OFFSETS = {
    id: 0x08,
    enabled: 0x18,
    namePtr: 0x20,
};

const { records, rpcExports } = createRecordStore();

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
                const id = rec.add(OFFSETS.id).readU32();
                const enabled = rec.add(OFFSETS.enabled).readS8();
                const namePtr = rec.add(OFFSETS.namePtr).readPointer();
                const name = readIl2CppString(namePtr);

                const isNew = !records.has(id);
                records.set(id, { id, enabled, name });

                // Only log on a brand-new id - avoids spamming re-sent
                // records (the server may push the whole table again).
                if (isNew) {
                    console.log(`[new] id=${id}  enabled=${enabled}  name="${name}"  (total: ${records.size})`);
                }
            } catch (e) {
                console.log("[!] Error reading record:", e.message);
            }
        },
    });

    console.log("[+] Hook installed. Waiting for the server to push DeviceQualityAllowList data...");
}

rpc.exports = rpcExports;

waitForModule("UnityFramework", installHook);
