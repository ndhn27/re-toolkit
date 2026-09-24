// dump_recommend_config_probe.js
//
// Exploratory probe used before the real layout of ExampleNamespace.DeviceRecommendConfig
// was known - dumps the first 128 raw bytes of the record, plus 48 raw bytes
// at every 8-byte slot whose value could be a pointer, so the field layout can
// be identified by eye. Same technique that worked for DeviceQualityAllowList
// (see docs/MEMORY_LAYOUT.md).
//
// The "possible pointer" lines are a heuristic, not a finding: a slot is listed
// if its value is non-null and falls in a readable range, which an integer or
// packed fields can do too, and nothing here knows what it points at
// (System.String*, byte[]*, another record, ...). The bytes are shown raw, never
// decoded. Confirm a candidate by reading it the way the real agent would
// (readIl2CppString in _lib.js) before writing it into schema/layouts.json.
//
// Set FRIDA_OFFSET below before running to the RVA of ...$$unpack (from
// Ghidra's Symbol Table, using Image Base = 0; an RVA, not a file offset - see
// README.md's "RVA vs file offset"). Build this with `npm run build` and run the bundled
// dist/dump_recommend_config_probe.js - see README.md's "Building the
// agents" section.

import { waitForModule, unpackFailed } from "./_lib.js";

const FRIDA_OFFSET = 0x0; // <-- SET THIS

if (FRIDA_OFFSET === 0x0) {
    throw new Error("FRIDA_OFFSET is still 0x0 - set it to your build's real RVA before running.");
}

const RECORD_DUMP_SIZE = 0x80; // wider than the earlier probe - this struct has more fields

function installHook(mod) {
    const addr = mod.base.add(FRIDA_OFFSET);
    console.log("[+] Hooking unpack at", addr);

    let count = 0;
    const MAX_DUMPS = 8; // only dump the first 8 records, enough to read the layout

    Interceptor.attach(addr, {
        onEnter(args) {
            this.recordPtr = args[0];
        },
        onLeave(retval) {
            if (unpackFailed(retval)) {
                console.log(`[!] unpack failed: ${retval}`);
                return;
            }
            count++;
            if (count > MAX_DUMPS) return;

            const rec = this.recordPtr;
            console.log(`\n===== record #${count}  rec=${rec} =====`);
            try {
                const bytes = rec.readByteArray(RECORD_DUMP_SIZE);
                console.log(hexdump(bytes, { address: rec, length: RECORD_DUMP_SIZE }));

                // Scan every 8-byte slot for a value that could be a pointer
                // (heuristic: non-null and inside a readable region) and dump 48
                // raw bytes there too - candidates for device name strings /
                // CPU or GPU regex patterns. Only candidates: see the header
                // comment for why a hit doesn't prove it's a pointer, let alone
                // a System.String*.
                for (let off = 0; off < RECORD_DUMP_SIZE; off += 8) {
                    const val = rec.add(off).readPointer();
                    if (val.isNull()) continue;
                    const range = Process.findRangeByAddress(val);
                    if (range && range.protection.indexOf("r") !== -1) {
                        console.log(`  --- possible pointer at +0x${off.toString(16)} = ${val} (prot=${range.protection}, unverified) ---`);
                        try {
                            const sub = val.readByteArray(48);
                            console.log(hexdump(sub, { address: val, length: 48 }));
                        } catch (e) {
                            console.log(`  (could not read: ${e.message})`);
                        }
                    }
                }
            } catch (e) {
                console.log("[!] Error dumping record:", e.message);
            }
        },
    });

    console.log("[+] Hook installed. Waiting for the server to push DeviceRecommendConfig data...");
}

waitForModule("UnityFramework", installHook);
