// dump_recommend_config_probe.js
//
// Exploratory probe used before the real layout of ExampleNamespace.DeviceRecommendConfig
// was known - dumps the first 128 raw bytes of the record, plus the first
// 128 bytes at any pointer-looking values found inside it, so the field
// layout can be identified by eye. Same technique that worked for
// DeviceQualityAllowList (see docs/MEMORY_LAYOUT.md).
//
// Set FRIDA_OFFSET below before running (from Ghidra's Symbol Table, using
// Image Base = 0).

const FRIDA_OFFSET = 0x00000000; // <-- SET THIS

const RECORD_DUMP_SIZE = 0x80; // wider than the earlier probe - this struct has more fields

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

    let count = 0;
    const MAX_DUMPS = 8; // only dump the first 8 records, enough to read the layout

    Interceptor.attach(addr, {
        onEnter(args) {
            this.recordPtr = args[0];
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) {
                console.log(`[!] unpack failed: ${retval.toInt32()}`);
                return;
            }
            count++;
            if (count > MAX_DUMPS) return;

            const rec = this.recordPtr;
            console.log(`\n===== record #${count}  rec=${rec} =====`);
            try {
                const bytes = rec.readByteArray(RECORD_DUMP_SIZE);
                console.log(hexdump(bytes, { address: rec, length: RECORD_DUMP_SIZE }));

                // Scan every 8-byte slot for anything that looks like a valid
                // pointer (heuristic: falls inside a readable region), and if
                // so dump 48 bytes there too - likely candidates for device
                // name strings / CPU or GPU regex patterns.
                for (let off = 0; off < RECORD_DUMP_SIZE; off += 8) {
                    const val = rec.add(off).readPointer();
                    if (val.isNull()) continue;
                    const range = Process.findRangeByAddress(val);
                    if (range && range.protection.indexOf("r") !== -1) {
                        console.log(`  --- candidate pointer at +0x${off.toString(16)} = ${val} (prot=${range.protection}) ---`);
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

main();
