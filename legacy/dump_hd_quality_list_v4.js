// dump_hd_quality_list_v4.js
//
// v3 was still wrong: many different id values were producing the SAME
// repeated "len" value - a sign that several records point at a handful of
// shared strings, and that the length offset within System.String was
// being read WRONG (the String header might also be only 8 bytes, like
// what was already observed on the record itself, not the standard 16-byte
// klass+monitor header).
//
// v4: stop guessing offsets - dump the RAW first 64 bytes at namePtr, only
// once per NEW namePtr value (dedup), so the real String layout in this
// build can be determined by eye before the parser is rewritten.

const FRIDA_OFFSET = 0x0; // <-- SET THIS: build-specific, find via Ghidra

if (FRIDA_OFFSET === 0x0) {
    throw new Error("FRIDA_OFFSET is still 0x0 - set it to your build's real offset " +
        "before running. See docs/ITERATION_HISTORY.md for how to find it.");
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

    let count = 0;
    const seenNamePtrs = new Set();

    Interceptor.attach(addr, {
        onEnter(args) {
            this.recordPtr = args[0];
        },
        onLeave(retval) {
            const ret = retval.toInt32();
            if (ret !== 0) {
                console.log(`[!] unpack returned error: ${ret} (skipping this record)`);
                return;
            }
            const rec = this.recordPtr;
            try {
                count++;
                const id = rec.add(0x08).readU32();
                const enabled = rec.add(0x18).readS8();
                const namePtr = rec.add(0x20).readPointer();
                const key = namePtr.toString();

                console.log(`[${count}] id=${id}  enabled=${enabled}  namePtr=${namePtr}${seenNamePtrs.has(key) ? "  (already dumped)" : ""}`);

                if (!namePtr.isNull() && !seenNamePtrs.has(key)) {
                    seenNamePtrs.add(key);
                    const range = Process.findRangeByAddress(namePtr);
                    if (range && range.protection.indexOf("r") !== -1) {
                        console.log(`   >>> RAW HEX at namePtr=${namePtr} (prot=${range.protection}), first 64 bytes:`);
                        const bytes = namePtr.readByteArray(64);
                        console.log(hexdump(bytes, { address: namePtr, length: 64 }));
                    } else {
                        console.log(`   >>> namePtr not mapped / not readable (prot=${range ? range.protection : "unmapped"})`);
                    }
                }
            } catch (e) {
                console.log("[!] Error reading record:", e.message);
            }
        },
    });

    console.log("[+] Hook installed. Waiting for the server to push DeviceQualityAllowList data...");
}

main();
