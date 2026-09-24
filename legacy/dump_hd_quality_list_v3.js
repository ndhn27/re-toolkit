// dump_hd_quality_list_v3.js
//
// FIX vs v2: miscounted the hexdump rows - the field with real data is
// actually at +0x20 (szName, a System.String), NOT +0x18. This matches the
// class's declared member order exactly - IL2CPP wasn't reordering fields
// as previously suspected, it's simply that every field (including the
// sbyte enabled) occupies a full 8-byte slot:
//   +0x08 id              (uint,  padded to 8 bytes)
//   +0x10 szName_ByteArray  (byte[], observed to always be NULL)
//   +0x18 enabled          (sbyte, padded to 8 bytes - read the low byte)
//   +0x20 szName            (string - the REAL device name)

const FRIDA_OFFSET = 0x0; // <-- SET THIS: build-specific, find via Ghidra

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

function tryAsIl2CppString(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try {
        const range = Process.findRangeByAddress(ptr);
        if (!range || range.protection.indexOf("r") === -1) return `<not readable, prot=${range ? range.protection : "unmapped"}>`;
        const len = ptr.add(0x10).readS32();
        if (len < 0 || len > 512) return `<unexpected len: ${len}>`;
        if (len === 0) return "(empty string)";
        const s = ptr.add(0x14).readUtf16String(len);
        return s === null ? "<UTF16 read failed>" : s;
    } catch (e) {
        return `<error: ${e.message}>`;
    }
}

function installHook(mod) {
    const addr = mod.base.add(FRIDA_OFFSET);
    console.log("[+] Hooking unpack at", addr);

    let count = 0;
    let enabledCount = 0;
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
                const name = tryAsIl2CppString(namePtr);

                const marker = enabled !== 0 ? "  * ENABLED" : "";
                if (enabled !== 0) enabledCount++;

                console.log(`[${count}] id=${id}  enabled=${enabled}  szName="${name}"${marker}`);

                if (count === 1) {
                    const bytes = rec.readByteArray(0x30);
                    console.log(hexdump(bytes, { address: rec, length: 0x30 }));
                }
            } catch (e) {
                console.log("[!] Error reading record:", e.message);
            }

            if (count % 50 === 0) {
                console.log(`--- Processed ${count} records, ${enabledCount} with enabled != 0 ---`);
            }
        },
    });

    console.log("[+] Hook installed. Waiting for the server to push DeviceQualityAllowList data...");
}

main();
