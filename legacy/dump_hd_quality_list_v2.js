// dump_hd_quality_list_v2.js
//
// FIX vs v1: offset +0x10 was always NULL (wrong namePtr) - +0x18 turned
// out to be the real pointer, which matches how IL2CPP typically packs
// reference-type (pointer) fields together, NOT necessarily preserving
// declaration order. The class declares both a szName_ByteArray (byte[])
// AND a szName (string) field - very likely these two fields sit right
// next to each other at +0x10/+0x18, and the one WITH data is +0x18
// (szName, a System.String, not a byte[]).
//
// v2 tries reading BOTH +0x10 and +0x18, using BOTH interpretations (old-
// style byte[] and UTF-16 System.String), printing everything so it can be
// visually compared to see which one produces meaningful text. Also cut
// the hexdump down to just the first record (reduce load on the hot path,
// to avoid the risk of hanging like the first run did).

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

// Interpretation 1: standard IL2CPP byte[] - klass+monitor(0x10) +
// bounds(0x8) + max_length(0x8, at +0x18) + data at +0x20. (This is the
// layout v1 used, kept here for comparison.)
function tryAsByteArray(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try {
        const range = Process.findRangeByAddress(ptr);
        if (!range || range.protection.indexOf("r") === -1) return `<not readable, prot=${range ? range.protection : "unmapped"}>`;
        const len = ptr.add(0x18).readS32();
        if (len <= 0 || len > 4096) return `<unexpected len: ${len}>`;
        return ptr.add(0x20).readCString(len);
    } catch (e) {
        return `<error: ${e.message}>`;
    }
}

// Interpretation 2: standard IL2CPP System.String - klass+monitor(0x10
// header) + length(int32 at +0x10) + UTF-16 characters starting at +0x14.
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

                const ptr10 = rec.add(0x10).readPointer();
                const ptr18 = rec.add(0x18).readPointer();

                const p10_bytes  = tryAsByteArray(ptr10);
                const p10_string = tryAsIl2CppString(ptr10);
                const p18_bytes  = tryAsByteArray(ptr18);
                const p18_string = tryAsIl2CppString(ptr18);

                console.log(
                    `[${count}] id=${id}\n` +
                    `      +0x10=${ptr10}  as byte[]="${p10_bytes}"  as string="${p10_string}"\n` +
                    `      +0x18=${ptr18}  as byte[]="${p18_bytes}"  as string="${p18_string}"`
                );

                // hexdump only once, for the first record, to reduce load
                // on the hot path
                if (count === 1) {
                    const bytes = rec.readByteArray(0x30);
                    console.log(hexdump(bytes, { address: rec, length: 0x30 }));
                }
            } catch (e) {
                console.log("[!] Error reading record:", e.message);
            }
        },
    });

    console.log("[+] Hook installed. Waiting for the server to push DeviceQualityAllowList data...");
}

main();
