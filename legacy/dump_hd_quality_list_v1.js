// dump_hd_quality_list_v1.js
//
// Hooks directly into ExampleNamespace.DeviceQualityAllowList$$unpack
// instead of trying to read a Dictionary from memory - this table is
// decoded record-by-record by the app's own custom binary serialization
// format, rather than being laid out as a standard IL2CPP Dictionary. Hooks
// onLeave of unpack, reading fields directly off the record that was just
// populated (param_1 / args[0]).
//
// Record layout inferred from decompilation (NOT 100% certain yet - verify
// by printing values and comparing against real device names you know):
//   +0x08 : uint32  - some numeric field (id/priority/version - meaning unclear)
//   +0x10 : byte[]* - IL2CPP byte array pointer, supposedly the device name/id string
//   +0x18 : int8    - HD quality on/off flag (the main target)
//   +0x20 : object* - ResExtension (ignored, not needed)

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

function readIl2CppByteArrayAsString(arrPtr) {
    // Standard IL2CPP array layout: klass(0x0) + monitor(0x8) + bounds(0x10)
    // + max_length(0x18) + data starting at 0x20
    if (arrPtr.isNull()) return null;
    const len = arrPtr.add(0x18).readS32();
    if (len <= 0 || len > 4096) return `<unexpected len: ${len}>`;
    try {
        return arrPtr.add(0x20).readCString(len);
    } catch (e) {
        return `<read error: ${e.message}>`;
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
                const field08 = rec.add(0x08).readU32();
                const namePtr = rec.add(0x10).readPointer();
                const name = readIl2CppByteArrayAsString(namePtr);
                const flag = rec.add(0x18).readS8();

                count++;
                console.log(
                    `[${count}] field08=${field08}  name="${name}"  hd_enable=${flag}  namePtr=${namePtr}`
                );

                // Also print raw hex for the first 5 records to visually
                // check where the real field actually is, in case the
                // offset guess is wrong.
                if (count <= 5) {
                    const bytes = rec.readByteArray(0x40);
                    console.log(hexdump(bytes, { address: rec, length: 0x40 }));
                }
            } catch (e) {
                console.log("[!] Error reading record:", e.message);
            }
        },
    });

    console.log("[+] Hook installed. Waiting for the server to push DeviceQualityAllowList data...");
}

main();
