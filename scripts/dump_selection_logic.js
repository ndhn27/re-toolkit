// dump_selection_logic.js
//
// Hooks the two "selection" functions instead of just reading the data
// tables - so the actual running priority/selection algorithm can be
// observed directly, without having to hand-read the decompiled code.
//
// Locate the RVAs for these two functions via static analysis (Image Base
// = 0) and set them below. Build-specific — will need to be re-found for
// whatever binary you're targeting.

const OFFSET_GetConfigMatchingDevicePattern = 0x0; // <-- SET THIS
const OFFSET_GetRecommendedQualityPreset = 0x0; // <-- SET THIS

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

function readConfigResult(ptr) {
    if (ptr.isNull()) return null;
    try {
        return {
            dwID: ptr.add(0x08).readU32(),
            dwType: ptr.add(0x0c).readU32(),
            dwDeviceLevel: ptr.add(0x30).readU32(),
            dwFPSGraphicMode: ptr.add(0x5c).readU32(),
            szConfig: readIl2CppString(ptr.add(0x60).readPointer()),
        };
    } catch (e) {
        return `<error reading result: ${e.message}>`;
    }
}

function main() {
    let mod;
    try {
        mod = Process.getModuleByName("UnityFramework");
        installHooks(mod);
    } catch (e) {
        console.log("[i] UnityFramework not loaded yet - waiting for module observer...");
        const observer = Process.attachModuleObserver({
            onAdded(m) {
                if (m.name === "UnityFramework") {
                    observer.detach();
                    installHooks(m);
                }
            },
        });
    }
}

function installHooks(mod) {
    const addrRegexGroup = mod.base.add(OFFSET_GetConfigMatchingDevicePattern);
    const addrRecommend = mod.base.add(OFFSET_GetRecommendedQualityPreset);

    console.log("[+] Hooking GetConfigMatchingDevicePattern at", addrRegexGroup);
    console.log("[+] Hooking GetRecommendedQualityPreset at", addrRecommend);

    Interceptor.attach(addrRegexGroup, {
        onEnter(args) {
            const deviceName = readIl2CppString(args[0]);
            const type = args[2].toInt32();
            console.log(`\n  [GetConfigMatchingDevicePattern] deviceName="${deviceName}" type=${type}`);
        },
        onLeave(retval) {
            const result = readConfigResult(retval);
            console.log(`  [GetConfigMatchingDevicePattern] -> ${result === null ? "NULL (no match)" : JSON.stringify(result)}`);
        },
    });

    Interceptor.attach(addrRecommend, {
        onEnter(args) {
            console.log("\n===== GetRecommendedQualityPreset() called =====");
        },
        onLeave(retval) {
            const result = readConfigResult(retval);
            console.log("===== FINAL RESULT:", result === null ? "NULL" : JSON.stringify(result), "=====\n");
        },
    });

    console.log("[+] Hooks installed. Waiting for GetRecommendedQualityPreset() to be called (usually when entering the graphics/lobby screen)...");
}

main();
