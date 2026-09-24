// dump_selection_logic.js
//
// Hooks the two "selection" functions instead of just reading the data
// tables - so the actual running priority/selection algorithm can be
// observed directly, without having to hand-read the decompiled code.
//
// Locate the RVAs for these two functions via static analysis (Image Base
// = 0) and set them below. Build-specific — will need to be re-found for
// whatever binary you're targeting. Build this with `npm run build` and
// run the bundled dist/dump_selection_logic.js - see README.md's
// "Building the agents" section.

import { readIl2CppString, waitForModule } from "./_lib.js";

const OFFSET_GetConfigMatchingDevicePattern = 0x0; // <-- SET THIS
const OFFSET_GetRecommendedQualityPreset = 0x0; // <-- SET THIS

if (OFFSET_GetConfigMatchingDevicePattern === 0x0 || OFFSET_GetRecommendedQualityPreset === 0x0) {
    throw new Error("OFFSET_GetConfigMatchingDevicePattern and/or OFFSET_GetRecommendedQualityPreset " +
        "are still 0x0 - set both to your build's real offsets before running.");
}

function readConfigResult(ptr) {
    if (ptr.isNull()) return null;
    try {
        return {
            id: ptr.add(0x08).readU32(),
            type: ptr.add(0x0c).readU32(),
            deviceLevel: ptr.add(0x30).readU32(),
            fpsGraphicMode: ptr.add(0x5c).readU32(),
            szConfig: readIl2CppString(ptr.add(0x60).readPointer()),
        };
    } catch (e) {
        return `<error reading result: ${e.message}>`;
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

waitForModule("UnityFramework", installHooks);
