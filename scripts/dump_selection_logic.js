// dump_selection_logic.js
//
// Hooks the two "selection" functions instead of just reading the data
// tables - so the actual running priority/selection algorithm can be
// observed directly, without having to hand-read the decompiled code.
//
// Locate the RVAs for these two functions via static analysis (Image Base
// = 0; RVAs, not file offsets - see README.md's "RVA vs file offset") and
// set them below. Build-specific — will need to be re-found for
// whatever binary you're targeting. Build this with `npm run build` and
// run the bundled dist/dump_selection_logic.js - see README.md's
// "Building the agents" section.

import { readIl2CppString, readRecord, waitForModule } from "./_lib.js";
import { RecommendConfigRecordLayout, SelectionResultFields } from "./_layouts.js";

/** @typedef {import("./_layouts.js").SelectionResult} SelectionResult */

// Both hooked functions below return a pointer to a full
// ExampleNamespace.DeviceRecommendConfig record, but only the few fields in
// SelectionResultFields (schema/layouts.json's `SelectionResult` subset) are
// worth watching live. They're read with the same layout as
// dump_recommend_config.js - it's the same underlying struct, so there is
// nothing to keep in sync by hand.

const OFFSET_GetConfigMatchingDevicePattern = 0x0; // <-- SET THIS
const OFFSET_GetRecommendedQualityPreset = 0x0; // <-- SET THIS

if (OFFSET_GetConfigMatchingDevicePattern === 0x0 || OFFSET_GetRecommendedQualityPreset === 0x0) {
    throw new Error("OFFSET_GetConfigMatchingDevicePattern and/or OFFSET_GetRecommendedQualityPreset " +
        "are still 0x0 - set both to your build's real RVAs before running.");
}

/**
 * @param {NativePointer} ptr
 * @returns {SelectionResult|null|string} the record, `null` if `ptr` was
 *   null (no match), or a `<error reading result: ...>` string if a field
 *   read failed partway through
 */
function readConfigResult(ptr) {
    if (ptr.isNull()) return null;
    try {
        return /** @type {SelectionResult} */ (readRecord(ptr, RecommendConfigRecordLayout, SelectionResultFields));
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
            try {
                const deviceName = readIl2CppString(args[0]);
                const type = args[2].toInt32();
                console.log(`\n  [GetConfigMatchingDevicePattern] deviceName="${deviceName}" type=${type}`);
            } catch (e) {
                console.log(`\n  [GetConfigMatchingDevicePattern] onEnter error: ${e.message}`);
            }
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
