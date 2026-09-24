// dump_hd_quality_list.js
//
// Frida hook for ExampleNamespace.DeviceQualityAllowList$$unpack.
//
// Where each field of a record lives, and how it's read, is defined once in
// schema/layouts.json (this agent reads DeviceQualityRecord) and reaches this
// file as scripts/_layouts.js, which is generated from it - see
// docs/MEMORY_LAYOUT.md for the layout and the investigation behind it. No
// offsets are spelled out here.
//
// Usage: set FRIDA_OFFSET to the file offset of the unpack function (from
// Ghidra's Symbol Table, using Image Base = 0), then build this with
// `npm run build` and run the bundled dist/dump_hd_quality_list.js with
// Frida against a running instance of the game. See README.md's
// "Building the agents" section.

import { readRecord, waitForModule, createRecordStore, unpackFailed, createSkipLogger } from "./_lib.js";
import { DeviceQualityRecordLayout } from "./_layouts.js";

/** @typedef {import("./_layouts.js").DeviceQualityRecord} DeviceQualityRecord */

const FRIDA_OFFSET = 0x0; // <-- SET THIS: build-specific, find via Ghidra

if (FRIDA_OFFSET === 0x0) {
    throw new Error("FRIDA_OFFSET is still 0x0 - set it to your build's real offset " +
        "(or set config.FRIDA_OFFSET and run this via tools/run_hd_quality_dump.py) " +
        "before running. See docs/ITERATION_HISTORY.md for how to find it.");
}

const { records, put, rpcExports } = /** @type {import("./_lib.js").RecordStore<DeviceQualityRecord>} */ (createRecordStore());
const logSkip = createSkipLogger("DeviceQualityAllowList");

function installHook(mod) {
    const addr = mod.base.add(FRIDA_OFFSET);
    console.log("[+] Hooking unpack at", addr);

    Interceptor.attach(addr, {
        onEnter(args) {
            this.recordPtr = args[0];
        },
        onLeave(retval) {
            if (unpackFailed(retval)) {
                logSkip(retval);
                return;
            }

            const rec = this.recordPtr;
            try {
                const record = /** @type {DeviceQualityRecord} */ (readRecord(rec, DeviceQualityRecordLayout));
                const { id, enabled, name } = record;

                const { isNew, changed } = put(record);

                if (changed) {
                    // Same id re-sent with different contents - either a
                    // real server-side update or `id` isn't unique here;
                    // the newer record has replaced the older one.
                    console.log(`[!] id ${id} re-sent with DIFFERENT contents - replaced ` +
                        `(name="${name}")`);
                }
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
