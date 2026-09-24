// dump_recommend_config.js
//
// Reads ExampleNamespace.DeviceRecommendConfig in full. The record layout
// (RecommendConfigRecord) is defined once in schema/layouts.json and reaches
// this file as scripts/_layouts.js, which is generated from it - see
// docs/MEMORY_LAYOUT.md for the layout and how it was found. No offsets are
// spelled out here.
//
// Set FRIDA_OFFSET before running (Symbol Table -> DeviceRecommendConfig
// -> ...$$unpack -> Location column, using Image Base = 0). Build this
// with `npm run build` and run the bundled dist/dump_recommend_config.js
// - see README.md's "Building the agents" section.

import { readRecord, waitForModule, createRecordStore, unpackFailed, createSkipLogger } from "./_lib.js";
import { RecommendConfigRecordLayout } from "./_layouts.js";

/** @typedef {import("./_layouts.js").RecommendConfigRecord} RecommendConfigRecord */

const FRIDA_OFFSET = 0x0; // <-- SET THIS: build-specific, find via Ghidra

if (FRIDA_OFFSET === 0x0) {
    throw new Error("FRIDA_OFFSET is still 0x0 - set it to your build's real offset " +
        "(or set config.FRIDA_OFFSET and run this via tools/run_hd_quality_dump.py) " +
        "before running. See docs/ITERATION_HISTORY.md for how to find it.");
}

// Keyed by `${type}:${id}`, not `id` alone: every record carries a `type`
// discriminator, and nothing here establishes that `id` is unique
// across types. With an id-only key, two records of different types that
// share an id would overwrite each other (and getCount() would under-report).
const { records, put, rpcExports } = /** @type {import("./_lib.js").RecordStore<RecommendConfigRecord>} */ (
    createRecordStore((r) => `${r.type}:${r.id}`));
const logSkip = createSkipLogger("DeviceRecommendConfig");

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
                const rec_data = /** @type {RecommendConfigRecord} */ (readRecord(rec, RecommendConfigRecordLayout));

                const { key, isNew, changed } = put(rec_data);

                if (changed) {
                    // Same type:id re-sent with different contents - either a
                    // real server-side update or a genuine key collision;
                    // the newer record has replaced the older one.
                    console.log(`[!] key ${key} re-sent with DIFFERENT contents - replaced ` +
                        `(szConfig="${rec_data.szConfig}")`);
                }
                if (isNew) {
                    console.log(`[new #${records.size}] id=${rec_data.id} type=${rec_data.type} szConfig="${rec_data.szConfig}" ` +
                        `param1=[${rec_data.paramMin1},${rec_data.paramMax1}] param2=[${rec_data.paramMin2},${rec_data.paramMax2}] param3=[${rec_data.paramMin3},${rec_data.paramMax3}] ` +
                        `deviceLevel=${rec_data.deviceLevel} fps60=${rec_data.supportsFPS60} fpsPerf=${rec_data.fpsPerfMode} fpsGraphic=${rec_data.fpsGraphicMode}`);
                }
            } catch (e) {
                console.log("[!] Error reading record:", e.message);
            }
        },
    });

    console.log("[+] Hook installed. Waiting for the server to push DeviceRecommendConfig data...");
}

rpc.exports = rpcExports;

waitForModule("UnityFramework", installHook);
