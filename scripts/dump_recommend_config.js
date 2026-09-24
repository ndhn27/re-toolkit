// dump_recommend_config.js
//
// Reads ExampleNamespace.DeviceRecommendConfig in full — see
// docs/MEMORY_LAYOUT.md for the confirmed field layout.
//
// Set FRIDA_OFFSET before running (Symbol Table -> DeviceRecommendConfig
// -> ...$$unpack -> Location column, using Image Base = 0). Build this
// with `npm run build` and run the bundled dist/dump_recommend_config.js
// - see README.md's "Building the agents" section.

import { readIl2CppString, waitForModule, createRecordStore, unpackFailed, createSkipLogger } from "./_lib.js";

/**
 * One entry of ExampleNamespace.DeviceRecommendConfig, as read from a
 * hooked `...$$unpack` call. Field offsets are inline in onLeave below
 * (source of truth), and match docs/MEMORY_LAYOUT.md's
 * "DeviceRecommendConfig record" section - see that file for the
 * investigation history behind them.
 *
 * dump_selection_logic.js's `SelectionResult` typedef documents a 5-field
 * subset of this same record, read via a different pair of hooked
 * functions that return a pointer to one of these records directly.
 *
 * @typedef {Object} RecommendConfigRecord
 * @property {number} id - numeric record id (+0x08, uint32)
 * @property {number} type - record type discriminator (+0x0c, uint32)
 * @property {number} paramMin1 - (+0x18, int32)
 * @property {number} paramMax1 - (+0x1c, int32)
 * @property {number} paramMin2 - (+0x20, int32)
 * @property {number} paramMax2 - (+0x24, int32)
 * @property {number} paramMin3 - (+0x28, int32)
 * @property {number} paramMax3 - (+0x2c, int32)
 * @property {number} deviceLevel - (+0x30, uint32)
 * @property {number} supportsFPS60 - (+0x34, uint32 - observed as a 0/1 flag)
 * @property {number} supportsParticleHD - (+0x38, uint32 - observed as a 0/1 flag)
 * @property {number} recommendGraphicMode - (+0x3c, uint32)
 * @property {number} renderQualityPerfMode - (+0x40, uint32)
 * @property {number} particleQualityPerfMode - (+0x44, uint32)
 * @property {number} resolutionPerfMode - (+0x48, uint32)
 * @property {number} fpsPerfMode - (+0x4c, uint32)
 * @property {number} renderQualityGraphicMode - (+0x50, uint32)
 * @property {number} particleQualityGraphicMode - (+0x54, uint32)
 * @property {number} resolutionGraphicMode - (+0x58, uint32)
 * @property {number} fpsGraphicMode - (+0x5c, uint32)
 * @property {string|null} szConfig - (+0x60, System.String*) - graphics
 *   preset name; null/`<...>` on a null pointer or read error, same as
 *   DeviceQualityRecord.name - see readIl2CppString in _lib.js
 */

const FRIDA_OFFSET = 0x0; // <-- SET THIS: build-specific, find via Ghidra

if (FRIDA_OFFSET === 0x0) {
    throw new Error("FRIDA_OFFSET is still 0x0 - set it to your build's real offset " +
        "(or set config.FRIDA_OFFSET and run this via tools/run_hd_quality_dump.py) " +
        "before running. See docs/ITERATION_HISTORY.md for how to find it.");
}

const { records, rpcExports } = /** @type {import("./_lib.js").RecordStore<RecommendConfigRecord>} */ (createRecordStore());
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
                const id = rec.add(0x08).readU32();
                /** @type {RecommendConfigRecord} */
                const rec_data = {
                    id: id,
                    type: rec.add(0x0c).readU32(),
                    paramMin1: rec.add(0x18).readS32(),
                    paramMax1: rec.add(0x1c).readS32(),
                    paramMin2: rec.add(0x20).readS32(),
                    paramMax2: rec.add(0x24).readS32(),
                    paramMin3: rec.add(0x28).readS32(),
                    paramMax3: rec.add(0x2c).readS32(),
                    deviceLevel: rec.add(0x30).readU32(),
                    supportsFPS60: rec.add(0x34).readU32(),
                    supportsParticleHD: rec.add(0x38).readU32(),
                    recommendGraphicMode: rec.add(0x3c).readU32(),
                    renderQualityPerfMode: rec.add(0x40).readU32(),
                    particleQualityPerfMode: rec.add(0x44).readU32(),
                    resolutionPerfMode: rec.add(0x48).readU32(),
                    fpsPerfMode: rec.add(0x4c).readU32(),
                    renderQualityGraphicMode: rec.add(0x50).readU32(),
                    particleQualityGraphicMode: rec.add(0x54).readU32(),
                    resolutionGraphicMode: rec.add(0x58).readU32(),
                    fpsGraphicMode: rec.add(0x5c).readU32(),
                    szConfig: readIl2CppString(rec.add(0x60).readPointer()),
                };

                const isNew = !records.has(id);
                records.set(id, rec_data);

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
