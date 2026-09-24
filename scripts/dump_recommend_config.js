// dump_recommend_config.js
//
// Reads ExampleNamespace.DeviceRecommendConfig in full — see
// docs/MEMORY_LAYOUT.md for the confirmed field layout.
//
// Set FRIDA_OFFSET before running (Symbol Table -> DeviceRecommendConfig
// -> ...$$unpack -> Location column, using Image Base = 0). Build this
// with `npm run build` and run the bundled dist/dump_recommend_config.js
// - see README.md's "Building the agents" section.

import { readIl2CppString, waitForModule, createRecordStore } from "./_lib.js";

const FRIDA_OFFSET = 0x0; // <-- SET THIS: build-specific, find via Ghidra

if (FRIDA_OFFSET === 0x0) {
    throw new Error("FRIDA_OFFSET is still 0x0 - set it to your build's real offset " +
        "(or set config.FRIDA_OFFSET and run this via tools/run_hd_quality_dump.py) " +
        "before running. See docs/ITERATION_HISTORY.md for how to find it.");
}

const { records, rpcExports } = createRecordStore();

function installHook(mod) {
    const addr = mod.base.add(FRIDA_OFFSET);
    console.log("[+] Hooking unpack at", addr);

    Interceptor.attach(addr, {
        onEnter(args) {
            this.recordPtr = args[0];
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) return;

            const rec = this.recordPtr;
            try {
                const id = rec.add(0x08).readU32();
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
