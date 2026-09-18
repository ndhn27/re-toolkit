// dump_recommend_config.js
//
// Reads ExampleNamespace.DeviceRecommendConfig in full — see
// docs/MEMORY_LAYOUT.md for the confirmed field layout.
//
// Set FRIDA_OFFSET before running (Symbol Table -> DeviceRecommendConfig
// -> ...$$unpack -> Location column, using Image Base = 0).

const FRIDA_OFFSET = 0x0; // <-- SET THIS: build-specific, find via Ghidra

const records = new Map(); // dwID -> record

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
                const dwID = rec.add(0x08).readU32();
                const rec_data = {
                    dwID: dwID,
                    dwType: rec.add(0x0c).readU32(),
                    iIntParam1min: rec.add(0x18).readS32(),
                    iIntParam1max: rec.add(0x1c).readS32(),
                    iIntParam2min: rec.add(0x20).readS32(),
                    iIntParam2max: rec.add(0x24).readS32(),
                    iIntParam3min: rec.add(0x28).readS32(),
                    iIntParam3max: rec.add(0x2c).readS32(),
                    dwDeviceLevel: rec.add(0x30).readU32(),
                    dwISSupportFPS60: rec.add(0x34).readU32(),
                    dwISSupportParticleHD: rec.add(0x38).readU32(),
                    dwRecommendGraphicMode: rec.add(0x3c).readU32(),
                    dwRenderQualityPerformanceMode: rec.add(0x40).readU32(),
                    dwParticleQualityPerformanceMode: rec.add(0x44).readU32(),
                    dwResolutionPerformanceMode: rec.add(0x48).readU32(),
                    dwFPSPerformanceMode: rec.add(0x4c).readU32(),
                    dwRenderQualityGraphicMode: rec.add(0x50).readU32(),
                    dwParticleQualityGraphicMode: rec.add(0x54).readU32(),
                    dwResolutionGraphicMode: rec.add(0x58).readU32(),
                    dwFPSGraphicMode: rec.add(0x5c).readU32(),
                    szConfig: readIl2CppString(rec.add(0x60).readPointer()),
                };

                const isNew = !records.has(dwID);
                records.set(dwID, rec_data);

                if (isNew) {
                    console.log(`[new #${records.size}] dwID=${rec_data.dwID} dwType=${rec_data.dwType} szConfig="${rec_data.szConfig}" ` +
                        `param1=[${rec_data.iIntParam1min},${rec_data.iIntParam1max}] param2=[${rec_data.iIntParam2min},${rec_data.iIntParam2max}] param3=[${rec_data.iIntParam3min},${rec_data.iIntParam3max}] ` +
                        `deviceLevel=${rec_data.dwDeviceLevel} fps60=${rec_data.dwISSupportFPS60} fpsPerf=${rec_data.dwFPSPerformanceMode} fpsGraphic=${rec_data.dwFPSGraphicMode}`);
                }
            } catch (e) {
                console.log("[!] Error reading record:", e.message);
            }
        },
    });

    console.log("[+] Hook installed. Waiting for the server to push DeviceRecommendConfig data...");
}

rpc.exports = {
    getCount: function () {
        return records.size;
    },
    getRecords: function () {
        return Array.from(records.values());
    },
    clear: function () {
        records.clear();
        return true;
    },
};

main();
