// dump_table_a.js
//
// Frida hook for the `...$$unpack` function of ExampleNamespace.ExampleTableA
// (a made-up name - substitute your target's own class).
//
// This agent contains no target-specific value. The RVA to hook, the module
// to wait for and the record layout all arrive in rpc.exports.init(stage,
// params), which retk dump calls with what it read from your profile
// (a JSON file kept outside git - see docs/PROFILES.md):
//
//   offsets.table_a        RVA of the unpack function - its address in Ghidra's
//                          Symbol Table with Image Base = 0, i.e. relative to the
//                          module's load address (NOT a file offset; see README.md's
//                          "RVA vs file offset")
//   names.methods.table_a  (optional) the same function BY NAME - the IL2CPP runtime is asked
//                          for its address first and offsets.table_a is the fallback
//                          (_resolve.js; docs/NAME_LOOKUP.md)
//   layouts.records.TableARecord   where each field of a record lives, and its `key`
//
// Records are logged as JSON, so this file names no field either: a profile can
// call its fields anything. Build with `npm run build`, run the bundled
// dist/dump_table_a.js through retk dump.

import { readRecord, sealUnreadable, waitForModule, createRecordStore, unpackFailed, createSkipLogger, parseParams, agentInit } from "./_lib.js";
import { createCanary, healthExport } from "./_canary.js";
import { resolveOffsets, resolutionExport, withFieldOffsets } from "./_resolve.js";

let keyOf = null; // set by init, once the profile says what identifies a record
const { records, put, rpcExports } = createRecordStore((rec) => keyOf(rec));
let canary = null; // set by init: checks every record read against the profile's layout (see _canary.js)
const logSkip = createSkipLogger("ExampleTableA");

function installHook(mod, offset, layout) {
    const addr = mod.base.add(offset);
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

            try {
                // `raw` still holds readIl2CppString()'s failure placeholders, which is
                // what the canary counts; `record` - what is stored and exported -
                // has them nulled and named in `_unreadable`, so a read error can't
                // pass for data in the JSON (see sealUnreadable in _lib.js).
                const raw = readRecord(this.recordPtr, layout);
                const record = sealUnreadable(raw);
                const { key, isNew, changed } = put(record);
                canary.observe(this.recordPtr, raw, changed);

                if (changed) {
                    // Same key re-sent with different contents - either a
                    // real update or the key isn't unique here; the newer
                    // record has replaced the older one.
                    console.log(`[!] key ${key} re-sent with DIFFERENT contents - replaced ` +
                        JSON.stringify(record));
                }
                // Only log on a brand-new key - avoids spamming re-sent
                // records (the app may unpack the whole table again).
                if (isNew) {
                    console.log(`[new #${records.size}] key=${key} ${JSON.stringify(record)}`);
                }
            } catch (e) {
                canary.readFailed(e);
                console.log("[!] Error reading record:", e.message);
            }
        },
    });

    console.log("[+] Hook installed. Waiting for the app to unpack ExampleTableA records...");
}

rpc.exports = {
    ...rpcExports,
    // How well the profile's layout held up against what was actually read; retk dump
    // asks for it at export time and judges it (retk/layout_check.py).
    // (plus, when the profile names the layout's fields, the offsets the runtime itself reports for them)
    getHealth: () => withFieldOffsets(healthExport(canary)),
    // Where the hook point came from - the name or the RVA - and what the runtime said about the layout's fields.
    getResolution: resolutionExport,
    init: agentInit((params, stage) => {
        const p = parseParams(params, { offsets: ["table_a"], records: ["TableARecord"] });
        const { layout, keyOf: k, klass } = p.records.TableARecord;
        keyOf = k;
        canary = createCanary("TableARecord", layout, { klass, headerSize: p.headerSize, sample: p.check.sample, gate: p.check.gate });
        waitForModule(p.moduleName, (mod) =>
            resolveOffsets(mod, p, ["table_a"], (rvas) => installHook(mod, rvas.table_a, layout), { stage }));
    }),
};
