// dump_table_b.js
//
// Reads ExampleNamespace.ExampleTableB in full (a made-up name - substitute
// your target's own class).
//
// Like dump_table_a.js this agent contains no target-specific value: it takes
// them from rpc.exports.init(stage, params), i.e. from your profile:
//
//   offsets.table_b                RVA of ...$$unpack (Symbol Table -> your class ->
//                                  ...$$unpack -> Location column, Image Base = 0; an RVA,
//                                  not a file offset - see README.md's "RVA vs file offset")
//   layouts.records.TableBRecord   the record layout and its `key`
//
// Build with `npm run build`, run the bundled dist/dump_table_b.js through
// retk dump.

import { readRecord, sealUnreadable, waitForModule, createRecordStore, unpackFailed, createSkipLogger, parseParams, agentInit } from "./_lib.js";
import { createCanary, healthExport } from "./_canary.js";
import { resolveOffsets, resolutionExport, withFieldOffsets } from "./_resolve.js";

// Keyed on the profile's `key` list for TableBRecord (kind + id in the example),
// not `id` alone: every record carries a `kind` discriminator, and nothing
// here establishes that `id` is unique across kinds. With an id-only key, two
// records of different kinds that share an id would overwrite each other (and
// getCount() would under-report).
let keyOf = null;
const { records, put, rpcExports } = createRecordStore((rec) => keyOf(rec));
let canary = null; // set by init: checks every record read against the profile's layout (see _canary.js)
const logSkip = createSkipLogger("ExampleTableB");

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
                    // real update or a genuine key collision; the newer
                    // record has replaced the older one.
                    console.log(`[!] key ${key} re-sent with DIFFERENT contents - replaced ` +
                        JSON.stringify(record));
                }
                if (isNew) {
                    console.log(`[new #${records.size}] key=${key} ${JSON.stringify(record)}`);
                }
            } catch (e) {
                canary.readFailed(e);
                console.log("[!] Error reading record:", e.message);
            }
        },
    });

    console.log("[+] Hook installed. Waiting for the app to unpack ExampleTableB records...");
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
        const p = parseParams(params, { offsets: ["table_b"], records: ["TableBRecord"] });
        const { layout, keyOf: k, klass } = p.records.TableBRecord;
        keyOf = k;
        canary = createCanary("TableBRecord", layout, { klass, headerSize: p.headerSize, sample: p.check.sample, gate: p.check.gate });
        waitForModule(p.moduleName, (mod) =>
            resolveOffsets(mod, p, ["table_b"], (rvas) => installHook(mod, rvas.table_b, layout), { stage }));
    }),
};
