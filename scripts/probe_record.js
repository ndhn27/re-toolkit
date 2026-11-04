// probe_record.js
//
// Exploratory probe for a record whose layout isn't known yet - dumps the
// first 128 raw bytes of the record, plus 48 raw bytes at every 8-byte slot
// whose value could be a pointer, so the field layout can be identified by
// eye. Same technique as docs/METHODOLOGY.md walks through.
//
// The "possible pointer" lines are a heuristic, not a finding: a slot is listed
// if its value is non-null and falls in a readable range, which an integer or
// packed fields can do too, and nothing here knows what it points at
// (System.String*, byte[]*, another record, ...). The bytes are shown raw, never
// decoded. Confirm a candidate by reading it the way the real agent would
// (readIl2CppString in _lib.js) before writing it into your layouts.json.
//
// The RVA of ...$$unpack (from Ghidra's Symbol Table, using Image Base = 0; an
// RVA, not a file offset - see README.md's "RVA vs file offset") arrives in
// rpc.exports.init(stage, params) as offsets.probe, from your profile - this
// file holds no target-specific value. Build with `npm run build` (docs/INSTALL.md), then attach the bundled dist/probe_record.js with the
// Frida CLI - NOT through retk dump, which exports a collected table and
// this agent only prints (the driver refuses it before resuming the app):
//
//   frida -R -f <package> -l dist/probe_record.js \
//         -P "$(retk profile params NAME --offset probe=0x...)"
//
// `--offset KEY=HEX` (and `--module`) override the profile for one run, as they
// do for the drivers - handy while you are still hunting for the right RVA.

import { waitForModule, unpackFailed, parseParams, agentInit } from "./_lib.js";
import { resolveOffsets, resolutionExport } from "./_resolve.js";

const RECORD_DUMP_SIZE = 0x80; // enough for a record of ~30 4-byte fields

function installHook(mod, offset) {
    const addr = mod.base.add(offset);
    console.log("[+] Hooking unpack at", addr);

    let count = 0;
    const MAX_DUMPS = 8; // only dump the first 8 records, enough to read the layout

    Interceptor.attach(addr, {
        onEnter(args) {
            this.recordPtr = args[0];
        },
        onLeave(retval) {
            if (unpackFailed(retval)) {
                console.log(`[!] unpack failed: ${retval}`);
                return;
            }
            count++;
            if (count > MAX_DUMPS) return;

            const rec = this.recordPtr;
            console.log(`\n===== record #${count}  rec=${rec} =====`);
            try {
                const bytes = rec.readByteArray(RECORD_DUMP_SIZE);
                console.log(hexdump(bytes, { address: rec, length: RECORD_DUMP_SIZE }));

                // Scan every 8-byte slot for a value that could be a pointer
                // (heuristic: non-null and inside a readable region) and dump 48
                // raw bytes there too - candidates for string fields. Only
                // candidates: see the header comment for why a hit doesn't
                // prove it's a pointer, let alone a System.String*.
                for (let off = 0; off < RECORD_DUMP_SIZE; off += 8) {
                    const val = rec.add(off).readPointer();
                    if (val.isNull()) continue;
                    const range = Process.findRangeByAddress(val);
                    if (range && range.protection.indexOf("r") !== -1) {
                        console.log(`  --- possible pointer at +0x${off.toString(16)} = ${val} (prot=${range.protection}, unverified) ---`);
                        try {
                            const sub = val.readByteArray(48);
                            console.log(hexdump(sub, { address: val, length: 48 }));
                        } catch (e) {
                            console.log(`  (could not read: ${e.message})`);
                        }
                    }
                }
            } catch (e) {
                console.log("[!] Error dumping record:", e.message);
            }
        },
    });

    console.log("[+] Hook installed. Waiting for the app to unpack records...");
}

rpc.exports = {
    getResolution: resolutionExport,
    init: agentInit((params, stage) => {
        const p = parseParams(params, { offsets: ["probe"] });
        waitForModule(p.moduleName, (mod) =>
            resolveOffsets(mod, p, ["probe"], (rvas) => installHook(mod, rvas.probe), { stage }));
    }),
};
