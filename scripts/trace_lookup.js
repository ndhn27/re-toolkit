// trace_lookup.js
//
// Hooks two "lookup" functions instead of just reading the data tables - so
// the actual running selection algorithm can be observed directly, without
// having to hand-read the decompiled code:
//
//   LookupByPattern(key: System.String, ?, kind: int) -> TableBRecord* | NULL
//       picks the record whose pattern matches `key` (NULL if none does)
//   ResolveDefault() -> TableBRecord*
//       the top-level entry point that returns the final chosen record
//
// Both names are placeholders for whatever your target calls its own
// functions. Their RVAs (found by static analysis, Image Base = 0; these are
// RVAs, not file offsets - see README.md's "RVA vs file offset") arrive in
// rpc.exports.init(stage, params) as offsets.lookup_by_pattern and
// offsets.resolve_default, from your profile - this file holds no
// target-specific value. A profile may also name them (names.methods.lookup_by_pattern /
// resolve_default): the IL2CPP runtime is asked for the address first and the RVA is the
// fallback (_resolve.js; docs/NAME_LOOKUP.md). Build with `npm run build` (docs/INSTALL.md), then attach the bundled dist/trace_lookup.js with the Frida CLI
// - NOT through retk dump, which exports a collected table and this
// agent collects nothing (the driver refuses it before resuming the app):
//
//   frida -R -f <package> -l dist/trace_lookup.js \
//         -P "$(retk profile params NAME)"
//
// `profiles.py params` takes the same `--offset KEY=HEX` / `--module` overrides
// as the drivers (docs/USAGE.md), for trying an RVA without editing the
// profile.
//
// Both hooked functions return a pointer to a full TableBRecord, but only the
// few fields in the profile's `LookupResult` subset are worth watching live.
// They're read with the same layout as dump_table_b.js - it's the same
// underlying struct, so there is nothing to keep in sync by hand.

import { readIl2CppString, readRecord, waitForModule, parseParams, agentInit } from "./_lib.js";
import { resolveOffsets, resolutionExport } from "./_resolve.js";

/**
 * @param {NativePointer} ptr
 * @param {{name: string, offset: number, type: string}[]} layout
 * @param {string[]} fields names of the subset's fields
 * @returns {Object|null|string} the record, `null` if `ptr` was
 *   null (no match), or a `<error reading result: ...>` string if a field
 *   read failed partway through
 */
function readLookupResult(ptr, layout, fields) {
    if (ptr.isNull()) return null;
    try {
        return readRecord(ptr, layout, fields);
    } catch (e) {
        return `<error reading result: ${e.message}>`;
    }
}

function installHooks(mod, offsets, layout, fields) {
    const addrLookup = mod.base.add(offsets.lookup_by_pattern);
    const addrResolve = mod.base.add(offsets.resolve_default);

    console.log("[+] Hooking LookupByPattern at", addrLookup);
    console.log("[+] Hooking ResolveDefault at", addrResolve);

    Interceptor.attach(addrLookup, {
        onEnter(args) {
            try {
                const key = readIl2CppString(args[0]);
                const kind = args[2].toInt32();
                console.log(`\n  [LookupByPattern] key="${key}" kind=${kind}`);
            } catch (e) {
                console.log(`\n  [LookupByPattern] onEnter error: ${e.message}`);
            }
        },
        onLeave(retval) {
            const result = readLookupResult(retval, layout, fields);
            console.log(`  [LookupByPattern] -> ${result === null ? "NULL (no match)" : JSON.stringify(result)}`);
        },
    });

    Interceptor.attach(addrResolve, {
        onEnter(args) {
            console.log("\n===== ResolveDefault() called =====");
        },
        onLeave(retval) {
            const result = readLookupResult(retval, layout, fields);
            console.log("===== FINAL RESULT:", result === null ? "NULL" : JSON.stringify(result), "=====\n");
        },
    });

    console.log("[+] Hooks installed. Waiting for ResolveDefault() to be called...");
}

rpc.exports = {
    getResolution: resolutionExport,
    init: agentInit((params, stage) => {
        const p = parseParams(params, {
            offsets: ["lookup_by_pattern", "resolve_default"],
            records: ["TableBRecord"],
            subsets: ["LookupResult"],
        });
        waitForModule(p.moduleName, (mod) =>
            resolveOffsets(mod, p, ["lookup_by_pattern", "resolve_default"],
                (rvas) => installHooks(mod, rvas, p.records.TableBRecord.layout, p.subsets.LookupResult), { stage }));
    }),
};
