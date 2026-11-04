// verify_hook.js
//
// Trial-hooks one or more CANDIDATE addresses - what retk relocate found in
// a new build - and checks what each one hands back against the profile's record
// layout, so a candidate can be called "verified" and not just "the bytes matched".
//
// A byte match says the code at an address looks like the old function's. It cannot
// say the address is the function the app really calls, or that the record that
// function is given is still laid out the way the profile says. This agent says both,
// by running the real thing: for every call of every candidate it does what
// dump_table_a.js does - take args[0] on entry, and on a successful return read the
// record through the layout - and feeds the result to the same layout canary
// (_canary.js: class word, string sanity, the profile's `expect`, drift measurement).
// It stores nothing and exports no table; retk verify asks for
// getVerification() and judges the counts (retk/verification.py), so the verdict is
// plain Python that a test pins.
//
// It assumes the convention the dump agents use: the record is args[0] and the call
// succeeded when the low 32 bits of the return value are 0 (unpackFailed in _lib.js -
// the same assumption, flagged there). A hook whose record comes back as the return
// value is not covered.
//
// Parameters (rpc.exports.init(stage, params); retk verify builds them):
//
//   module                       the IL2CPP module to hook in
//   layouts                      the profile's layouts (the record read, the string layout)
//   verify.record                the name of the record in layouts.records
//   verify.candidates            [{id, rva}] - RVAs, Image Base = 0 (NOT file offsets; see
//                                README.md's "RVA vs file offset"; relocate_offset.py prints
//                                its result as an RVA too)
//
// A candidate is refused rather than hooked - and says why in `error` - when it is not
// 4-byte aligned, lies beyond the module, or is in memory that is not executable:
// hooking the middle of data is how a wrong candidate crashes the app.
//
// This file holds no address and no name of a real target. Build with `npm run build`.

import { readRecord, waitForModule, unpackFailed, parseParams, agentInit } from "./_lib.js";
import { createCanary } from "./_canary.js";

const state = { record: null, moduleName: null, moduleLoaded: false, candidates: [] };

/** Why `rva` cannot be hooked in `mod`, or null if nothing speaks against it. */
function refusal(mod, rva) {
    // Only AArch64 has fixed-width instructions: elsewhere (the x86-64 the tests run on) any address may be one.
    if (Process.arch === "arm64" && rva % 4 !== 0) {
        return `RVA 0x${rva.toString(16)} is not 4-byte aligned - an AArch64 instruction cannot start there`;
    }
    if (typeof mod.size === "number" && rva >= mod.size) {
        return `RVA 0x${rva.toString(16)} is beyond the end of ${state.moduleName} (size 0x${mod.size.toString(16)}) - ` +
            `a position in the file passed in place of an RVA?`;
    }
    let range = null;
    let told = false;
    try {
        range = Process.findRangeByAddress(mod.base.add(rva));
        told = true;
    } catch (e) {
        // can't tell - leave it to Interceptor.attach
    }
    if (told && range === null) return `RVA 0x${rva.toString(16)} is not in any mapped range of the process`;
    if (range && typeof range.protection === "string" && !range.protection.includes("x")) {
        return `RVA 0x${rva.toString(16)} is in ${range.protection} memory, not executable - not code`;
    }
    return null;
}

function hookCandidate(mod, c, layout) {
    const why = refusal(mod, c.rva);
    if (why) {
        c.error = why;
        console.log(`[!] candidate ${c.id}: ${why} - not hooked`);
        return;
    }
    const addr = mod.base.add(c.rva);
    try {
        Interceptor.attach(addr, {
            onEnter(args) {
                c.enters++;
                this.recordPtr = args[0];
            },
            onLeave(retval) {
                c.leaves++;
                if (unpackFailed(retval)) {
                    c.failedReturns++;
                    return;
                }
                try {
                    c.canary.observe(this.recordPtr, readRecord(this.recordPtr, layout), false);
                } catch (e) {
                    c.canary.readFailed(e);
                }
            },
        });
        c.hooked = true;
        console.log(`[+] candidate ${c.id}: hooked ${addr}`);
    } catch (e) {
        c.error = `could not hook: ${e.message}`;
        console.log(`[!] candidate ${c.id}: ${c.error}`);
    }
}

function parseVerify(params) {
    const v = params && params.verify;
    if (!v || typeof v.record !== "string" || !Array.isArray(v.candidates) || v.candidates.length === 0) {
        throw new Error("no `verify` section in the parameters: {record, candidates: [{id, rva}]} - run this " +
            "through retk verify");
    }
    const ids = new Set();
    for (const c of v.candidates) {
        if (!c || typeof c.id !== "string" || ids.has(c.id)) throw new Error("verify.candidates: every candidate needs a unique `id`");
        ids.add(c.id);
        if (!Number.isSafeInteger(c.rva) || c.rva <= 0) {
            throw new Error(`verify.candidates[${c.id}].rva is missing or 0 - an RVA with Image Base = 0`);
        }
    }
    return v;
}

rpc.exports = {
    /**
     * What every candidate did: how often it was entered, how often it returned a
     * failure, and - in `health`, the layout canary's counts - how well the records it
     * handed back fit the layout. Safe to call at any time, even before init.
     */
    getVerification: () => ({
        version: 1,
        record: state.record,
        module: state.moduleName,
        module_loaded: state.moduleLoaded,
        candidates: state.candidates.map((c) => ({
            id: c.id, rva: c.rva, hooked: c.hooked, error: c.error,
            enters: c.enters, leaves: c.leaves, failed_returns: c.failedReturns,
            health: c.canary ? c.canary.health() : null,
        })),
    }),
    init: agentInit((params) => {
        parseParams(params);                       // refuses a missing module (and missing params) first, like every agent
        const v = parseVerify(params);
        const p = parseParams(params, { records: [v.record] });
        const { layout, klass } = p.records[v.record];
        state.record = v.record;
        state.moduleName = p.moduleName;
        state.candidates = v.candidates.map((c) => ({
            id: c.id, rva: c.rva, hooked: false, error: null, enters: 0, leaves: 0, failedReturns: 0,
            canary: createCanary(v.record, layout, { klass, headerSize: p.headerSize, sample: p.check.sample }),
        }));
        waitForModule(p.moduleName, (mod) => {
            state.moduleLoaded = true;
            for (const c of state.candidates) hookCandidate(mod, c, layout);
            console.log("[+] Waiting for the app to call the candidates...");
        });
    }),
};
