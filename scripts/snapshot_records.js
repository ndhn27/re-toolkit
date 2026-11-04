// snapshot_records.js
//
// Takes the table out of a running app WITHOUT hooking its unpack function: for an attach that comes
// after the app has already unpacked everything (dump_table_a.js would wait for a call that never comes).
// It looks for the records where they live - a static field that holds the table, and/or the live
// instances of the record class on the heap - reads them with the profile's layout, and serves them
// through the same rpc exports the dump agents have, so retk dump exports them unchanged:
//
//     retk dump --profile myapp --attach <process> --snapshot
//
// Like every agent here it names no target-specific value: the parameters arrive in
// rpc.exports.init(stage, params) from the profile (README.md's "Snapshot"):
//
//   snapshot.record   which record of layouts.records to read (e.g. "TableARecord")
//   snapshot.static   (optional) {namespace, class, assembly?, field, container: object | array | list}
//   snapshot.heap     (optional) {namespace, class, assembly?, max?, budget_ms?}
//   layouts.records.<record>   where each field of a record lives, and its `key`
//   names.exports / names.fields   as for every agent (_resolve.js)
//
// rpc exports: getCount / getRecords / getUnreadable / clear (the record store), getHealth (the layout
// canary - and the runtime's field offsets, when the profile names them), getResolution, and
//   snapshot()      take the snapshot - now if the runtime is up, as soon as it is otherwise. Returns at
//                   once; the work goes on in the background (a heap scan takes seconds)
//   getSnapshot()   {state: idle | waiting | running | done | failed, count, sources: [...], why}
//
// The snapshot is only taken when asked to (an agent loaded at spawn has nothing to read yet).

import { createRecordStore, waitForModule, parseParams, agentInit } from "./_lib.js";
import { createCanary, healthExport } from "./_canary.js";
import { resolveOffsets, resolutionExport, withFieldOffsets } from "./_resolve.js";
import { createSnapshot, makeIo } from "./_snapshot.js";

let keyOf = null;
const { records, put, rpcExports } = createRecordStore((rec) => keyOf(rec));
let canary = null;
let snapshot = null;      // createSnapshot(), set by init
let runtime = null;       // {api, io} once the IL2CPP runtime is up
let asked = false;        // snapshot() was called
let started = false;

function maybeStart() {
    if (!asked || started || snapshot === null || runtime === null) return;
    started = true;
    snapshot.run(runtime.api, runtime.io).then(
        () => { started = false; asked = false; },
        (e) => { started = false; asked = false; snapshot.fail(`the snapshot threw: ${e.message}`); },
    );
}

rpc.exports = {
    ...rpcExports,
    getHealth: () => withFieldOffsets(healthExport(canary)),
    getResolution: resolutionExport,
    getSnapshot: () => (snapshot === null ? { state: "idle", count: 0, sources: [], why: "not initialised" } : snapshot.status()),
    snapshot: () => {
        if (snapshot === null) throw new Error("snapshot(): init has not run");
        if (started) return { started: false, why: "a snapshot is already running" };
        asked = true;
        if (runtime === null && snapshot.status().state !== "failed") snapshot.wait();
        maybeStart();
        return { started: true };
    },
    init: agentInit((params, stage) => {
        const want = params.snapshot;
        if (!want || typeof want.record !== "string" || (!want.static && !want.heap)) {
            throw new Error("snapshot params: need snapshot.record and at least one of snapshot.static / snapshot.heap");
        }
        const p = parseParams(params, { records: [want.record] });
        const { layout, keyOf: k, klass } = p.records[want.record];
        keyOf = k;
        canary = createCanary(want.record, layout, { klass, headerSize: p.headerSize, sample: p.check.sample, gate: false });
        snapshot = createSnapshot({ layout, store: { put, clear: rpcExports.clear, size: () => records.size }, canary, want });
        waitForModule(p.moduleName, (mod) =>
            resolveOffsets(mod, p, [], () => {}, {
                stage,
                onRuntime: (api) => {
                    runtime = { api, io: makeIo() };
                    maybeStart();
                },
                onUnavailable: (why) => {
                    snapshot.fail(`the IL2CPP runtime cannot be asked (${why}) - a snapshot needs it to find the class`);
                },
            }));
    }),
};
