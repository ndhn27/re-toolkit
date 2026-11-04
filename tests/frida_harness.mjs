// frida_harness.mjs
//
// Runs the REAL scripts/*.js code under Node against a fake process image, so
// tests/test_layouts.py can check what the agents actually read and export
// without a device or Frida. Driven from Python: one JSON request on stdin,
// one JSON response on stdout.
//
//   { "scriptsDir": "...", "image": "<base64 process memory>", "params": {...}, "mode": ... }
//
// `params` is what the driver would pass to rpc.exports.init(stage, params):
// {module, offsets, layouts}. The image is the whole address space: address N
// is byte N of the image, and the app's module is loaded at address 0. Modes:
//
//   info                        -> { readers: [FIELD_READERS keys], unreadableKey: UNREADABLE_KEY,
//                                    apiFunctions: API_FUNCTIONS, resolveModes: RESOLVE_MODES,
//                                    snapshotContainers: CONTAINERS (scripts/_snapshot.js) }
//   seal        records: [{...}] -> [sealUnreadable(record)]
//        what the dump agents export for a record whose strings could not be read
//   readRecord  cases: [{record, base, only?}]
//                               -> [{ok: record} | {error}]
//        reads each record with params.layouts.records[record].fields
//   string      addrs: [n]      -> [readIl2CppString(n)]
//   agent       agent, events: [{hook, args, retval}]
//                               -> { attached, log, initError, rpc: {count, records} | null,
//                                    unreadable: getUnreadable() | null,
//                                    health: getHealth() | null, verification: getVerification() | null,
//                                    messages: [send() payloads], timers: [{ms, cleared}] }
//        imports scriptsDir/<agent>, calls its rpc.exports.init("early", params)
//        (an init that throws is reported in `initError`, not fatal), then feeds
//        each event to the Interceptor.attach() callback number `hook`, in order.
//        `moduleAlreadyLoaded: false` makes the module load right after init (the observer
//        fires); with `moduleNeverLoads: true` it never does. `otherModules: [names]` are
//        always loaded (what a wrong `module` name would be looked up against).
//        Timers never run on their own: setTimeout only records them, and
//        `fireTimers: true` runs the ones still pending once the events are done
//        (so "the module still isn't loaded after 20 s" needs no 20 s wait).
//        `moduleSize` gives the app's module a `size`; `arch` is Process.arch (default "arm64").
//        `rangeProtections: {"<address>": "rw-"}` is what findRangeByAddress reports for an
//        address (default "r-x"); `attachThrows: [addresses]` makes Interceptor.attach fail there.
//   resolve     keys, params, model, mode-less: drives scripts/_resolve.js's resolveOffsets() with a made-up
//               IL2CPP runtime (`model`, below) in place of the Frida binding
//                               -> { rvas: [{key: rva}, ...every onReady call], resolution, fields, log, error }
//        `model`: {ready: "now" | "later" | {unavailable: why}, can: {nest, methods, methodByName, fields},
//                  assemblies: [{name, classes: [{namespace, name, nested: [class], methods: [{name, argc, rva}],
//                  fields: [{name, offset}]}]}]}. "later" holds `done` until the end of the request, so a
//        test can see that nothing is hooked before the runtime is up (`readyBefore` is what had been called by then).
//        The "agent" mode also takes `stage` (the rpc.exports.init stage, default "early").
//   canary      record, fields: [{name, offset, type, expect?}], klass?, headerSize?, sample?, gate?,
//               observations: [{base, record, keyConflict?, failed?}]
//                               -> { health, log, messages }
//        drives scripts/_canary.js directly, without an agent around it. The canary reads the
//        fake image itself when it probes for drift, so `base` must point at real bytes.
//
// Only the bits of Frida the agents touch are faked (NativePointer reads,
// Process.getModuleByName / findRangeByAddress, Interceptor.attach, rpc), with Frida's semantics:
// readU32 is unsigned, readS32/readS8 are signed, reading outside the image
// throws.

import path from "node:path";
import { pathToFileURL } from "node:url";

const chunks = [];
for await (const c of process.stdin) chunks.push(c);
const req = JSON.parse(Buffer.concat(chunks).toString("utf8"));
const mem = Buffer.from(req.image, "base64");

class Ptr {
    constructor(addr) {
        this.addr = addr;
    }
    add(n) {
        return new Ptr(this.addr + Number(n));
    }
    and(mask) {
        return new Ptr(Number(BigInt(this.addr) & BigInt(mask)));
    }
    isNull() {
        return this.addr === 0;
    }
    toInt32() {
        return this.addr | 0;
    }
    toString() {
        return "0x" + this.addr.toString(16);
    }
    _at(size) {
        if (this.addr < 0 || this.addr + size > mem.length) {
            throw new Error(`access violation accessing ${this}`);
        }
        return this.addr;
    }
    readU8() { return mem.readUInt8(this._at(1)); }
    readS8() { return mem.readInt8(this._at(1)); }
    readU32() { return mem.readUInt32LE(this._at(4)); }
    readS32() { return mem.readInt32LE(this._at(4)); }
    readPointer() { return new Ptr(Number(mem.readBigUInt64LE(this._at(8)))); }
    readUtf16String(len) {
        const at = this._at(len * 2);
        return mem.toString("utf16le", at, at + len * 2);
    }
}

// The image is the whole address space, so an address is "mapped" iff it falls inside it.
function findRangeByAddress(p) {
    if (!(p.addr > 0 && p.addr < mem.length)) return null;
    const protection = (req.rangeProtections || {})[String(p.addr)] || "r-x";
    return { base: new Ptr(0), size: mem.length, protection };
}

const dir = req.scriptsDir;
const load = (name) => import(pathToFileURL(path.join(dir, name)).href);
const respond = (obj) => process.stdout.write(JSON.stringify(obj));

// The single JSON response is the only thing allowed on real stdout (Python
// parses it verbatim - see run_harness()), so console.log is redirected for
// EVERY mode, not just "agent": any code under tests/ - _lib.js included,
// not just the agent entry points - may log, and a stray line would corrupt
// the JSON the same way regardless of which mode triggered it.
const log = [];
console.log = (...a) => log.push(a.map(String).join(" "));

if (req.mode === "info") {
    const lib = await load("_lib.js");
    const res = await load("_resolve.js");
    const snap = await load("_snapshot.js");
    respond({ readers: Object.keys(lib.FIELD_READERS), unreadableKey: lib.UNREADABLE_KEY,
              apiFunctions: res.API_FUNCTIONS, resolveModes: res.RESOLVE_MODES, snapshotContainers: snap.CONTAINERS });
} else if (req.mode === "buildId") {
    const b = await load("_buildid.js");
    respond({ build: b.readBuildId({ base: new Ptr(req.base || 0) }) });
} else if (req.mode === "seal") {
    const lib = await load("_lib.js");
    respond(req.records.map((r) => lib.sealUnreadable(r)));
} else if (req.mode === "readRecord") {
    const lib = await load("_lib.js");
    lib.parseParams(req.params, { records: Object.keys(req.params.layouts.records) });
    respond(req.cases.map((c) => {
        try {
            return { ok: lib.readRecord(new Ptr(c.base), req.params.layouts.records[c.record].fields, c.only ?? undefined) };
        } catch (e) {
            return { error: e.message };
        }
    }));
} else if (req.mode === "string") {
    const lib = await load("_lib.js");
    lib.parseParams(req.params, { records: Object.keys(req.params.layouts.records) });
    respond(req.addrs.map((a) => lib.readIl2CppString(new Ptr(a))));
} else if (req.mode === "agent") {
    const attached = [];
    const already = req.moduleAlreadyLoaded !== false;
    const loadedName = req.moduleName || "UnityFramework";
    const loadedPath = req.modulePath || loadedName;
    let observerCb = null;
    globalThis.Process = {
        getModuleByName(name) {
            if (req.moduleByNameThrows || !already) {
                throw new Error(`unable to find module: ${name}`);
            }
            if (name !== ((req.params && req.params.module) || "UnityFramework")) {
                throw new Error(`unable to find module: ${name}`);
            }
            const mod = { name: loadedName, path: loadedPath, base: new Ptr(0) };
            if (req.moduleSize !== undefined) mod.size = req.moduleSize;
            return mod;
        },
        enumerateModules() {
            const mods = already ? [{ name: loadedName, path: loadedPath, base: new Ptr(0) }] : [];
            return mods.concat((req.otherModules || []).map((n) => ({ name: n, path: "/x/" + n, base: new Ptr(0) })));
        },
        arch: req.arch || "arm64",          // the toolkit's target; `arch: "x64"` is what the real-Frida tests run on
        findRangeByAddress: findRangeByAddress,
        attachModuleObserver(hooks) {
            observerCb = hooks.onAdded;
            return { detach() { observerCb = null; } };
        },
    };
    globalThis.Interceptor = {
        attach: (addr, cb) => {
            if ((req.attachThrows || []).includes(addr.addr)) throw new Error(`unable to intercept function at ${addr}`);
            attached.push({ addr: addr.addr, cb });
        },
    };
    globalThis.rpc = {};
    const messages = [];
    globalThis.send = (payload) => messages.push(payload);
    const timers = [];
    globalThis.setTimeout = (fn, ms) => { timers.push({ fn, ms, cleared: false }); return timers.length; };
    globalThis.clearTimeout = (id) => { if (timers[id - 1]) timers[id - 1].cleared = true; };

    await load(req.agent);

    let initError = null;
    try {
        globalThis.rpc.exports.init(req.stage || "early", req.params);
    } catch (e) {
        initError = e.message;
    }

    if (!already && observerCb && !req.moduleNeverLoads) {
        observerCb({ name: loadedName, path: loadedPath, base: new Ptr(0) });
    }
    for (const ev of req.events) {
        const { cb } = attached[ev.hook];
        const ctx = {};
        if (cb.onEnter) cb.onEnter.call(ctx, (ev.args ?? []).map((a) => new Ptr(a)));
        if (cb.onLeave) cb.onLeave.call(ctx, new Ptr(ev.retval ?? 0));
    }
    if (req.fireTimers) for (const t of timers) if (!t.cleared) t.fn();
    const ex = globalThis.rpc.exports;
    respond({
        attached: attached.map((a) => a.addr),
        log,
        initError,
        rpc: ex && ex.getCount ? { count: ex.getCount(), records: ex.getRecords() } : null,
        unreadable: ex && ex.getUnreadable ? ex.getUnreadable() : null,
        health: ex && ex.getHealth ? ex.getHealth() : null,
        verification: ex && ex.getVerification ? ex.getVerification() : null,
        resolution: ex && ex.getResolution ? ex.getResolution() : null,
        messages,
        timers: timers.map((t) => ({ ms: t.ms, cleared: t.cleared })),
    });
} else if (req.mode === "resolve") {
    const lib = await load("_lib.js");
    const res = await load("_resolve.js");
    const p = lib.parseParams(req.params, { offsets: req.keys, records: Object.keys((req.params.layouts || {}).records || {}) });
    const model = req.model;
    let nextId = 0;
    const tag = (c) => { c.id = c.id ?? ++nextId; c.toString = () => `class#${c.id}`; (c.nested || []).forEach(tag); return c; };
    model.assemblies.forEach((a) => a.classes.forEach(tag));
    const can = { nest: true, methods: true, methodByName: true, fields: true, ...(model.can || {}) };
    let pendingDone = null;
    const api = {
        has: () => true,
        whenReady(done, unavailable) {
            if (model.ready === "now" || model.ready === undefined) done();
            else if (model.ready === "later") pendingDone = done;
            else unavailable(model.ready.unavailable);
        },
        images: () => model.assemblies.map((a) => ({ name: a.name, image: a })),
        classFromName: (image, ns, name) => image.classes.find((c) => (c.namespace || "") === ns && c.name === name) || null,
        canNest: () => can.nest,
        nestedClass: (k, name) => (k.nested || []).find((c) => c.name === name) || null,
        canEnumerateMethods: () => can.methods,
        methods: (k) => (k.methods || []).map((m) => ({ name: m.name, argc: m.argc, info: m })),
        canFindMethodByName: () => can.methodByName,
        methodFromName: (k, name, argc) => (k.methods || []).find((m) => m.name === name && (argc < 0 || m.argc === argc)) || null,
        methodRva: (info) => (info.rva === undefined ? null : info.rva),
        canReadFields: () => can.fields,
        fieldOffset: (k, name) => { const f = (k.fields || []).find((x) => x.name === name); return f ? f.offset : null; },
    };
    const mod = { base: new Ptr(0) };
    if (req.moduleSize !== undefined) mod.size = req.moduleSize;
    const rvas = [];
    let error = null;
    try {
        res.resolveOffsets(mod, p, req.keys, (r) => rvas.push(r), { makeApi: () => api, stage: req.stage || "early" });
    } catch (e) {
        error = e.message;
    }
    const readyBefore = rvas.length;
    if (pendingDone) pendingDone();
    respond({ rvas, readyBefore, resolution: res.resolutionExport(), fields: res.fieldOffsetsHealth(), log, error });
} else if (req.mode === "canary") {
    globalThis.Process = { findRangeByAddress };
    const messages = [];
    globalThis.send = (payload) => messages.push(payload);
    const { createCanary } = await load("_canary.js");
    const options = {};
    for (const key of ["klass", "headerSize", "sample", "gate"]) if (req[key] !== undefined && req[key] !== null) options[key] = req[key];
    const canary = createCanary(req.record, req.fields, options);
    for (const o of req.observations) {
        if (o.failed) canary.readFailed(new Error(o.failed));
        else canary.observe(new Ptr(o.base), o.record, !!o.keyConflict);
    }
    respond({ health: canary.health(), log, messages });
} else {
    throw new Error(`unknown mode ${req.mode}`);
}
