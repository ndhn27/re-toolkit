// frida_harness.mjs
//
// Runs the REAL scripts/*.js code under Node against a fake process image, so
// tests/test_layouts.py can check what the agents actually read and export
// without a device or Frida. Driven from Python: one JSON request on stdin,
// one JSON response on stdout.
//
//   { "scriptsDir": "...", "image": "<base64 process memory>", "mode": ... }
//
// The image is the whole address space: address N is byte N of the image, and
// UnityFramework is loaded at address 0. Modes:
//
//   info                        -> { readers: [FIELD_READERS keys] }
//   readRecord  cases: [{layout, base, only?}]
//                               -> [{ok: record} | {error}]
//   string      addrs: [n]      -> [readIl2CppString(n)]
//   agent       agent, events: [{hook, args, retval}]
//                               -> { attached, log, rpc: {count, records} | null }
//        imports scriptsDir/<agent> (its FRIDA_OFFSET placeholders must
//        already be patched non-zero), then feeds each event to the
//        Interceptor.attach() callback number `hook`, in order.
//
// Only the bits of Frida the agents touch are faked (NativePointer reads,
// Process.getModuleByName, Interceptor.attach, rpc), with Frida's semantics:
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
    respond({ readers: Object.keys(lib.FIELD_READERS) });
} else if (req.mode === "readRecord") {
    const lib = await load("_lib.js");
    const layouts = await load("_layouts.js");
    respond(req.cases.map((c) => {
        try {
            return { ok: lib.readRecord(new Ptr(c.base), layouts[c.layout], c.only ?? undefined) };
        } catch (e) {
            return { error: e.message };
        }
    }));
} else if (req.mode === "string") {
    const lib = await load("_lib.js");
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
            if (name !== "UnityFramework") throw new Error(`unable to find module: ${name}`);
            return { name: loadedName, path: loadedPath, base: new Ptr(0) };
        },
        enumerateModules() {
            if (!already) return [];
            return [{ name: loadedName, path: loadedPath, base: new Ptr(0) }];
        },
        attachModuleObserver(hooks) {
            observerCb = hooks.onAdded;
            return { detach() { observerCb = null; } };
        },
    };
    globalThis.Interceptor = { attach: (addr, cb) => attached.push({ addr: addr.addr, cb }) };
    globalThis.rpc = {};
    globalThis.send = () => {};

    await load(req.agent);

    if (!already && observerCb) {
        observerCb({ name: loadedName, path: loadedPath, base: new Ptr(0) });
    }
    for (const ev of req.events) {
        const { cb } = attached[ev.hook];
        const ctx = {};
        if (cb.onEnter) cb.onEnter.call(ctx, (ev.args ?? []).map((a) => new Ptr(a)));
        if (cb.onLeave) cb.onLeave.call(ctx, new Ptr(ev.retval ?? 0));
    }
    const ex = globalThis.rpc.exports;
    respond({
        attached: attached.map((a) => a.addr),
        log,
        rpc: ex ? { count: ex.getCount(), records: ex.getRecords() } : null,
    });
} else {
    throw new Error(`unknown mode ${req.mode}`);
}
