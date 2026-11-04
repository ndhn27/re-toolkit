// _resolve.js
//
// Finds what an agent hooks BY NAME, with the profile's RVA as the fallback. Shared by the
// agents (dump_table_a.js, dump_table_b.js, trace_lookup.js, probe_record.js); not an agent
// itself. Bundled into dist/ by `npm run build` like _lib.js.
//
// The order, per hook point:
//
//   0. A BUILD THE TOOLKIT HAS SEEN. When `params.cache` holds an RVA for this hook point that an
//      earlier, verified run recorded for THIS build of the module (the build is read from the
//      loaded module's own headers: _buildid.js), that RVA is used as it is - the build is the
//      same code, so the address is too - and nothing is asked of the runtime for it. Only in
//      resolve mode "auto": "names" and "rva" say where an address must come from. A build the
//      cache has not seen gets what follows, which is the rescan.
//
// Per hook point the profile has a name for (`names.methods`):
//
//   1. ASK THE IL2CPP RUNTIME. The module exports the IL2CPP C API (il2cpp_class_from_name,
//      il2cpp_class_get_methods, ...). Class -> method -> MethodInfo -> its first word is the
//      method pointer; minus the module's base that is the RVA, taken directly from the
//      running build instead of from a Ghidra address that goes stale with every update.
//      Fields work the same way: class -> field -> il2cpp_field_get_offset is the offset the
//      runtime itself uses, which is compared with the profile's layout (see fieldOffsetsHealth).
//   2. FALL BACK TO THE RVA when the runtime cannot answer: the exports are hidden or stripped
//      (the module does not export what is needed - `names.exports` can say what a renamed
//      one is called), the runtime never came up, or the name does not resolve to exactly one
//      method. `resolve: "names"` turns the fallback off; `"rva"` skips the lookup.
//
// The name is only a lookup key: nothing here is a real name - they arrive in
// rpc.exports.init(stage, params) from the profile (names.methods / names.fields /
// names.exports), like every other value (see _lib.js's parseParams).
//
// WHEN the lookup can run. Class lookup needs the runtime to be initialised, which happens
// in il2cpp_init (or il2cpp_init_utf16) - after the agent is loaded when the app is spawned
// ("early" stage) and before it when attaching to a running one ("late"). Early, the agent
// hooks il2cpp_init and looks the names up in its onLeave, on the app's own thread; late, it
// asks il2cpp_domain_get() straight away and attaches its own thread first. Nothing in the
// target is called until then: il2cpp_domain_get is a read of a static pointer, null before
// init.
//
// The decision logic (findClass, findMethod, resolveOffsets, ...) only talks to an `api`
// object with plain methods, so tests/test_names_agent.py runs it under Node against a
// made-up metadata model; createIl2cppApi() is the Frida binding (NativeFunction over the
// module's exports), exercised against a real native library by tests/test_frida_real.py.
//
// What this does not cover: generic methods and classes (no single method pointer to find),
// static fields (il2cpp_field_get_offset is an offset into the class's static storage, not
// into an object), and any platform whose MethodInfo does not start with the method pointer
// (every Unity version this toolkit has met does; it is read at offset 0).

import { readBuildId, buildKey } from "./_buildid.js";

/** The IL2CPP C API this file may call. Keep equal to API_FUNCTIONS in retk/il2cpp_names.py (tested). */
export const API_FUNCTIONS = [
    "il2cpp_init", "il2cpp_init_utf16", "il2cpp_thread_attach",
    "il2cpp_domain_get", "il2cpp_domain_get_assemblies", "il2cpp_assembly_get_image",
    "il2cpp_image_get_name", "il2cpp_class_from_name", "il2cpp_class_get_name",
    "il2cpp_class_get_nested_types", "il2cpp_class_get_methods", "il2cpp_class_get_method_from_name",
    "il2cpp_method_get_name", "il2cpp_method_get_param_count",
    "il2cpp_class_get_field_from_name", "il2cpp_field_get_offset", "il2cpp_field_static_get_value",
];

/** What `resolve` may be. Keep equal to RESOLVE_MODES in retk/profiles.py (tested). */
export const RESOLVE_MODES = ["auto", "names", "rva"];

/** The least the lookup cannot work without. */
const REQUIRED = ["il2cpp_domain_get", "il2cpp_domain_get_assemblies", "il2cpp_assembly_get_image", "il2cpp_class_from_name"];

const POLL_MS = 250;              // without il2cpp_init to hook: how often to ask whether the runtime is up
const READY_TIMEOUT_MS = 30000;   // ... and how long before giving up and falling back
const MAX_ITERATIONS = 100000;    // runaway guard for the il2cpp_class_get_* iterators

/** A lookup that did not settle. `kind` says which way: api | not_ready | class_not_found |
 *  method_not_found | field_not_found | ambiguous | pointer. */
export class ResolveError extends Error {
    constructor(kind, message) {
        super(message);
        this.kind = kind;
    }
}

// ---------------------------------------------------------------------------------------
// the Frida binding
// ---------------------------------------------------------------------------------------

// [return type, argument types] of every function createIl2cppApi() calls.
const SIGNATURES = {
    il2cpp_thread_attach: ["pointer", ["pointer"]],
    il2cpp_domain_get: ["pointer", []],
    il2cpp_domain_get_assemblies: ["pointer", ["pointer", "pointer"]],
    il2cpp_assembly_get_image: ["pointer", ["pointer"]],
    il2cpp_image_get_name: ["pointer", ["pointer"]],
    il2cpp_class_from_name: ["pointer", ["pointer", "pointer", "pointer"]],
    il2cpp_class_get_name: ["pointer", ["pointer"]],
    il2cpp_class_get_nested_types: ["pointer", ["pointer", "pointer"]],
    il2cpp_class_get_methods: ["pointer", ["pointer", "pointer"]],
    il2cpp_class_get_method_from_name: ["pointer", ["pointer", "pointer", "int"]],
    il2cpp_method_get_name: ["pointer", ["pointer"]],
    il2cpp_method_get_param_count: ["uint32", ["pointer"]],
    il2cpp_class_get_field_from_name: ["pointer", ["pointer", "pointer"]],
    il2cpp_field_get_offset: ["int", ["pointer"]],
    il2cpp_field_static_get_value: ["void", ["pointer", "pointer"]],
};

/** A function that finds an export of `mod` by its IL2CPP API name, honouring `aliases`
 *  ({api name: the name the module really exports it as}). Returns null for a hidden one. */
function exportFinder(mod, aliases) {
    let table = null;
    return (api) => {
        const actual = aliases[api] || api;
        if (typeof mod.findExportByName === "function") {
            const p = mod.findExportByName(actual);
            if (p) return p;
        }
        if (table === null) {
            table = new Map();
            try {
                for (const e of mod.enumerateExports()) {
                    if (e.type === undefined || e.type === "function") table.set(e.name, e.address);
                }
            } catch (e) {
                // a module whose exports cannot be listed has none to find
            }
        }
        return table.get(actual) || null;
    };
}

/**
 * The `api` object the lookups below use, over the real exports of `mod`.
 *
 *   has(name)                  is that IL2CPP function exported (under its alias)?
 *   whenReady(done, unavailable)  done() once the runtime is up, unavailable(why) if it cannot be known
 *   images()                   [{name, image}]
 *   classFromName(image, ns, name) / nestedClass(klass, name) / className(klass)
 *   methods(klass)             [{name, argc, info}] - or null when the module cannot enumerate them
 *   methodFromName(klass, name, argc)
 *   methodRva(info)            the method pointer minus the module base, or null for no code
 *   fieldOffset(klass, name)   the runtime's offset for an instance field, or null for no such field
 *
 * `stage` is the rpc.exports.init stage: "early" (spawned, nothing has run yet - wait for il2cpp_init)
 * or anything else (attached to a running app - the runtime is up, and this thread must attach to it).
 */
export function createIl2cppApi(mod, aliases = {}, stage = "early") {
    const find = exportFinder(mod, aliases);
    const natives = {};
    const fn = (name) => {
        if (!(name in natives)) {
            const addr = find(name);
            const [ret, args] = SIGNATURES[name];
            natives[name] = addr ? new NativeFunction(addr, ret, args) : null;
        }
        return natives[name];
    };
    const has = (name) => find(name) !== null;
    const str = (p) => (p.isNull() ? null : p.readCString());
    const cstr = (s) => Memory.allocUtf8String(s);
    const iterate = (call, klass) => {
        const iter = Memory.alloc(Process.pointerSize);
        iter.writePointer(NULL);
        const out = [];
        for (let i = 0; i < MAX_ITERATIONS; i++) {
            const item = call(klass, iter);
            if (item.isNull()) break;
            out.push(item);
        }
        return out;
    };
    const domain = () => fn("il2cpp_domain_get")();

    return {
        has,

        missing(names = REQUIRED) {
            return names.filter((n) => !has(n));
        },

        whenReady(done, unavailable) {
            const absent = REQUIRED.filter((n) => !has(n));
            if (absent.length) {
                unavailable(`the module does not export ${absent.join(", ")} - hidden, stripped or renamed ` +
                    "(`names.exports` in the profile can say what a renamed one is called)");
                return;
            }
            const up = () => {
                const d = domain();
                if (d.isNull()) return false;
                const sizeBox = Memory.alloc(Process.pointerSize);
                fn("il2cpp_domain_get_assemblies")(d, sizeBox);
                return sizeBox.readU32() > 0;
            };
            const attachThread = () => {
                // late stage: this is Frida's own thread, not one the runtime knows
                if (stage !== "early" && has("il2cpp_thread_attach")) fn("il2cpp_thread_attach")(domain());
            };
            const ready = () => {
                try {
                    attachThread();
                } catch (e) {
                    console.log(`[!] il2cpp_thread_attach failed (${e.message}) - going on without it`);
                }
                done();
            };

            if (stage !== "early") {
                if (up()) return ready();
            }
            const inits = ["il2cpp_init", "il2cpp_init_utf16"].filter(has);
            if (stage === "early" && inits.length) {
                let fired = false;
                for (const name of inits) {
                    Interceptor.attach(find(name), {
                        onLeave() {
                            if (fired) return;
                            fired = true;
                            ready();
                        },
                    });
                }
                console.log(`[i] waiting for ${inits.join(" / ")} to return before looking names up`);
                return;
            }
            // Nothing to hook (init is hidden too), or attached late and not up yet: ask until it is.
            let waited = 0;
            const poll = () => {
                let isUp = false;
                try {
                    isUp = up();
                } catch (e) {
                    unavailable(`asking the runtime whether it is up failed: ${e.message}`);
                    return;
                }
                if (isUp) return ready();
                waited += POLL_MS;
                if (waited >= READY_TIMEOUT_MS) {
                    unavailable(`the IL2CPP runtime was not up after ${READY_TIMEOUT_MS / 1000}s`);
                    return;
                }
                setTimeout(poll, POLL_MS);
            };
            setTimeout(poll, POLL_MS);
        },

        images() {
            const d = domain();
            const sizeBox = Memory.alloc(Process.pointerSize);
            const arr = fn("il2cpp_domain_get_assemblies")(d, sizeBox);
            const n = sizeBox.readU32();
            const out = [];
            for (let i = 0; i < n; i++) {
                const image = fn("il2cpp_assembly_get_image")(arr.add(i * Process.pointerSize).readPointer());
                if (image.isNull()) continue;
                out.push({ name: has("il2cpp_image_get_name") ? str(fn("il2cpp_image_get_name")(image)) : null, image });
            }
            return out;
        },

        classFromName(image, ns, name) {
            const k = fn("il2cpp_class_from_name")(image, cstr(ns), cstr(name));
            return k.isNull() ? null : k;
        },

        canNest() {
            return has("il2cpp_class_get_nested_types") && has("il2cpp_class_get_name");
        },

        nestedClass(klass, name) {
            const kids = iterate(fn("il2cpp_class_get_nested_types"), klass);
            return kids.find((k) => str(fn("il2cpp_class_get_name")(k)) === name) || null;
        },

        canEnumerateMethods() {
            return has("il2cpp_class_get_methods") && has("il2cpp_method_get_name") && has("il2cpp_method_get_param_count");
        },

        methods(klass) {
            return iterate(fn("il2cpp_class_get_methods"), klass).map((info) => ({
                name: str(fn("il2cpp_method_get_name")(info)),
                argc: fn("il2cpp_method_get_param_count")(info),
                info,
            }));
        },

        canFindMethodByName() {
            return has("il2cpp_class_get_method_from_name");
        },

        methodFromName(klass, name, argc) {
            const info = fn("il2cpp_class_get_method_from_name")(klass, cstr(name), argc);
            return info.isNull() ? null : info;
        },

        methodRva(info) {
            // MethodInfo's first member is the method pointer, in every IL2CPP version
            const ptr = info.readPointer();
            if (ptr.isNull()) return null;
            const rva = Number(ptr.sub(mod.base).toString());
            return Number.isSafeInteger(rva) ? rva : null;
        },

        canReadFields() {
            return has("il2cpp_class_get_field_from_name") && has("il2cpp_field_get_offset");
        },

        fieldOffset(klass, name) {
            const f = fn("il2cpp_class_get_field_from_name")(klass, cstr(name));
            return f.isNull() ? null : fn("il2cpp_field_get_offset")(f);
        },

        canReadStatic() {
            return has("il2cpp_class_get_field_from_name") && has("il2cpp_field_static_get_value");
        },

        /** The pointer a static field holds (null for no such field). The runtime may initialise the class first. */
        staticFieldValue(klass, name) {
            const f = fn("il2cpp_class_get_field_from_name")(klass, cstr(name));
            if (f.isNull()) return null;
            const box = Memory.alloc(Process.pointerSize);
            box.writePointer(NULL);
            fn("il2cpp_field_static_get_value")(f, box);
            return box.readPointer();
        },
    };
}

// ---------------------------------------------------------------------------------------
// the lookups (pure: only `api`)
// ---------------------------------------------------------------------------------------

const label = (spec) => `${spec.namespace ? spec.namespace + "." : ""}${spec.class}`;
const specText = (spec) => `${label(spec)}::${spec.method}` + (spec.args === undefined || spec.args < 0 ? "" : `/${spec.args}`);
const sameImage = (want, have) => {
    if (!want) return true;
    const strip = (s) => String(s || "").replace(/\.dll$/i, "").toLowerCase();
    return strip(want) === strip(have);
};

/** The one class `spec` ({namespace, class, assembly?}) names, in the assembly it names or in all. */
export function findClass(api, spec) {
    const images = api.images().filter((i) => sameImage(spec.assembly, i.name));
    if (!images.length) {
        throw new ResolveError("class_not_found", spec.assembly
            ? `no assembly named ${spec.assembly} is loaded`
            : "the runtime reports no assemblies");
    }
    const [top, ...nested] = spec.class.split("/");
    if (nested.length && !api.canNest()) {
        throw new ResolveError("api", `${label(spec)} is a nested class, and the module does not export ` +
            "il2cpp_class_get_nested_types / il2cpp_class_get_name");
    }
    const found = [];
    for (const { name, image } of images) {
        let k = api.classFromName(image, spec.namespace || "", top);
        for (const part of nested) {
            if (!k) break;
            k = api.nestedClass(k, part);
        }
        if (k) found.push({ klass: k, assembly: name });
    }
    const distinct = [...new Map(found.map((f) => [String(f.klass), f])).values()];
    if (!distinct.length) throw new ResolveError("class_not_found", `${label(spec)} is not in any loaded assembly`);
    if (distinct.length > 1) {
        throw new ResolveError("ambiguous", `${label(spec)} exists in ${distinct.map((f) => f.assembly).join(", ")} - ` +
            "name the assembly (`assembly` in the profile's name object)");
    }
    return distinct[0];
}

/** The ONE method `spec` ({namespace, class, method, args, assembly?}) names: {rva, assembly, note?}. */
export function findMethod(api, spec, moduleSize) {
    const { klass, assembly } = findClass(api, spec);
    let info = null;
    let note = null;
    if (api.canEnumerateMethods()) {
        const all = api.methods(klass).filter((m) => m.name === spec.method);
        const hits = spec.args < 0 ? all : all.filter((m) => m.argc === spec.args);
        if (!hits.length) {
            throw new ResolveError("method_not_found", all.length
                ? `${specText(spec)}: the class has ${spec.method} with ${all.map((m) => m.argc).join(", ")} ` +
                  `parameter(s), not ${spec.args}`
                : `${specText(spec)}: no method of that name in the class`);
        }
        if (hits.length > 1) {
            throw new ResolveError("ambiguous", `${specText(spec)}: ${hits.length} overloads answer to it ` +
                `(${hits.map((m) => m.argc).join(", ")} parameters) - add /N for the one you mean`);
        }
        info = hits[0].info;
    } else if (api.canFindMethodByName()) {
        info = api.methodFromName(klass, spec.method, spec.args);
        if (spec.args < 0) note = "the module cannot list methods, so a second overload of this name could not be ruled out";
        if (!info) throw new ResolveError("method_not_found", `${specText(spec)}: no such method`);
    } else {
        throw new ResolveError("api", "the module exports neither il2cpp_class_get_methods nor il2cpp_class_get_method_from_name");
    }
    const rva = api.methodRva(info);
    if (rva === null || rva <= 0) {
        throw new ResolveError("pointer", `${specText(spec)}: the method has no code pointer (abstract, generic, or not compiled)`);
    }
    if (typeof moduleSize === "number" && rva >= moduleSize) {
        throw new ResolveError("pointer", `${specText(spec)}: its pointer is 0x${rva.toString(16)} past the module's base, ` +
            `beyond the module (size 0x${moduleSize.toString(16)}) - the code lives elsewhere`);
    }
    return { rva, assembly, note };
}

// ---------------------------------------------------------------------------------------
// the orchestrator
// ---------------------------------------------------------------------------------------

let report = null;   // what getResolution() returns; replaced by every resolveOffsets()

/**
 * The RVAs the build cache holds for the build `mod` is: `{key: RVA}`, {} for none (an unknown
 * build, an unreadable one, or no cache). An RVA outside the module is not an address of this
 * build whatever the cache says, so it is dropped here rather than hooked.
 */
function cachedOffsets(p, build, mod) {
    if (!build) return {};
    const entry = (p.cache && p.cache.builds && p.cache.builds[buildKey(build)]) || {};
    const known = {};
    for (const [key, rva] of Object.entries(entry)) {
        if (typeof mod.size === "number" && rva >= mod.size) {
            console.log(`[!] ${key}: the build cache says ${hex(rva)}, which is outside this module ` +
                `(${hex(mod.size)} bytes) - ignoring it`);
            continue;
        }
        known[key] = rva;
    }
    return known;
}

const hex = (n) => (typeof n === "number" ? `0x${n.toString(16)}` : String(n));

/** What the last resolveOffsets() found, as plain JSON (rpc.exports.getResolution). */
export function resolutionExport() {
    return report === null ? null : JSON.parse(JSON.stringify(report));
}

/**
 * The layout fields whose offset the runtime was asked for, as `field_offsets` entries for the
 * agent's getHealth(): {record, field, il2cpp_field, layout_offset, runtime_offset, status:
 * "match" | "mismatch" | "unresolved", reason?}. retk/layout_check.py judges them: a mismatch
 * fails the layout check outright (it is not a sample - the runtime says where the field is).
 * Empty when no names.fields were given or the lookup has not run.
 */
export function fieldOffsetsHealth() {
    return report === null ? [] : report.fields.map((f) => ({ ...f }));
}

/** `health` (what healthExport() returned) with `field_offsets` added when there are any. */
export function withFieldOffsets(health) {
    const fields = fieldOffsetsHealth();
    return fields.length && health && typeof health === "object" ? { ...health, field_offsets: fields } : health;
}

function resolveFields(api, p, rep) {
    const want = (p.names && p.names.fields) || {};
    for (const [record, entry] of Object.entries(want)) {
        const known = p.records && p.records[record];
        if (!known) continue;   // a record this agent does not read
        const layout = new Map(known.layout.map((f) => [f.name, f.offset]));
        let klass = null;
        let classError = null;
        try {
            klass = findClass(api, entry).klass;
        } catch (e) {
            classError = e.message;
        }
        if (!klass && !classError) classError = "class not found";
        for (const [layoutField, il2cppField] of Object.entries(entry.map)) {
            if (!layout.has(layoutField)) continue;
            const row = { record, field: layoutField, il2cpp_field: il2cppField, layout_offset: layout.get(layoutField),
                          runtime_offset: null, status: "unresolved" };
            if (classError) {
                row.reason = classError;
            } else if (!api.canReadFields()) {
                row.reason = "the module exports neither il2cpp_class_get_field_from_name nor il2cpp_field_get_offset";
            } else {
                const off = api.fieldOffset(klass, il2cppField);
                if (off === null) {
                    row.reason = `${label(entry)} has no field ${il2cppField}`;
                } else {
                    row.runtime_offset = off;
                    row.status = off === row.layout_offset ? "match" : "mismatch";
                }
            }
            rep.fields.push(row);
            if (row.status === "mismatch") {
                console.log(`[!] layout field ${record}.${layoutField} is at ${hex(row.layout_offset)} in the profile, ` +
                    `but the runtime puts ${label(entry)}.${il2cppField} at ${hex(row.runtime_offset)} - the layout is stale`);
            } else if (row.status === "unresolved") {
                console.log(`[i] could not check ${record}.${layoutField} against the runtime: ${row.reason}`);
            }
        }
    }
    const checked = rep.fields.filter((f) => f.status !== "unresolved").length;
    if (checked) {
        console.log(`[+] ${rep.fields.filter((f) => f.status === "match").length}/${checked} layout field offset(s) ` +
            "confirmed by the IL2CPP runtime");
    }
}

/**
 * Work out the RVA of every key in `keys` and call `onReady({key: rva})` once - with the
 * runtime's answer for a key the profile has a name for, the profile's RVA otherwise (and as
 * the fallback, unless p.resolve is "names"). Never calls `onReady` if a key ends with no
 * address at all; the reason is logged and in resolutionExport().
 *
 * `p` is what parseParams() returned (resolve, offsets, names, records). `hooks.makeApi`
 * replaces createIl2cppApi (tests); `hooks.stage` is the rpc.exports.init stage.
 * `hooks.onRuntime(api)` is called once the runtime is up (after the names and fields were looked up) and
 * `hooks.onUnavailable(why)` if it cannot be asked: for an agent that needs the runtime for more than its
 * hook points (snapshot_records.js) and must not wait for it twice. Either one keeps the lookup going
 * even when there are no names and no fields to resolve.
 */
export function resolveOffsets(mod, p, keys, onReady, hooks = {}) {
    const mode = p.resolve || "auto";
    const names = (p.names && p.names.methods) || {};
    const build = readBuildId(mod);       // {kind, id} or null: which build of the module this is
    const rep = { mode, build, methods: [], fields: [], api: { ready: null, why: null } };
    report = rep;
    const known = mode === "auto" ? cachedOffsets(p, build, mod) : {};

    const entries = new Map();
    for (const key of keys) {
        const spec = mode === "rva" ? undefined : names[key];
        const profileRva = p.offsets[key] || 0;
        entries.set(key, { key, name: spec ? specText(spec) : null, source: null, rva: null,
                           name_rva: null, profile_rva: profileRva || null, cache_rva: known[key] || null,
                           agrees: null, reason: null });
    }
    // A hook point with a cached RVA for this build is not looked up: only the rest is `named`.
    const named = keys.filter((k) => entries.get(k).name && !entries.get(k).cache_rva);
    const wantFields = mode !== "rva" && p.names && p.names.fields && Object.keys(p.names.fields).length > 0;

    let finished = false;
    const finish = () => {
        if (finished) return;     // a throw after the last key must not hook twice
        finished = true;
        const rvas = {};
        let failed = false;
        for (const key of keys) {
            const e = entries.get(key);
            rep.methods.push(e);
            if (e.rva === null) {
                failed = true;
            } else {
                rvas[key] = e.rva;
            }
        }
        if (failed) {
            console.log("[!] nothing was hooked: " + keys.filter((k) => entries.get(k).rva === null).join(", ") +
                " has no address (see above)");
            return;
        }
        onReady(rvas);
    };

    for (const key of keys) {
        const e = entries.get(key);
        if (e.cache_rva) {
            e.source = "cache";
            e.rva = e.cache_rva;
            if (e.profile_rva) e.agrees = e.profile_rva === e.cache_rva;
            console.log(`[+] ${key}: ${hex(e.rva)}, as recorded for this build (${buildKey(build)})` +
                (e.profile_rva && !e.agrees ? ` - the profile's RVA ${hex(e.profile_rva)} is for another build` : ""));
        } else if (!e.name) {
            e.source = "rva";
            e.rva = e.profile_rva;
        }
    }

    const wantRuntime = typeof hooks.onRuntime === "function" || typeof hooks.onUnavailable === "function";
    if (!named.length) {
        // Nothing to look up for the hooks: hook the RVAs now, without waiting for the runtime. Field
        // offsets (if the profile names them) are checked once it is up - they are a check, not a dependency.
        finish();
        if (!wantFields && !wantRuntime) return;
    }

    let api;
    try {
        api = (hooks.makeApi || createIl2cppApi)(mod, (p.names && p.names.exports) || {}, hooks.stage || "early");
    } catch (e) {
        api = null;
        rep.api = { ready: false, why: `the IL2CPP API could not be set up: ${e.message}` };
    }

    const fallBack = (why) => {
        rep.api = { ready: false, why };
        if (hooks.onUnavailable) hooks.onUnavailable(why);
        console.log(`[!] name lookup unavailable: ${why}`);
        for (const key of named) {
            const e = entries.get(key);
            e.reason = why;
            if (mode === "names") {
                e.source = "none";
                console.log(`[!] ${key}: resolve is "names" and the runtime cannot be asked - not hooking`);
            } else if (e.profile_rva) {
                e.source = "rva";
                e.rva = e.profile_rva;
                console.log(`[i] ${key}: falling back to the profile's RVA ${hex(e.rva)}`);
            } else {
                e.source = "none";
                console.log(`[!] ${key}: no RVA in the profile to fall back to`);
            }
        }
        for (const [record, entry] of Object.entries((p.names && p.names.fields) || {})) {
            if (!(p.records && p.records[record])) continue;
            for (const layoutField of Object.keys(entry.map)) {
                const f = (p.records[record].layout.find((x) => x.name === layoutField));
                if (f) rep.fields.push({ record, field: layoutField, il2cpp_field: entry.map[layoutField],
                                         layout_offset: f.offset, runtime_offset: null, status: "unresolved", reason: why });
            }
        }
        finish();
    };

    const resolveNow = () => {
        rep.api = { ready: true, why: null };
        for (const key of named) {
            const e = entries.get(key);
            const spec = names[key];
            try {
                const r = findMethod(api, spec, typeof mod.size === "number" ? mod.size : undefined);
                e.name_rva = r.rva;
                e.source = "name";
                e.rva = r.rva;
                if (r.note) e.reason = r.note;
                if (e.profile_rva) {
                    e.agrees = e.profile_rva === r.rva;
                    if (!e.agrees) {
                        console.log(`[!] ${key}: the profile says ${hex(e.profile_rva)}, but ${e.name} is at ` +
                            `${hex(r.rva)} in this build - hooking the name's address; update the profile's RVA`);
                    }
                }
                console.log(`[+] ${key}: ${e.name} -> ${hex(r.rva)} (${r.assembly || "assembly unknown"}, from the IL2CPP runtime)` +
                    (r.note ? ` - note: ${r.note}` : ""));
            } catch (err) {
                if (!(err instanceof ResolveError)) throw err;
                e.reason = err.message;
                if (mode !== "names" && e.profile_rva) {
                    e.source = "rva";
                    e.rva = e.profile_rva;
                    console.log(`[!] ${key}: ${err.message} - falling back to the profile's RVA ${hex(e.rva)}`);
                } else {
                    e.source = "none";
                    console.log(`[!] ${key}: ${err.message}` + (mode === "names"
                        ? ' - resolve is "names", so there is no fallback' : " - and the profile has no RVA for it"));
                }
            }
        }
        if (wantFields) {
            try {
                resolveFields(api, p, rep);
            } catch (err) {
                console.log(`[!] checking layout field offsets failed: ${err.message}`);
            }
        }
        finish();
        if (hooks.onRuntime) hooks.onRuntime(api);
    };

    if (api === null) {
        fallBack(rep.api.why);
        return;
    }
    api.whenReady(() => {
        try {
            resolveNow();
        } catch (err) {
            fallBack(`the lookup threw: ${err.message}`);
        }
    }, fallBack);
}
