// _lib.js
//
// Shared helpers for the Frida agents in this project. This file is NOT a
// standalone agent — it's imported by the entry-point scripts and bundled
// into dist/ via `npm run build` (frida-compile). See README.md's
// "Building the agents" section before trying to `frida -l` anything in
// scripts/ directly; the raw files here use ES module imports and won't
// load as-is.
//
// No agent contains a real value: no offset, no package id, no field name.
// Each agent exports `init(stage, params)` through rpc.exports, and everything
// target-specific arrives in `params` (see parseParams below) from the
// driver, which reads it from a profile that lives outside git.

import { RESOLVE_MODES } from "./_resolve.js";

/** Where a System.String's length and characters sit; set by parseParams(). */
let stringLayout = null;

/**
 * Read an IL2CPP System.String at `strPtr`. Where its length and characters
 * sit is the profile's `layouts.string` (see docs/MEMORY_LAYOUT.md): an int32
 * length, then UTF-16LE characters, with no gap.
 *
 * MAX_STRING_LEN below is a runaway-read guard, not a real content limit: it
 * only exists to stop a wrong `strPtr` (bad offset, stale pointer, a field
 * misread as a string) from being misread as a string billions of units
 * long and handed to readUtf16String(). A genuine IL2CPP string in the
 * records this project reads should never come close to it - if one does,
 * that's worth checking on its own merits, not a sign the bound needs to
 * grow further.
 */
const MAX_STRING_LEN = 65536; // UTF-16 units (128 KiB of UTF-16LE data)

// What readIl2CppString() returns INSTEAD of a string when the read fails. They
// are values, not exceptions, so one bad string can't abort the rest of a
// record - which is why a caller that wants to know (the layout canary) needs
// isStringReadFailure() rather than a catch.
const READ_ERROR = "<read error";
const BAD_LENGTH = "<unexpected len";

/** True if `s` is one of readIl2CppString()'s failure placeholders rather than a real string. */
export function isStringReadFailure(s) {
    return typeof s === "string" && (s.startsWith(READ_ERROR) || s.startsWith(BAD_LENGTH));
}

/**
 * The key a record carries when some of its string fields could not be read: a
 * list of those fields' names. retk/layouts.py refuses a layout with a field
 * of this name (RESERVED_FIELD_NAMES there; tests/test_unreadable.py checks the
 * two agree), so it can never clash with a real field.
 */
export const UNREADABLE_KEY = "_unreadable";

/**
 * A copy of `rec` that is safe to export: every string field that holds one of
 * readIl2CppString()'s failure placeholders becomes `null`, and the record
 * gains `_unreadable: [names]`. Without it a `"<unexpected len: -1>"` sits in
 * the JSON next to real strings and nobody reading the file can tell it from
 * data. A record with nothing wrong comes back as a plain copy - no
 * `_unreadable` key - so a good dump looks exactly as it always did.
 *
 * `null` alone would not do: a null string pointer is a legitimate value (an
 * unset field) and reads as `null` too. `_unreadable` is what tells the two
 * apart. The canary must be shown the ORIGINAL record, not this one: it counts
 * the placeholders (see _canary.js), and a nulled field has no failure left to
 * count. (One residue: a genuine string that itself begins with "<read error"
 * or "<unexpected len" is indistinguishable from a failure here, as it already
 * is for the canary.)
 *
 * @param {Object<string, any>} rec  what readRecord() returned
 * @returns {Object<string, any>}
 */
export function sealUnreadable(rec) {
    const out = {};
    const bad = [];
    for (const [name, value] of Object.entries(rec)) {
        if (isStringReadFailure(value)) {
            bad.push(name);
            out[name] = null;
        } else {
            out[name] = value;
        }
    }
    if (bad.length) out[UNREADABLE_KEY] = bad;
    return out;
}

// While > 0, readIl2CppString() does not log a rejected length. The layout canary reads fields at
// offsets that are KNOWN to be wrong (it is measuring how far a layout has drifted), and every one of
// those junk "lengths" would otherwise print a line.
let quietDepth = 0;

/** Run `fn()` with readIl2CppString()'s "rejected length" log line switched off; returns what `fn` returns. */
export function quietly(fn) {
    quietDepth++;
    try {
        return fn();
    } finally {
        quietDepth--;
    }
}

export function readIl2CppString(strPtr) {
    if (strPtr.isNull()) return null;
    if (stringLayout === null) throw new Error("readIl2CppString: no string layout - call parseParams() first");
    let len;
    try {
        len = strPtr.add(stringLayout.lengthOffset).readS32();
    } catch (e) {
        return `${READ_ERROR}: ${e.message}>`;
    }
    if (len < 0 || len > MAX_STRING_LEN) {
        if (quietDepth === 0) {
            console.log(`[!] readIl2CppString: rejected length ${len} at ${strPtr} ` +
                `(cap is ${MAX_STRING_LEN} UTF-16 units) - treating as a bad read, not a real string`);
        }
        return `${BAD_LENGTH}: ${len}>`;
    }
    if (len === 0) return "";
    try {
        return strPtr.add(stringLayout.charsOffset).readUtf16String(len);
    } catch (e) {
        return `${READ_ERROR}: ${e.message}>`;
    }
}

/**
 * How each layout field `type` is read at an address. This is the only place
 * that decides what "u32" or "s8" means at runtime, and tests/test_layouts.py
 * decodes every type here against an independent Python decoder, so changing
 * e.g. `u32` to `readS8()` fails a test instead of silently corrupting every
 * dump. Keep the keys equal to TYPES in retk/layouts.py (also tested).
 */
export const FIELD_READERS = {
    u32: (p) => p.readU32(),
    s32: (p) => p.readS32(),
    s8: (p) => p.readS8(),
    string: (p) => readIl2CppString(p.readPointer()),
};

/**
 * Read a record at `base` field by field according to `layout` (a record's
 * `fields` list from the profile's layouts, as returned by parseParams). If
 * `only` is given it must name fields of `layout` and just those are read -
 * trace_lookup.js uses that for its subset. Result keys follow layout (offset)
 * order.
 *
 * Throws if a field's read throws (e.g. an unreadable address), on a
 * `type` FIELD_READERS doesn't know, or if `only` names a field that isn't
 * in `layout` - callers already wrap the read in try/catch.
 *
 * @param {NativePointer} base
 * @param {{name: string, offset: number, type: string}[]} layout
 * @param {string[]} [only]
 * @returns {Object<string, number|string|null>}
 */
export function readRecord(base, layout, only) {
    if (only) {
        const known = new Set(layout.map((f) => f.name));
        const missing = only.filter((n) => !known.has(n));
        if (missing.length) throw new Error(`readRecord: no such field(s): ${missing.join(", ")}`);
    }
    const fields = only ? layout.filter((f) => only.includes(f.name)) : layout;
    const rec = {};
    for (const f of fields) {
        const read = FIELD_READERS[f.type];
        if (!read) throw new Error(`readRecord: unknown field type "${f.type}" (${f.name})`);
        rec[f.name] = read(base.add(f.offset));
    }
    return rec;
}

/**
 * True if Frida module `m` is the one named `moduleName`.
 *
 * `Module.name` is a "canonical name" and may be either the short name
 * (`UnityFramework`) or a full path (`.../UnityFramework.framework/UnityFramework`).
 * Matching only `m.name === moduleName` hangs forever on the path form.
 */
export function moduleMatches(m, moduleName) {
    if (!m || !moduleName) return false;
    if (m.name === moduleName) return true;
    const base = (s) => {
        const parts = String(s || "").split(/[/\\]/);
        return parts[parts.length - 1] || "";
    };
    return base(m.name) === moduleName || base(m.path) === moduleName;
}

/**
 * The library that holds the IL2CPP runtime, by platform: only what the hints below SAY. The
 * agent never picks one of these for itself - the driver hands it `params.module`, chosen from
 * --module / --platform / the profile (retk/profiles.py, resolve_module()) - and parseParams()
 * refuses to run without it. Keep equal to PLATFORM_MODULES and PLATFORM_LABELS in
 * retk/profiles.py (tests/test_module_lookup.py checks).
 */
const RUNTIME_MODULES = { ios: "UnityFramework", android: "libil2cpp.so", windows: "GameAssembly.dll" };
const RUNTIME_LABELS = { ios: "iOS", android: "Android", windows: "Windows" };
const RUNTIME_MODULES_HINT = Object.keys(RUNTIME_MODULES)
    .map((p) => `${RUNTIME_MODULES[p]} on ${RUNTIME_LABELS[p]}`).join(", ");

/** How long waitForModule() waits silently before saying the module still isn't there. */
const MODULE_WAIT_WARN_MS = 20000;

/**
 * Frida's module APIs, behind ONE function. Every question this project asks Frida about
 * modules - is `moduleName` loaded, which loaded modules look like the IL2CPP runtime, tell me
 * when `moduleName` loads - goes through the object this returns, and nothing else in scripts/
 * calls Process.getModuleByName / enumerateModules / attachModuleObserver (or a `Module.` lookup;
 * tests/test_module_lookup.py fails if something does). A Frida whose module API differs
 * therefore means editing this function, and only this function.
 *
 *   find(moduleName)             the loaded Module, or null. The exact name first, then a scan by
 *                                basename: `Module.name` may be the full path (see moduleMatches).
 *   nearRuntime()                names of loaded modules that look like an IL2CPP / Unity runtime
 *                                (for the "wrong module name?" hint); [] when they cannot be listed.
 *   observe(moduleName, onMatch) start watching for `moduleName` to load - `onMatch(module)` runs
 *                                for it - and return the observer, or null when this Frida has no
 *                                module observer.
 */
function fridaModules() {
    const runtimeLike = new RegExp(["il2cpp", "unity",
        ...Object.values(RUNTIME_MODULES).map((n) => n.replace(/^lib/, "").replace(/\.(so|dll)$/i, ""))].join("|"), "i");
    return {
        find(moduleName) {
            try {
                return Process.getModuleByName(moduleName);
            } catch (e) {
                // Not under that exact name - fall through to a basename scan.
            }
            if (typeof Process.enumerateModules !== "function") return null;
            try {
                const list = Process.enumerateModules();
                return list.find((m) => moduleMatches(m, moduleName)) || null;
            } catch (e) {
                return null;
            }
        },
        nearRuntime() {
            try {
                return Process.enumerateModules()
                    .map((m) => m.name)
                    .filter((n) => runtimeLike.test(String(n)))
                    .slice(0, 10);
            } catch (e) {
                return [];
            }
        },
        observe(moduleName, onMatch) {
            if (typeof Process.attachModuleObserver !== "function") return null;
            return Process.attachModuleObserver({
                onAdded(m) {
                    if (moduleMatches(m, moduleName)) onMatch(m);
                },
            });
        },
    };
}

/**
 * Run `onReady(module)` once `moduleName` is loaded in the target process
 * - immediately if it's already loaded when this is called, otherwise via
 * a one-shot module observer that detaches itself after firing.
 *
 * The observer is attached FIRST, then the already-loaded lookup runs.
 * The other way around (lookup, then observer) races: the module can load
 * in the gap and `onAdded` never fires for it, so the agent hangs forever.
 * `onReady` is guarded so a sync `onAdded` for an already-resident module
 * plus the immediate lookup cannot install the same hook twice.
 *
 * Every agent in this project waits on the profile's `module` this way before
 * installing its hooks. The name is the driver's to supply (parseParams refuses
 * to run without one): it is platform-specific - the IL2CPP runtime is
 * `UnityFramework` in an iOS app, `libil2cpp.so` on Android (see RUNTIME_MODULES) - and the
 * record layouts would need re-deriving for another build in any case.
 *
 * A wrong name used to be indistinguishable from "not loaded yet": the agent
 * waits forever and says nothing. So if the module is still missing after
 * MODULE_WAIT_WARN_MS, the agent lists the loaded modules that look like an
 * IL2CPP runtime and says what to set instead.
 *
 * `onReady` is allowed to throw (e.g. `Interceptor.attach` failing because
 * of a bad/misconfigured offset). That is a real error in the hook, not a
 * "wait for it to load" situation, and it must not be swallowed.
 */
export function waitForModule(moduleName, onReady) {
    let done = false;
    let warnTimer = null;
    const fire = (m) => {
        if (done) return;
        done = true;
        if (warnTimer !== null) clearTimeout(warnTimer);
        onReady(m);
    };

    const frida = fridaModules();
    const observer = frida.observe(moduleName, (m) => {
        try { observer.detach(); } catch (e) { /* already detached (or, for a sync call, not assigned yet) */ }
        fire(m);
    });

    const found = frida.find(moduleName);
    if (found) {
        if (observer) {
            try { observer.detach(); } catch (e) { /* already detached */ }
        }
        fire(found);
        return;
    }

    if (observer) {
        console.log(`[i] ${moduleName} not loaded yet - waiting for module observer...`);
        warnTimer = setTimeout(() => {
            if (done) return;
            const near = frida.nearRuntime();
            console.log(`[!] ${moduleName} is still not loaded after ${MODULE_WAIT_WARN_MS / 1000}s. ` +
                (near.length
                    ? `Loaded modules that look like the IL2CPP runtime: ${near.join(", ")} - if one of ` +
                      `those is the right one, set it as \`module\` in your profile (or pass --module).`
                    : `No loaded module looks like the IL2CPP runtime yet. If this is the wrong name for ` +
                      `the platform (${RUNTIME_MODULES_HINT}), set \`module\` ` +
                      `in your profile (or pass --module); otherwise the app may just be slow to start.`));
        }, MODULE_WAIT_WARN_MS);
        // Under Node (the test harness) a pending timer would keep the process alive.
        if (warnTimer && typeof warnTimer.unref === "function") warnTimer.unref();
        return;
    }
    throw new Error(
        `${moduleName} is not loaded, and Process.attachModuleObserver is unavailable. ` +
        `Attach after the module is resident, or upgrade frida-server.`
    );
}

/**
 * True if `retval` - the raw return value Frida's `Interceptor.attach`
 * hands to `onLeave` - means an `...$$unpack` call FAILED.
 *
 * Only the LOW 32 BITS are tested. `retval` wraps the full 64-bit x0, but
 * AArch64 does not define the upper half of x0 when a function returns a
 * 32-bit `int`/`bool`/enum - the callee only has to get w0 right. Testing
 * the whole word would therefore read a genuine "0 = success" as a failure
 * whenever the upper half happens to be dirty, and drop every record. A
 * low-32-bit test is correct for every return type this could plausibly be
 * (int, bool, enum, int32 status code) and for a 64-bit value too, except
 * one whose low half is exactly zero while the high half isn't - for a
 * status code or a null-vs-pointer result that means a pointer sitting on a
 * 4 GiB boundary, which isn't a case worth designing around.
 *
 * STILL AN ASSUMPTION: that 0 means success. Nothing in this project
 * records that as verified (not in docs/MEMORY_LAYOUT.md, not in
 * docs/METHODOLOGY.md), and no register-width test can settle it - it depends
 * on what your build's unpack() actually returns. Confirm it in Ghidra (the
 * function's return type, and the value its success path loads into w0/x0
 * before `ret`) or by watching a hook see both outcomes. If every record
 * shows up as `[skip]`, suspect this first.
 */
export function unpackFailed(retval) {
    return !retval.and(0xffffffff).isNull();
}

/**
 * Returns a function to call from `onLeave` whenever `unpackFailed()` is
 * true, so a failed unpack() is counted and logged instead of being
 * dropped silently - a silent `return;` is indistinguishable from the hook
 * simply never firing, e.g. because of a wrong offset in the profile. `what` is a short label
 * (the record type name) included in the log line so it's clear which
 * hook is skipping when an agent hooks more than one function.
 */
export function createSkipLogger(what) {
    let skipped = 0;
    return function logSkip(retval) {
        skipped++;
        console.log(`[skip] ${what} unpack() returned ${retval} (expected 0 in the low ` +
            `32 bits) - record dropped (total skipped so far: ${skipped})`);
    };
}

/**
 * The shape every "dump the whole table" agent's record store is generic
 * over - `T` is filled in per-agent (see the `TableARecord` typedef in
 * dump_table_a.js, `TableBRecord` in dump_table_b.js). Plain documentation
 * only - this project has no TS/checkJs build step, so nothing enforces
 * these at build time; they're here so a reader (or an editor's JSDoc-aware
 * IntelliSense) can see the record shape without cross-referencing
 * docs/MEMORY_LAYOUT.md by hand.
 *
 * @template T
 * @typedef {Object} RecordStore
 * @property {Map<string|number, T>} records - accumulated records, keyed by
 *   whatever `keyOf` returned for them (the numeric `id` by default)
 * @property {(rec: T) => {key: string|number, isNew: boolean, changed: boolean}} put
 *   - store `rec` under `keyOf(rec)`. `isNew`: that key wasn't present
 *   before. `changed`: the key WAS present but with different contents, i.e.
 *   this write silently replaced a different record - either the server
 *   pushed an update, or `keyOf` isn't unique enough (see createRecordStore)
 * @property {{getCount: () => number, getRecords: () => T[], getUnreadable: () => {key: string|number, fields: string[]}[], clear: () => boolean}} rpcExports
 *   - exposed as `rpc.exports` so the Python drivers in retk/ can pull the
 *   accumulated table over RPC. `getUnreadable()` lists the stored records
 *   that carry `_unreadable` (see sealUnreadable), by key.
 */

/**
 * `params.cache.builds` as plain {"<kind>:<id>": {key: RVA}}, or {} when there is none. A malformed
 * one is refused rather than half-used: the driver builds it (retk/buildcache.py), so a wrong
 * shape is a bug to see, not something to guess around.
 */
function parseBuildCache(cache, isObject) {
    if (cache === undefined || cache === null) return {};
    if (!isObject(cache) || (cache.builds !== undefined && !isObject(cache.builds))) {
        throw new Error("cache must be {builds: {\"<kind>:<id>\": {<offsets key>: <RVA>}}}");
    }
    const builds = {};
    for (const [build, offsets] of Object.entries(cache.builds || {})) {
        if (!isObject(offsets)) throw new Error(`cache.builds[${JSON.stringify(build)}] must map offsets keys to RVAs`);
        builds[build] = {};
        for (const [key, rva] of Object.entries(offsets)) {
            if (!Number.isSafeInteger(rva) || rva <= 0) {
                throw new Error(`cache.builds[${JSON.stringify(build)}].${key} must be a positive integer RVA, got ${JSON.stringify(rva)}`);
            }
            builds[build][key] = rva;
        }
    }
    return builds;
}

/**
 * Turn the `params` an agent receives in rpc.exports.init(stage, params) into
 * what it needs, failing early with a message that says what is missing.
 *
 * `params` comes from the driver (retk dump reads it from a profile)
 * or from `frida -P '<json>'` (`retk profile params NAME` prints
 * it):
 *
 *   { module: "UnityFramework",
 *     offsets: { table_a: <RVA>, ... },
 *     layouts: { string: {lengthOffset, charsOffset},
 *                records: { <Record>: { key: [...], klass?: "constant"|"pointer",
 *                                       fields: [{name, offset, type, expect?}] } },
 *                subsets: { <Subset>: { of: <Record>, fields: [names] } } } }
 *
 * `cache` (optional, retk/buildcache.py makes it): the RVAs an earlier, verified run recorded for
 * particular BUILDS of the module - `{builds: {"<kind>:<id>": {<offsets key>: <RVA>}}}`, a build
 * being named as _buildid.js reads it from the loaded module. resolveOffsets() uses the entry
 * for the build it is actually running in, and nothing else.
 *
 * Two optional extras feed the layout canary (_canary.js): `layouts.headerSize` (the object header the
 * layout assumes, so a measured drift can be reported as a header size) and `check`
 * (`{sample: N, gate: bool}`: how many of the first reads are probed for drift, and whether the agent
 * sends a snapshot to the driver once it has read that many - retk dump's --layout-gate).
 *
 * `want` lists what this agent asks for by name: `offsets` (keys that must be
 * non-zero RVAs - or have a name, see below), `records` and `subsets` (which need
 * `layouts`). Returns
 * `{moduleName, offsets, resolve, names: {methods, fields, exports}, cache: {builds}, headerSize,
 * check: {sample, gate}, records: {name: {layout, keyOf, klass}}, subsets: {name: [fields]}}`
 * (`klass` is the record's header check mode and a layout field may carry an
 * `expect`; both are for _canary.js; `resolve` and `names` are for _resolve.js).
 * An offset of 0 is "not set" and is refused, so a template profile can't
 * silently hook the wrong address - unless the profile names that hook point
 * (`names.methods[key]`) and `resolve` is not "rva": then the runtime is asked for it
 * (_resolve.js), the offset (0 here when the profile has none) is only the fallback, and
 * resolveOffsets() refuses when neither gives an address.
 */
export function parseParams(params, want = {}) {
    const { offsets: wantOffsets = [], records: wantRecords = [], subsets: wantSubsets = [] } = want;
    if (params === null || typeof params !== "object" || Array.isArray(params)) {
        throw new Error("no parameters - run this through retk dump --profile NAME, or " +
            "`frida ... -P \"$(retk profile params NAME)\"`");
    }
    if (typeof params.module !== "string" || !params.module) {
        throw new Error("no `module` in the parameters - set it in your profile: the name of the IL2CPP " +
            `module in the target (${RUNTIME_MODULES_HINT}), or pass --module / --platform`);
    }
    const check = params.check && typeof params.check === "object" ? params.check : {};
    const resolve = params.resolve === undefined || params.resolve === null ? "auto" : params.resolve;
    if (!RESOLVE_MODES.includes(resolve)) {
        throw new Error(`resolve must be one of ${RESOLVE_MODES.join(", ")}, got ${JSON.stringify(resolve)}`);
    }
    const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
    const rawNames = isObject(params.names) ? params.names : {};
    const names = {
        methods: isObject(rawNames.methods) ? rawNames.methods : {},
        fields: isObject(rawNames.fields) ? rawNames.fields : {},
        exports: isObject(rawNames.exports) ? rawNames.exports : {},
    };
    const out = {
        moduleName: params.module, offsets: {}, records: {}, subsets: {}, headerSize: null, resolve, names,
        cache: { builds: parseBuildCache(params.cache, isObject) },
        // sample: null = "use the canary's default"; gate: only an explicit `true` makes the agent send.
        check: { sample: Number.isSafeInteger(check.sample) && check.sample > 0 ? check.sample : null,
                 gate: check.gate === true },
    };

    for (const key of wantOffsets) {
        const v = (params.offsets || {})[key];
        const named = resolve !== "rva" && isObject(names.methods[key]);
        if (named && (v === undefined || v === null || v === 0)) {
            out.offsets[key] = 0;      // no fallback RVA: the name is all there is
            continue;
        }
        if (!Number.isSafeInteger(v) || v <= 0) {
            throw new Error(`offsets.${key} is missing or 0 - set it in your profile ` +
                `(an RVA, Image Base = 0) or pass --offset ${key}=0x...` +
                (resolve === "rva" ? "" : `, or name it in the profile's names.methods.${key}`));
        }
        out.offsets[key] = v;
    }

    if (wantRecords.length || wantSubsets.length) {
        const layouts = params.layouts;
        if (!layouts || !layouts.string) throw new Error("the profile has no `layouts` section");
        const { lengthOffset, charsOffset } = layouts.string;
        if (!Number.isSafeInteger(lengthOffset) || !Number.isSafeInteger(charsOffset)) {
            throw new Error("layouts.string needs integer lengthOffset and charsOffset");
        }
        stringLayout = { lengthOffset, charsOffset };
        if (Number.isSafeInteger(layouts.headerSize) && layouts.headerSize > 0) out.headerSize = layouts.headerSize;
        for (const name of wantRecords) {
            const r = (layouts.records || {})[name];
            if (!r || !Array.isArray(r.fields)) throw new Error(`the profile's layouts define no record "${name}"`);
            out.records[name] = { layout: r.fields, keyOf: keyFromFields(r.key || ["id"]),
                                  klass: r.klass || "constant" };
        }
        for (const name of wantSubsets) {
            const s = (layouts.subsets || {})[name];
            if (!s || !Array.isArray(s.fields)) throw new Error(`the profile's layouts define no subset "${name}"`);
            out.subsets[name] = s.fields;
        }
    }
    return out;
}

/**
 * `rpc.exports.init` for an agent: runs `start(params)` and, if it throws,
 * logs why before rethrowing. The log matters: the Frida CLI ignores an
 * `init` that throws, so without it a misconfigured agent just does nothing.
 * The Python drivers see the rethrown error as an RPC failure and kill the
 * still-suspended app. `start` is called as `start(params, stage)`: `stage` is Frida's
 * "early" (the app was just spawned) or "late" (attached to a running one), which
 * _resolve.js needs to know whether the IL2CPP runtime is up yet.
 */
export function agentInit(start) {
    return function init(stage, params) {
        try {
            start(params, stage);
        } catch (e) {
            console.log(`[!] init failed: ${e.message}`);
            throw e;
        }
    };
}

/**
 * Build a `keyOf` for createRecordStore from a record's `key` list in the
 * profile's layouts (parseParams does this for you). One field name
 * keys on that field's value as is; several are joined with ":" in the given
 * order, e.g. ["kind", "id"] -> "3:77".
 *
 * @param {string[]} fields
 * @returns {(rec: any) => string|number}
 */
export function keyFromFields(fields) {
    if (!Array.isArray(fields) || fields.length === 0) {
        throw new Error("keyFromFields: need at least one field name");
    }
    if (fields.length === 1) {
        const [f] = fields;
        return (rec) => rec[f];
    }
    return (rec) => fields.map((f) => rec[f]).join(":");
}

/**
 * A key -> record `Map`, plus the matching rpc.exports (getCount /
 * getRecords / clear) that every "dump the whole table" agent
 * (dump_table_a.js, dump_table_b.js) exposes so the Python drivers in
 * retk/ can pull the accumulated table over RPC.
 *
 * The key defaults to `rec.id`, which is right whenever `id` is unique
 * across the whole table. If a record ALSO carries a type/category field and
 * `id` is only unique *within* that type, keying on `id` alone makes records
 * of different types overwrite each other and `getCount()` under-report -
 * pass a `keyOf` that includes the discriminator (see keyFromFields below;
 * the profile's `key` list for a record says which fields to use). `put()`
 * reports when a key is re-written with DIFFERENT contents so a bad key
 * shows up in the log instead of as silently missing rows.
 *
 * A record that carries `_unreadable` (sealUnreadable) is also tracked by key,
 * so the driver can name the records that have unreadable fields without
 * knowing which fields identify a record. Storing the same key again replaces
 * the entry: a later clean read of the record clears it.
 *
 * @template T
 * @param {(rec: T) => string|number} [keyOf] - defaults to `rec.id`
 * @returns {RecordStore<T>}
 */
export function createRecordStore(keyOf = (rec) => /** @type {any} */ (rec).id) {
    const records = new Map();
    const unreadable = new Map();   // key -> names of the fields that could not be read
    const put = (rec) => {
        const key = keyOf(rec);
        const prev = records.get(key);
        const isNew = prev === undefined;
        const changed = !isNew && JSON.stringify(prev) !== JSON.stringify(rec);
        records.set(key, rec);
        const bad = /** @type {any} */ (rec)[UNREADABLE_KEY];
        if (Array.isArray(bad) && bad.length) unreadable.set(key, bad.slice());
        else unreadable.delete(key);
        return { key, isNew, changed };
    };
    const rpcExports = {
        getCount: () => records.size,
        getRecords: () => Array.from(records.values()),
        getUnreadable: () => Array.from(unreadable, ([key, fields]) => ({ key, fields })),
        clear: () => {
            records.clear();
            unreadable.clear();
            return true;
        },
    };
    return { records, put, rpcExports };
}
