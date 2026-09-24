// _lib.js
//
// Shared helpers for the Frida agents in this project. This file is NOT a
// standalone agent — it's imported by the entry-point scripts and bundled
// into dist/ via `npm run build` (frida-compile). See README.md's
// "Building the agents" section before trying to `frida -l` anything in
// scripts/ directly; the raw files here use ES module imports and won't
// load as-is.

import { Il2CppStringLayout } from "./_layouts.js";

/**
 * Read an IL2CPP System.String at `strPtr`. Where its length and characters
 * sit is Il2CppStringLayout (generated from schema/layouts.json, see
 * docs/MEMORY_LAYOUT.md for how it was worked out): an int32 length, then
 * UTF-16LE characters, with no gap.
 */
export function readIl2CppString(strPtr) {
    if (strPtr.isNull()) return null;
    let len;
    try {
        len = strPtr.add(Il2CppStringLayout.lengthOffset).readS32();
    } catch (e) {
        return `<read error: ${e.message}>`;
    }
    if (len < 0 || len > 512) return `<unexpected len: ${len}>`;
    if (len === 0) return "";
    try {
        return strPtr.add(Il2CppStringLayout.charsOffset).readUtf16String(len);
    } catch (e) {
        return `<read error: ${e.message}>`;
    }
}

/**
 * How each schema field `type` (schema/layouts.json) is read at an address.
 * This is the only place that decides what "u32" or "s8" means at runtime,
 * and tests/test_layouts.py decodes every type here against an independent
 * Python decoder, so changing e.g. `u32` to `readS8()` fails a test instead
 * of silently corrupting every dump. Keep the keys equal to TYPES in
 * tools/gen_layouts.py (also tested).
 */
export const FIELD_READERS = {
    u32: (p) => p.readU32(),
    s32: (p) => p.readS32(),
    s8: (p) => p.readS8(),
    string: (p) => readIl2CppString(p.readPointer()),
};

/**
 * Read a record at `base` field by field according to `layout` (one of the
 * `*Layout` tables in _layouts.js). If `only` is given it must name fields of
 * `layout` and just those are read - dump_selection_logic.js uses that for
 * its 5-field subset. Result keys follow layout (offset) order.
 *
 * Throws if a field's read throws (e.g. an unreadable address), on a
 * `type` FIELD_READERS doesn't know, or if `only` names a field that isn't
 * in `layout` - callers already wrap the read in try/catch.
 *
 * @param {NativePointer} base
 * @param {import("./_layouts.js").FieldSpec[]} layout
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
 * Run `onReady(module)` once `moduleName` is loaded in the target process
 * - immediately if it's already loaded when this is called, otherwise via
 * a one-shot module observer that detaches itself after firing.
 *
 * Every agent in this project waits on "UnityFramework" this way before
 * installing its hooks. That name is iOS-specific — this whole template
 * was derived from an iOS investigation and hasn't been tried on Android
 * (see README.md); on Android you'd wait on "libil2cpp.so" instead, and
 * the record layouts below would need re-deriving for that build too.
 *
 * Only the *lookup* (`Process.getModuleByName`) is what "not loaded yet"
 * actually means, so only that call is wrapped in try/catch. `onReady`
 * runs outside it deliberately: if the module IS already loaded but
 * `onReady` itself throws (e.g. `Interceptor.attach` failing because of a
 * bad/misconfigured offset), that's a real error in the hook, not a
 * "wait for it to load" situation - `attachModuleObserver`'s `onAdded`
 * only fires for modules loaded *after* the observer is attached, so
 * treating that error as "not loaded yet" would silently swallow it and
 * hang forever waiting on an observer that can never fire, since the
 * module is already resident.
 */
export function waitForModule(moduleName, onReady) {
    let mod;
    try {
        mod = Process.getModuleByName(moduleName);
    } catch (e) {
        console.log(`[i] ${moduleName} not loaded yet - waiting for module observer...`);
        const observer = Process.attachModuleObserver({
            onAdded(m) {
                if (m.name === moduleName) {
                    observer.detach();
                    onReady(m);
                }
            },
        });
        return;
    }
    onReady(mod);
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
 * records that as verified (not in docs/MEMORY_LAYOUT.md, not in the
 * iteration history), and no register-width test can settle it - it depends
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
 * simply never firing, e.g. because of a wrong FRIDA_OFFSET. `what` is a short label
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
 * over - `T` is filled in per-agent (see the `DeviceQualityRecord` typedef
 * in dump_hd_quality_list.js, `RecommendConfigRecord` in
 * dump_recommend_config.js). Plain documentation only - this project has no
 * TS/checkJs build step, so nothing enforces these at build time; they're
 * here so a reader (or an editor's JSDoc-aware IntelliSense) can see the
 * record shape without cross-referencing docs/MEMORY_LAYOUT.md by hand.
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
 * @property {{getCount: () => number, getRecords: () => T[], clear: () => boolean}} rpcExports
 *   - exposed as `rpc.exports` so the Python drivers in tools/ can pull the
 *   accumulated table over RPC (see tools/records.py for the Python-side
 *   mirror of each per-agent T)
 */

/**
 * A key -> record `Map`, plus the matching rpc.exports (getCount /
 * getRecords / clear) that every "dump the whole table" agent
 * (dump_hd_quality_list.js, dump_recommend_config.js) exposes so the
 * Python drivers in tools/ can pull the accumulated table over RPC.
 *
 * The key defaults to `rec.id`, which is right whenever `id` is unique
 * across the whole table (DeviceQualityAllowList has no other
 * discriminator). If a record ALSO carries a type/category field and `id`
 * is only unique *within* that type, keying on `id` alone makes records of
 * different types overwrite each other and `getCount()` under-report -
 * pass a `keyOf` that includes the discriminator (DeviceRecommendConfig
 * uses `${type}:${id}`). `put()` reports when a key is re-written with
 * DIFFERENT contents so a bad key shows up in the log instead of as
 * silently missing rows.
 *
 * @template T
 * @param {(rec: T) => string|number} [keyOf] - defaults to `rec.id`
 * @returns {RecordStore<T>}
 */
export function createRecordStore(keyOf = (rec) => /** @type {any} */ (rec).id) {
    const records = new Map();
    const put = (rec) => {
        const key = keyOf(rec);
        const prev = records.get(key);
        const isNew = prev === undefined;
        const changed = !isNew && JSON.stringify(prev) !== JSON.stringify(rec);
        records.set(key, rec);
        return { key, isNew, changed };
    };
    const rpcExports = {
        getCount: () => records.size,
        getRecords: () => Array.from(records.values()),
        clear: () => {
            records.clear();
            return true;
        },
    };
    return { records, put, rpcExports };
}
