// _lib.js
//
// Shared helpers for the Frida agents in this project. This file is NOT a
// standalone agent — it's imported by the entry-point scripts and bundled
// into dist/ via `npm run build` (frida-compile). See README.md's
// "Building the agents" section before trying to `frida -l` anything in
// scripts/ directly; the raw files here use ES module imports and won't
// load as-is.

/**
 * Read an IL2CPP System.String at `strPtr`.
 *
 * Layout confirmed experimentally (see docs/MEMORY_LAYOUT.md for the full
 * investigation history):
 *   +0x00 : klass (8 bytes)
 *   +0x08 : length (int32, NOT padded to 8 bytes)
 *   +0x0C : UTF-16LE characters, starting immediately, no gap
 */
export function readIl2CppString(strPtr) {
    if (strPtr.isNull()) return null;
    let len;
    try {
        len = strPtr.add(0x08).readS32();
    } catch (e) {
        return `<read error: ${e.message}>`;
    }
    if (len < 0 || len > 512) return `<unexpected len: ${len}>`;
    if (len === 0) return "";
    try {
        return strPtr.add(0x0c).readUtf16String(len);
    } catch (e) {
        return `<read error: ${e.message}>`;
    }
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
 */
export function waitForModule(moduleName, onReady) {
    try {
        const mod = Process.getModuleByName(moduleName);
        onReady(mod);
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
    }
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
 * @property {Map<number, T>} records - accumulated records, keyed by their numeric id
 * @property {{getCount: () => number, getRecords: () => T[], clear: () => boolean}} rpcExports
 *   - exposed as `rpc.exports` so the Python drivers in tools/ can pull the
 *   accumulated table over RPC (see tools/records.py for the Python-side
 *   mirror of each per-agent T)
 */

/**
 * An id -> record `Map`, plus the matching rpc.exports (getCount /
 * getRecords / clear) that every "dump the whole table" agent
 * (dump_hd_quality_list.js, dump_recommend_config.js) exposes so the
 * Python drivers in tools/ can pull the accumulated table over RPC.
 *
 * @template T
 * @returns {RecordStore<T>}
 */
export function createRecordStore() {
    const records = new Map();
    const rpcExports = {
        getCount: () => records.size,
        getRecords: () => Array.from(records.values()),
        clear: () => {
            records.clear();
            return true;
        },
    };
    return { records, rpcExports };
}
