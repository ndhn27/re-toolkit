// _snapshot.js
//
// Read a table out of a RUNNING app, without hooking anything and without waiting for the app to unpack
// it again - what an attach that comes too late for the unpack call needs. Shared by snapshot_records.js;
// not an agent itself. Bundled into dist/ by `npm run build` like _lib.js.
//
// Two ways to find the records, either or both named by the profile (`names.snapshot.<Record>`):
//
//   static   A STATIC FIELD that holds the table - an array, a System.Collections.Generic.List<T>, or one
//            record - read through the IL2CPP API (class -> il2cpp_field_static_get_value). The pointers are
//            exact, so the records are taken as they are and every one is shown to the layout canary: a
//            layout that no longer fits is reported by the layout check like any dump, not filtered away.
//            Dictionaries are not walked (their entry layout depends on the key type).
//   heap     LIVE INSTANCES of a class: the heap is scanned for the class pointer at +0 of an object (the
//            word the layout canary already checks). That finds every object of the class that has not been
//            collected yet - reachable or not - and some memory that merely holds the class pointer (a table
//            of classes, an array of them). Each candidate is therefore read against the layout and kept only
//            if it breaks none of its checks (no unreadable string, no `expect` violated); a layout with few
//            `expect`s rejects little, and the status says how many candidates there were and how many fit.
//
// `static` is tried first, `heap` when it is absent, unresolved or empty.
//
// Nothing here calls into the app's own code except the IL2CPP API functions of _resolve.js - with one
// caveat: il2cpp_field_static_get_value may initialise the class first (run its type initializer) if the
// app has not used it yet. Attach after the table has been built and that never happens.
//
// The memory work (ranges, scanning) goes through an `io` object so tests/test_snapshot_agent.py can run
// the logic under Node against a made-up image; makeIo() is the Frida binding.

import { readRecord, sealUnreadable, quietly } from "./_lib.js";
import { recordProblems } from "./_canary.js";
import { findClass, ResolveError } from "./_resolve.js";

/** What `static.container` may be. Keep equal to SNAPSHOT_CONTAINERS in retk/profiles.py (tested). */
export const CONTAINERS = ["object", "array", "list"];

export const DEFAULT_HEAP_MAX = 100000;      // candidates kept from a heap scan before it stops
export const DEFAULT_BUDGET_MS = 60000;      // how long a heap scan may take
export const CHUNK_BYTES = 16 * 1024 * 1024; // scanned at a time, with the event loop given back in between
export const MAX_ELEMENTS = 1000000;         // an array or list longer than this is not a table
const MAX_EXAMPLES = 3;                      // rejected candidates described in the status

const spec = (s) => `${s.namespace ? s.namespace + "." : ""}${s.class}`;

/** The elements of an Il2CppArray of references at `arr` (klass, monitor, bounds, max_length, then the items). */
export function arrayElements(arr, ps = 8, limit = undefined) {
    const length = arr.add(3 * ps).readU32();
    if (length > MAX_ELEMENTS) throw new ResolveError("pointer", `an array of ${length} elements is not a table`);
    const n = limit === undefined ? length : Math.max(0, Math.min(length, limit));
    const items = [];
    let nulls = 0;
    for (let i = 0; i < n; i++) {
        const p = arr.add(4 * ps + i * ps).readPointer();
        if (p.isNull()) nulls++;
        else items.push(p);
    }
    return { items, nulls, length };
}

/**
 * The record pointers a static field holds. `s` is {namespace, class, assembly?, field, container}. Returns
 * {roots: [NativePointer], note}; throws ResolveError for anything that is not settled (no such class or
 * field, the API missing, a value that is not what `container` says it is).
 */
export function staticRoots(api, s, ps = 8) {
    if (!CONTAINERS.includes(s.container)) throw new ResolveError("api", `static.container must be one of ${CONTAINERS.join(", ")}`);
    if (!api.canReadStatic()) {
        throw new ResolveError("api", "the module exports neither il2cpp_class_get_field_from_name nor il2cpp_field_static_get_value");
    }
    const { klass } = findClass(api, s);
    const value = api.staticFieldValue(klass, s.field);
    if (value === null) throw new ResolveError("field_not_found", `${spec(s)} has no field ${s.field}`);
    if (value.isNull()) return { roots: [], note: `${spec(s)}.${s.field} is null: the table has not been built yet` };
    if (s.container === "object") return { roots: [value], note: null };
    if (s.container === "array") {
        const { items, nulls, length } = arrayElements(value, ps);
        return { roots: items, note: nulls ? `${nulls} of ${length} array slots are null` : null };
    }
    // a List<T>: _items (the backing array) and _size (how many of its slots are in use)
    const listClass = value.readPointer();
    const itemsAt = api.fieldOffset(listClass, "_items");
    const sizeAt = api.fieldOffset(listClass, "_size");
    if (itemsAt === null || sizeAt === null) {
        throw new ResolveError("field_not_found", `${spec(s)}.${s.field} is not a List: its class has no _items / _size`);
    }
    const size = value.add(sizeAt).readS32();
    if (size < 0 || size > MAX_ELEMENTS) throw new ResolveError("pointer", `a List of size ${size} is not a table`);
    const backing = value.add(itemsAt).readPointer();
    if (backing.isNull() || size === 0) return { roots: [], note: `${spec(s)}.${s.field} is an empty List` };
    const { items, nulls } = arrayElements(backing, ps, size);
    return { roots: items, note: nulls ? `${nulls} of ${size} list entries are null` : null };
}

/**
 * Scan the heap for `klass` at +0 of an object; `onCandidate(address)` gets every aligned hit. `io`:
 * {pointerSize, ranges(), scan(base, size, pattern), now(), yield()}. Stops at `max` candidates or
 * `budgetMs`, and says so. Returns what was covered.
 */
export async function scanHeap(klass, io, opts, onCandidate) {
    const { max = DEFAULT_HEAP_MAX, budgetMs = DEFAULT_BUDGET_MS } = opts;
    const ps = io.pointerSize || 8;
    const pattern = klass.toMatchPattern();
    const t0 = io.now();
    const out = { candidates: 0, scanned_bytes: 0, ranges: 0, skipped_chunks: 0, truncated: false, timed_out: false };
    for (const range of io.ranges()) {
        out.ranges++;
        for (let off = 0; off < range.size; off += CHUNK_BYTES) {
            if (io.now() - t0 > budgetMs) {
                out.timed_out = true;
                return out;
            }
            const size = Math.min(CHUNK_BYTES, range.size - off);
            let hits;
            try {
                hits = io.scan(range.base.add(off), size, pattern);
            } catch (e) {
                out.skipped_chunks++;          // unmapped while we looked, or a guard page
                continue;
            }
            out.scanned_bytes += size;
            for (const h of hits) {
                if (!h.address.and(ps - 1).isNull()) continue;
                if (out.candidates >= max) {
                    out.truncated = true;
                    return out;
                }
                out.candidates++;
                onCandidate(h.address);
            }
            await io.yield();
        }
    }
    return out;
}

/**
 * The snapshot of one record type. `store` is {put, clear, size} (the agent's record store), `canary` the
 * layout canary (or null), `layout` the record's fields, `want` the profile's `names.snapshot` entry:
 * {record, static?: {namespace, class, assembly?, field, container}, heap?: {namespace, class, assembly?, max?}}.
 *
 * run(api, io) takes the snapshot (once the runtime is up) and resolves to status(): {state: "idle" |
 * "running" | "done" | "failed", record, count, sources: [{source, status, candidates, accepted, rejected,
 * unreadable, ...}], why}.
 */
export function createSnapshot({ layout, store, canary, want, log = console.log }) {
    const st = { state: "idle", record: want.record, count: 0, sources: [], why: null, elapsed_ms: 0 };
    const status = () => JSON.parse(JSON.stringify(st));

    /** Read the record at `ptr` into the store; `strict` = reject what breaks the layout's checks (heap candidates). */
    function accept(ptr, source, strict) {
        let raw;
        try {
            raw = strict ? quietly(() => readRecord(ptr, layout)) : readRecord(ptr, layout);
        } catch (e) {
            if (!strict && canary) canary.readFailed(e);
            source.unreadable++;
            return;
        }
        if (strict) {
            const problems = recordProblems(layout, raw);
            if (problems.length) {
                source.rejected++;
                if (source.examples.length < MAX_EXAMPLES) source.examples.push({ at: ptr.toString(), problems: problems.slice(0, 2) });
                return;
            }
        }
        const { key, changed } = store.put(sealUnreadable(raw));
        if (canary) canary.observe(ptr, raw, changed);
        if (changed) log(`[!] key ${key} found twice in the snapshot with DIFFERENT contents - the later one replaced the earlier`);
        source.accepted++;
    }

    const newSource = (name) => ({ source: name, status: "unavailable", candidates: 0, accepted: 0, rejected: 0,
                                   unreadable: 0, examples: [], why: null });

    function fromStatic(api, io) {
        const src = newSource("static");
        st.sources.push(src);
        try {
            const { roots, note } = staticRoots(api, want.static, io.pointerSize || 8);
            src.note = note;
            for (const ptr of roots) {
                src.candidates++;
                accept(ptr, src, false);
            }
            src.status = src.accepted > 0 ? "ok" : "empty";
            if (src.status === "empty" && !src.why) src.why = note || "the static field held no readable record";
        } catch (e) {
            if (!(e instanceof ResolveError)) throw e;
            src.status = "unavailable";
            src.why = e.message;
        }
        log(`[${src.status === "ok" ? "+" : "!"}] snapshot, static field ${spec(want.static)}.${want.static.field}: ` +
            (src.status === "ok" ? `${src.accepted} record(s)` : src.why));
        return src;
    }

    async function fromHeap(api, io) {
        const src = newSource("heap");
        st.sources.push(src);
        try {
            const { klass } = findClass(api, want.heap);
            const scan = await scanHeap(klass, io, { max: want.heap.max, budgetMs: want.heap.budget_ms },
                                        (addr) => accept(addr, src, true));
            Object.assign(src, { candidates: scan.candidates, scanned_bytes: scan.scanned_bytes, ranges: scan.ranges,
                                 skipped_chunks: scan.skipped_chunks, truncated: scan.truncated, timed_out: scan.timed_out });
            src.status = src.accepted > 0 ? "ok" : "empty";
            if (src.status === "empty") {
                src.why = scan.candidates
                    ? `${scan.candidates} object(s) of ${spec(want.heap)} found, none fits the layout's checks`
                    : `no live object of ${spec(want.heap)} found in ${scan.ranges} range(s)`;
            }
            if (scan.truncated) src.why = `stopped at ${scan.candidates} candidates (names.snapshot.heap.max)`;
            if (scan.timed_out) src.why = "stopped at the time budget before the whole heap was scanned";
        } catch (e) {
            if (!(e instanceof ResolveError)) throw e;
            src.status = "unavailable";
            src.why = e.message;
        }
        log(`[${src.status === "ok" ? "+" : "!"}] snapshot, heap scan for ${spec(want.heap)}: ` +
            (src.status === "ok" ? `${src.accepted} of ${src.candidates} candidate(s) fit the layout, ${src.rejected} rejected`
                                  : src.why));
        return src;
    }

    async function run(api, io) {
        if (st.state === "running") return status();
        Object.assign(st, { state: "running", count: 0, sources: [], why: null, elapsed_ms: 0 });
        store.clear();
        const t0 = io.now();
        try {
            if (want.static) await Promise.resolve(fromStatic(api, io));
            if (want.heap && !(st.sources[0] && st.sources[0].status === "ok")) await fromHeap(api, io);
            st.count = store.size();
            st.state = st.count > 0 ? "done" : "failed";
            if (st.state === "failed") {
                st.why = st.sources.map((s) => `${s.source}: ${s.why || s.status}`).join("; ") || "no source configured";
            }
        } catch (e) {
            st.state = "failed";
            st.why = `the snapshot threw: ${e.message}`;
        }
        st.elapsed_ms = io.now() - t0;
        return status();
    }

    return { run, status, fail(why) { Object.assign(st, { state: "failed", why }); }, wait() { st.state = "waiting"; } };
}

/** The Frida binding of `io`: private rw- memory (file-backed ranges are code and data of modules, not heap). */
export function makeIo() {
    return {
        pointerSize: Process.pointerSize,
        ranges: () => Process.enumerateRanges({ protection: "rw-", coalesce: true }).filter((r) => !r.file),
        scan: (base, size, pattern) => Memory.scanSync(base, size, pattern),
        now: () => Date.now(),
        yield: () => new Promise((resolve) => setTimeout(resolve, 0)),
    };
}
