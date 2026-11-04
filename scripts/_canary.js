// _canary.js
//
// A runtime self-check for a record layout. NOT a standalone agent: imported by
// the dump agents and bundled into dist/ by `npm run build`, like _lib.js.
//
// Why it exists. A layout (where each field of a record sits, how it is read)
// is found by reading memory and looking at it, and nothing ever tests it
// against the build it is later run on. When a build moves a field, or the
// object header turns out not to be what the layout assumed, readRecord() still
// "works": it reads the wrong bytes at the right addresses and the agent dumps
// plausible-looking garbage without a word. The canary is the word.
//
// What it checks, on every record the agent reads:
//
//   the class word   the pointer at +0 must be a real, aligned, mapped address -
//                    and, for a table of one class (`klass: "constant"`, the
//                    default), the SAME one in every record. If `args[0]` isn't
//                    the object the layout describes, or the header isn't what
//                    the layout assumed, this is the first thing to go.
//   strings          a string field must be null or a readable string without
//                    control characters or broken surrogates; a wrong length
//                    offset or a field that isn't a string pointer shows up
//                    here (readIl2CppString's failure placeholders count).
//   `expect`         whatever the profile claims about a field's values - one
//                    of 0/1, at least 1, non-empty, at most 64 characters. This
//                    is the part only the person who read the data can supply,
//                    and the part that catches a misplaced numeric offset.
//   read errors      a record whose read throws (an unmapped address).
//   key conflicts    the same key re-sent with different contents: with a wrong
//                    `key` (or a wrong offset under it) nearly every record
//                    "conflicts".
//   drift            (the first `sample` records only) where the fields WOULD
//                    be if the whole layout had moved. Each record is also read
//                    with every offset shifted by -32..+32 bytes in steps of 8,
//                    and what is counted per shift is how many field reads look
//                    like data (a string that is readable, a value that keeps
//                    its `expect`) and how many do not. A build that grew or
//                    shrank the object header moves EVERY field by the same
//                    amount, so when the declared offsets fail and exactly one
//                    shift fits, the layout is not just "wrong": it has moved,
//                    and by how much is the header's new size. This is the
//                    "measured header size"; retk/layout_check.py turns the
//                    counts into the verdict and the wording.
//
// The agent can also `send` the canary's state to the driver once it has seen
// `sample` records (`gate`), so the driver can judge the first N records and
// stop at once instead of after the player has spent minutes feeding it garbage.
//
// The agent only COUNTS (observe() never throws, and never slows the hook
// noticeably); the verdict - how many violations are too many - is made by
// retk/layout_check.py from getHealth(), so it is tested without a device and
// its tolerance is a command-line flag. The first violation of each kind is
// also logged as it happens, for anyone running the agent under plain `frida`.
//
// What it cannot see: a layout that is wrong in a way that keeps every value
// plausible (two u32 fields swapped that both hold small numbers), and anything
// in a field with no `expect` beyond the structural checks above. It narrows
// "silent garbage" to "garbage that happens to look right"; it does not prove a
// layout correct. The drift measurement needs a field that says something at the
// right place - a string, or a number with an `expect` - and finds only a
// UNIFORM shift: one field that moved on its own is reported as a failure, not
// explained.

import { isStringReadFailure, FIELD_READERS, quietly } from "./_lib.js";

/** How many of the first reads are probed for drift (and, with `gate`, when the snapshot is sent). */
export const DEFAULT_SAMPLE = 16;
const SHIFT_STEP = 8;            // a header changes by whole pointers; a layout shift by 4 is a field, not the header
const MAX_SHIFT = 32;            // probed: -32 .. +32

const MAX_EXAMPLES = 3;          // violations kept per field, for the report
const MAX_DISTINCT = 32;         // distinct values tracked per field
const MAX_VALUES_SHOWN = 8;      // list a field's observed values only when there are this few
const MAX_KLASS_VARIANTS = 8;    // distinct class words tracked

/** A UTF-16 unit as U+XXXX, for messages. */
const unit = (c) => "U+" + c.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0");

/**
 * Why `value` breaks a field's `expect`, or null if it doesn't (or there is no
 * `expect`). `value` is what readRecord() returned: a number, or - for a
 * `string` field - null (a null pointer) or a string.
 */
export function checkExpect(value, expect) {
    if (!expect) return null;
    if (typeof value === "number") {
        if (Array.isArray(expect.oneOf) && !expect.oneOf.includes(value)) {
            return `${value} is not one of ${expect.oneOf.join(", ")}`;
        }
        if (typeof expect.min === "number" && value < expect.min) return `${value} is below min ${expect.min}`;
        if (typeof expect.max === "number" && value > expect.max) return `${value} is above max ${expect.max}`;
        return null;
    }
    if (expect.nonEmpty && (value === null || value === "")) {
        return value === null ? "null pointer, expected a string" : "empty string, expected a non-empty one";
    }
    if (typeof expect.maxLength === "number" && typeof value === "string" && value.length > expect.maxLength) {
        return `length ${value.length} is above maxLength ${expect.maxLength}`;
    }
    return null;
}

/**
 * Why `s` doesn't look like a real string, or null if it does. A null pointer is
 * not a problem here (a field may legitimately be unset); `expect.nonEmpty` is
 * how a profile says it may not be.
 */
export function stringProblem(s) {
    if (s === null) return null;
    if (isStringReadFailure(s)) return `unreadable (${s})`;
    // One UTF-16 unit at a time; two single-unit strings compare by code unit.
    for (let i = 0; i < s.length; i++) {
        const c = s.charAt(i);
        if (c < " " && c !== "\t" && c !== "\n" && c !== "\r") return `control character ${unit(c)} at index ${i}`;
        if (c === "\uFFFD") return `replacement character ${unit(c)} at index ${i}`;
        if (c >= "\uD800" && c <= "\uDBFF") {
            const next = s.charAt(i + 1);
            if (!(next >= "\uDC00" && next <= "\uDFFF")) return `unpaired surrogate ${unit(c)} at index ${i}`;
            i++;
        } else if (c >= "\uDC00" && c <= "\uDFFF") {
            return `unpaired surrogate ${unit(c)} at index ${i}`;
        }
    }
    return null;
}

/**
 * Why a record read at an address that was only GUESSED to be one - a heap-scan candidate (_snapshot.js) -
 * is not one: the problems `rec` (what readRecord() returned) has against `layout`, each as "field: why".
 * Empty means it fits everything the layout can say: no string field unreadable or junk, no `expect`
 * broken. A layout without `expect`s cannot reject anything but unreadable strings, which is why the
 * agent that uses this says how many it rejected and how few checks stood behind that.
 */
export function recordProblems(layout, rec) {
    const out = [];
    for (const f of layout) {
        if (!(f.name in rec)) continue;
        const value = rec[f.name];
        const why = (f.type === "string" ? stringProblem(value) : null) || checkExpect(value, f.expect || null);
        if (why) out.push(`${f.name}: ${why}`);
    }
    return out;
}

/**
 * A canary for one record type.
 *
 * @param {string} record   the record's name in the profile (for messages)
 * @param {{name: string, offset: number, type: string, expect?: object}[]} layout  the record's fields
 * @param {{klass?: "constant"|"pointer", headerSize?: number|null, sample?: number, gate?: boolean}} [options]
 *   `headerSize`: the object header the layout assumes (reported next to the measured one).
 *   `sample`: how many of the first reads are probed for drift (0 turns the probe off).
 *   `gate`: `send()` the canary's state to the driver once `sample` reads have been seen.
 */
export function createCanary(record, layout, options = {}) {
    const { klass = "constant", headerSize = null, gate = false } = options;
    const sample = Number.isSafeInteger(options.sample) && options.sample >= 0 ? options.sample : DEFAULT_SAMPLE;
    const k = { mode: klass, checked: 0, badPointer: 0, variants: new Map(), other: 0 };
    const fields = new Map();
    for (const f of layout) {
        fields.set(f.name, {
            type: f.type, expect: f.expect || null, checked: 0, violations: 0, bad: 0, nulls: 0,
            examples: [], min: null, max: null, distinct: new Set(), capped: false,
        });
    }
    let calls = 0;
    let readErrors = 0;
    let keyConflicts = 0;
    let internalErrors = 0;
    const warned = new Set();

    // Drift probe: one tally per shift. reads = field reads attempted; good / bad = the reads that
    // were evidence one way or the other (the rest - null strings, zeros, fields with no `expect` -
    // say nothing, which is exactly why a shift that lands in zeroed memory can never "fit").
    const shifts = [];
    for (let s = -MAX_SHIFT; s <= MAX_SHIFT; s += SHIFT_STEP) shifts.push({ shift: s, reads: 0, bad: 0, good: 0 });
    let probed = 0;      // records probed so far
    let seen = 0;        // reads attempted so far (successful or not), for the gate
    let gateSent = false;

    /** What reading `f` at `value` says: "bad", "good" or "neutral" (nothing either way). */
    function evidence(f, value) {
        if (f.type === "string") {
            if (stringProblem(value) || checkExpect(value, f.expect)) return "bad";
            return value === null ? "neutral" : "good";
        }
        if (checkExpect(value, f.expect)) return "bad";
        return f.expect && value !== 0 ? "good" : "neutral";
    }

    function probe(base) {
        for (const t of shifts) {
            for (const f of layout) {
                const at = f.offset + t.shift;
                if (at < 0) continue;                                  // in front of the object
                t.reads++;
                let value;
                try {
                    value = quietly(() => FIELD_READERS[f.type](base.add(at)));
                } catch (e) {
                    t.bad++;                                           // unmapped: this shift is not it
                    continue;
                }
                const e = evidence({ type: f.type, expect: f.expect || null }, value);
                if (e === "bad") t.bad++;
                else if (e === "good") t.good++;
            }
        }
        probed++;
    }

    /** At the `sample`-th read: hand the driver the state so far (see the module comment). */
    function maybeSend() {
        seen++;
        if (!gate || gateSent || sample === 0 || seen < sample) return;
        gateSent = true;
        if (typeof send === "function") send({ type: "layout-sample", sample, health: healthExport(api) });
    }

    /** Log the first violation of each kind, then stay quiet - the counts carry the rest. */
    function warn(kind, message) {
        if (warned.has(kind)) return;
        warned.add(kind);
        console.log(`[!] layout check ${record}: ${message} (counting further ones silently)`);
    }

    function checkKlass(base) {
        let word;
        try {
            word = base.readPointer();
        } catch (e) {
            k.badPointer++;
            warn("klass", `cannot read the class word at +0 of ${base}: ${e.message}`);
            return;
        }
        k.checked++;
        let valid = !word.isNull() && word.and(7).isNull();
        if (valid && typeof Process.findRangeByAddress === "function") {
            try {
                valid = Process.findRangeByAddress(word) !== null;
            } catch (e) {
                // Can't tell - leave it at "looks like a pointer".
            }
        }
        if (!valid) {
            k.badPointer++;
            warn("klass", `the word at +0 is ${word}, which is not a valid class pointer - is args[0] the object ` +
                `the layout describes, and is the header what the layout assumed?`);
        }
        const id = word.toString();
        if (k.variants.has(id)) k.variants.set(id, k.variants.get(id) + 1);
        else if (k.variants.size < MAX_KLASS_VARIANTS) k.variants.set(id, 1);
        else k.other++;
    }

    function checkField(name, f, value) {
        f.checked++;
        if (typeof value === "number") {
            f.min = f.min === null ? value : Math.min(f.min, value);
            f.max = f.max === null ? value : Math.max(f.max, value);
        }
        if (!f.capped) {
            f.distinct.add(value);
            if (f.distinct.size > MAX_DISTINCT) f.capped = true;
        }

        let why = null;
        if (f.type === "string") {
            if (value === null) f.nulls++;
            why = stringProblem(value);
            if (why) {
                f.bad++;
                warn(`string:${name}`, `${name}: ${why}`);
                if (f.examples.length < MAX_EXAMPLES) f.examples.push(why);
                return;                                   // a failed read has no values to check
            }
        }
        why = checkExpect(value, f.expect);
        if (why) {
            f.violations++;
            warn(`expect:${name}`, `${name}: ${why}`);
            if (f.examples.length < MAX_EXAMPLES) f.examples.push(why);
        }
    }

    const api = {
        /**
         * Record one successful read. `base` is the record's address, `rec` what
         * readRecord() returned for it, `keyConflict` whether put() found the
         * same key already holding different contents. Never throws.
         */
        observe(base, rec, keyConflict = false) {
            try {
                calls++;
                if (keyConflict) keyConflicts++;
                checkKlass(base);
                for (const [name, f] of fields) {
                    if (name in rec) checkField(name, f, rec[name]);
                }
                if (probed < sample) probe(base);
            } catch (e) {
                internalErrors++;
            }
            try {
                maybeSend();
            } catch (e) {
                internalErrors++;
            }
        },

        /** Record a read that threw (e.g. an access violation): a wrong offset often lands in unmapped memory. */
        readFailed(error) {
            readErrors++;
            warn("read", `a record could not be read: ${error && error.message}`);
            try {
                maybeSend();
            } catch (e) {
                internalErrors++;
            }
        },

        /** Everything counted so far, as plain JSON (what getHealth() returns). */
        health() {
            const outFields = {};
            for (const [name, f] of fields) {
                const entry = {
                    type: f.type, checked: f.checked, violations: f.violations, bad: f.bad, nulls: f.nulls,
                    has_expect: f.expect !== null, examples: f.examples.slice(),
                    distinct: f.capped ? null : f.distinct.size,
                };
                if (f.type !== "string") {
                    entry.min = f.min;
                    entry.max = f.max;
                    if (!f.capped && f.distinct.size <= MAX_VALUES_SHOWN) {
                        entry.values = Array.from(f.distinct).sort((a, b) => a - b);
                    }
                }
                outFields[name] = entry;
            }
            return {
                record,
                calls,
                read_errors: readErrors,
                key_conflicts: keyConflicts,
                internal_errors: internalErrors,
                klass: {
                    mode: k.mode, checked: k.checked, bad_pointer: k.badPointer, other: k.other,
                    variants: Array.from(k.variants.entries()).sort((a, b) => b[1] - a[1]),
                },
                fields: outFields,
                drift: sample === 0 ? null : {
                    header_size: headerSize, step: SHIFT_STEP, sample, probed,
                    shifts: shifts.map((t) => ({ shift: t.shift, reads: t.reads, bad: t.bad, good: t.good })),
                },
            };
        },
    };
    return api;
}

/**
 * The `getHealth` rpc export for an agent: `rpc.exports = { ..., getHealth: () => healthExport(canary) }`.
 * Canaries that don't exist yet (init hasn't run) are skipped, so the call is
 * safe at any point.
 */
export function healthExport(...canaries) {
    return { version: 1, records: canaries.filter(Boolean).map((c) => c.health()) };
}
