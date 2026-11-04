"""
diff_records.py

Compares two exports of run_dump.py - the same table dumped from two builds - at the level
of RECORDS, not lines: which records were added, which were removed, which changed and
how (field by field) - and whether the two dumps still have the same SHAPE, because a dump
whose layout no longer fits its build is not a table that changed, it is a table that is
no longer being read. A text diff of two records.json files answers neither.

    retk diff records_old.json records_new.json
    retk diff records_old.json records_new.json --profile myapp --record TableARecord
    retk diff records_old.json records_new.json --key kind,id --json diff_records_1.json

What identifies a record (the KEY) is, in order: --key f1,f2; the profile's layout (`key` of the
record named by --record, or the only one whose fields match the dumps); else a field - or pair of
fields - that is unique in both files and shared by the most records (it says so: "inferred").
A key that does not identify a record is reported, never silently diffed: duplicates keep the
last record, as the agents' store does, and are listed under `problems`.

RECORDS. Matched by key, compared field by field. A field a record could not READ (`_unreadable`
in the export, which the agents write as `null`) is never a change: it is listed as inconclusive,
because "the string became unreadable" is a statement about memory, not about the table.
`--ignore f1,f2` leaves volatile fields out.

SCHEMA DRIFT. The findings that say the two dumps are not comparable as tables - the exit status
is 3, like a failed layout check, and the record diff above is then to be read with suspicion:

    field_removed / field_added   the records do not have the same fields (a layout changed between dumps)
    type_changed                  a field's values changed kind (number / string / bool / list / object)
    null_rate                     a field became (or stopped being) mostly null
    garbled_strings               strings turned into non-printable junk - the usual look of a wrong offset
    domain_shift                  a field with a few distinct values now holds mostly other ones
    field_moved                   the values the old dump had in field A are now in field B: columns swapped,
                                  or a layout shifted by a field
    all_fields_changed            every field changed in nearly every shared record: a shifted layout, or a
                                  different table (a LAYOUT CHECK that failed is the same thing from the inside)
    suspect_dump                  a dump's own `meta` says its layout check failed, or the layout gate stopped it

and these, which are only worth a look (status stays 1 or 0):

    systematic_change             one field changed in nearly every shared record
    magnitude_shift               a numeric field's typical size changed by 100x or more
    new_values                    a field with few distinct values has values the old dump never had
    count_shift / low_key_overlap the table changed size by half or more / the two dumps barely share keys

The thresholds are constants below, with what they mean; tests/test_diff_records.py pins them.

--json PATH writes the whole report (every record of every category). It holds real data and the
`meta` of both dumps: keep it out of git - `diff_records*.json` is ignored by this repo's .gitignore.

Exit status: 0 the dumps hold the same records, 1 they differ but have the same shape, 3 schema drift,
2 for bad input (unreadable file, no usable key, ...).

Usage:
    retk diff OLD.json NEW.json [--key F1,F2 | --profile NAME [--record NAME]]
                           [--ignore F1,F2] [--limit N] [--json PATH]
"""
import argparse
import json
import sys
from collections import Counter
from itertools import combinations

from . import layout_check
REPORT_VERSION = 1
EXIT_SAME, EXIT_DIFFERENT, EXIT_USAGE, EXIT_DRIFT = 0, 1, 2, 3

# --- thresholds ------------------------------------------------------------------------------
MIN_SHARED = 5                # fewer shared records than this and a ratio says nothing: no ratio finding is made
MOVED_RATIO = 0.8             # field_moved: old A == new B in at least this share of shared records...
MOVED_DEST_CHANGED = 0.5      # ...and B itself changed in at least this share (else A was just a copy of B)
SYSTEMATIC_RATIO = 0.9        # systematic_change / all_fields_changed: changed in at least this share
NULL_RATE_JUMP = 0.5          # null_rate: the share of nulls moved by at least this much
GARBLED_JUMP = 0.3            # garbled_strings: the share of non-printable strings moved up by this much
ENUM_MAX_DISTINCT = 16        # "a field with few distinct values": at most this many in the old dump...
ENUM_MIN_RECORDS = 4          # ...over at least this many records
DOMAIN_SHIFT_SHARE = 0.5      # domain_shift: this share of new values is outside the old domain
MAGNITUDE_FACTOR = 100        # magnitude_shift: median |value| changed by this factor
COUNT_SHIFT = 0.5             # count_shift: the table grew or shrank by this share
LOW_OVERLAP = 0.3             # low_key_overlap: shared keys / the larger dump
DISTINCT_CAP = 1000           # distinct values tracked per field
KEY_FIELDS_TRIED = 8          # inferring a key looks at pairs among the first this-many fields

UNREADABLE = "_unreadable"
BREAKING, WARNING, INFO = "breaking", "warning", "info"


class DiffError(ValueError):
    """Input the diff cannot be made from (reported on one line, exit status 2)."""


# --------------------------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------------------------

class Dump:
    """One export of run_dump.py: `records` (list of dicts), `meta` (dict, {} for a bare list)."""

    def __init__(self, path, records, meta):
        self.path, self.records, self.meta = path, records, meta

    @property
    def label(self):
        return str(self.path)

    def fields(self):
        """Data fields, in the order they first appear."""
        seen = {}
        for rec in self.records:
            for name in rec:
                if name != UNREADABLE:
                    seen.setdefault(name, None)
        return list(seen)


def load_dump(path):
    """A `Dump` from the export at `path`: `{"meta": {...}, "records": [...]}` or a bare list."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise DiffError(f"{path}: {e.strerror or e}") from e
    except json.JSONDecodeError as e:
        raise DiffError(f"{path}: not valid JSON: {e}") from e
    if isinstance(data, list):
        records, meta = data, {}
    elif isinstance(data, dict) and isinstance(data.get("records"), list):
        records, meta = data["records"], data.get("meta") if isinstance(data.get("meta"), dict) else {}
    else:
        raise DiffError(f"{path}: not a run_dump.py export (expected {{\"meta\": ..., \"records\": [...]}} or a list of records)")
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            raise DiffError(f"{path}: record {i} is {type(rec).__name__}, not an object")
    return Dump(path, records, meta)


# --------------------------------------------------------------------------------------------
# values
# --------------------------------------------------------------------------------------------

def kind(value):
    """The JSON kind of a value, with int and float one `number` (JavaScript has no other)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "list" if isinstance(value, list) else "object"


def same(a, b):
    """Equal as JSON values - and a boolean is not the number 1."""
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    return a == b


def show(value, width=60):
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= width else text[:width - 3] + "..."


def hashable(value):
    """A string that is equal for equal values (1 and 1.0 are, True and 1 are not): a dict key / set member."""
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def unreadable(rec):
    marked = rec.get(UNREADABLE)
    return set(marked) if isinstance(marked, list) else set()


# --------------------------------------------------------------------------------------------
# the key
# --------------------------------------------------------------------------------------------

def key_from_profile(profile, record, old, new):
    """The `key` of a profile's layout record: `record` if given, else the one whose fields are the dumps' fields."""
    from . import profiles
    try:
        loaded = profiles.load(profile)
    except profiles.ProfileError as e:
        raise DiffError(str(e)) from e
    if loaded.layouts is None:
        raise DiffError(f"{profile}: the profile has no layouts, so no key to take from it - pass --key")
    records = loaded.layouts["records"]
    if record is not None:
        if record not in records:
            raise DiffError(f"{profile}: no record {record!r} in its layouts (has: {', '.join(records)})")
        return list(records[record]["key"])
    have = set(old.fields()) | set(new.fields())
    fits = [name for name, rec in records.items() if {f["name"] for f in rec["fields"]} == have]
    if len(fits) == 1:
        return list(records[fits[0]]["key"])
    raise DiffError(f"{profile}: {'several records fit' if fits else 'no record matches'} the dumps' fields "
                    f"({', '.join(sorted(have))}) - name one with --record ({', '.join(records)}) or pass --key")


def _scalar_fields(*dumps):
    """Fields every record of every dump has, with a non-null scalar value, in the first dump's order."""
    common = None
    for dump in dumps:
        names = [n for n in dump.fields()
                 if all(n in r and kind(r[n]) in ("number", "string", "bool") and n not in unreadable(r)
                        for r in dump.records)]
        common = names if common is None else [n for n in common if n in names]
    return common or []


def infer_key(old, new):
    """A field - or pair - unique in both dumps that the most records share, as a list of names."""
    if not old.records or not new.records:
        raise DiffError("a dump has no records, so there is nothing to infer a key from - pass --key")
    names = _scalar_fields(old, new)[:KEY_FIELDS_TRIED]
    best = None
    for size in (1, 2):
        for combo in combinations(names, size):
            keys = []
            for dump in (old, new):
                found = [tuple(hashable(r[n]) for n in combo) for r in dump.records]
                if len(set(found)) != len(found):
                    break
                keys.append(set(found))
            else:
                overlap = len(keys[0] & keys[1])
                if best is None or overlap > best[0]:
                    best = (overlap, list(combo))
        if best is not None:
            return best[1]                                  # the smallest size that works wins
    raise DiffError("no field (or pair of fields) identifies a record in both dumps - pass --key")


def index(dump, key, which, problems):
    """{key tuple: record}; a repeated key keeps the LAST record (the agents' store does the same)."""
    out, seen = {}, Counter()
    for rec in dump.records:
        missing = [k for k in key if k not in rec]
        if missing:
            raise DiffError(f"{dump.label}: a record has no field {', '.join(missing)} (the key is {', '.join(key)})")
        ident = tuple(hashable(rec[k]) for k in key)
        seen[ident] += 1
        out[ident] = rec
    for ident, count in seen.items():
        if count > 1:
            problems.append({"kind": "duplicate_key", "dump": which, "count": count,
                             "key": {k: json.loads(v) for k, v in zip(key, ident)},
                             "detail": f"{count} records in the {which} dump share this key; the last one is compared"})
    return out


# --------------------------------------------------------------------------------------------
# the record diff
# --------------------------------------------------------------------------------------------

def diff_records(old_by, new_by, key, fields, ignore):
    """(added, removed, changed, unchanged_count, inconclusive_count, shared) over the indexed dumps."""
    key_set = set(key)
    added = [new_by[k] for k in new_by if k not in old_by]
    removed = [old_by[k] for k in old_by if k not in new_by]
    changed, unchanged, inconclusive_records = [], 0, 0
    shared = [k for k in old_by if k in new_by]
    for ident in shared:
        o, n = old_by[ident], new_by[ident]
        o_bad, n_bad = unreadable(o), unreadable(n)
        changes, inconclusive = [], []
        for name in fields:
            if name in key_set or name in ignore:
                continue
            if name in o_bad or name in n_bad:
                if not (name in o_bad and name in n_bad):
                    inconclusive.append(name)
                continue
            ov, nv = o.get(name), n.get(name)
            if name not in o or name not in n or not same(ov, nv):
                changes.append({"field": name, "old": ov, "new": nv,
                                **({"missing_in": "old" if name not in o else "new"} if (name not in o) != (name not in n) else {})})
        if changes:
            changed.append({"key": {k: json.loads(v) for k, v in zip(key, ident)}, "changes": changes,
                            "inconclusive": inconclusive})
        else:
            unchanged += 1
        if inconclusive and not changes:
            inconclusive_records += 1
    return added, removed, changed, unchanged, inconclusive_records, shared


# --------------------------------------------------------------------------------------------
# schema drift
# --------------------------------------------------------------------------------------------

def field_stats(dump, name):
    """What the dump's values of `name` look like: counts per kind, numeric spread, distinct set, ..."""
    kinds, distinct, nums, strings, bad_strings, readable = Counter(), set(), [], 0, 0, 0
    for rec in dump.records:
        if name not in rec or name in unreadable(rec):
            continue
        value = rec[name]
        readable += 1
        kinds[kind(value)] += 1
        if kind(value) in ("number", "string", "bool") and len(distinct) < DISTINCT_CAP:
            distinct.add(hashable(value))
        if kind(value) == "number":
            nums.append(abs(value))
        elif kind(value) == "string":
            strings += 1
            if any((not ch.isprintable() and ch not in "\t\n\r") or ch == "\ufffd" for ch in value):
                bad_strings += 1
    non_null = {k: v for k, v in kinds.items() if k != "null"}
    median = sorted(nums)[len(nums) // 2] if nums else None
    return {"n": readable, "dominant": max(non_null, key=non_null.get) if non_null else "null",
            "null_rate": kinds["null"] / readable if readable else 0.0, "distinct": distinct,
            "median_abs": median, "garbled_rate": bad_strings / strings if strings else 0.0, "strings": strings}


def _finding(kind_, severity, detail, field=None, **extra):
    out = {"kind": kind_, "severity": severity, "detail": detail}
    if field is not None:
        out["field"] = field
    out.update(extra)
    return out


def _meta_findings(old, new):
    out = []
    for which, dump in (("old", old), ("new", new)):
        meta = dump.meta
        check = meta.get("layout_check") if isinstance(meta.get("layout_check"), dict) else {}
        if meta.get("suspect"):
            out.append(_finding("suspect_dump", BREAKING,
                                f"the {which} dump was stopped by the layout gate (its meta says suspect): it is not a dump of the table",
                                dump=which))
        elif check.get("status") == layout_check.FAIL:
            out.append(_finding("suspect_dump", BREAKING,
                                f"the {which} dump failed its own layout check ({'; '.join(check.get('problems', [])[:2]) or 'see its meta'}): "
                                f"what it holds is probably not the table", dump=which))
        elif check.get("status") == layout_check.UNVERIFIED:
            out.append(_finding("layout_unverified", INFO, f"the {which} dump's layout was never verified against its build",
                                dump=which))
    return out


def schema_findings(old, new, key, ignore, old_by, new_by, shared):
    """The schema-drift findings (see the module docstring), most serious first."""
    findings = _meta_findings(old, new)
    old_fields = [f for f in old.fields() if f not in ignore]
    new_fields = [f for f in new.fields() if f not in ignore]
    for name in old_fields:
        if name not in new_fields and new.records:
            findings.append(_finding("field_removed", BREAKING, f"{name} is in the old records and not in the new ones", name))
    for name in new_fields:
        if name not in old_fields and old.records:
            findings.append(_finding("field_added", BREAKING, f"{name} is in the new records and not in the old ones", name))
    common = [f for f in old_fields if f in new_fields]

    stats = {f: (field_stats(old, f), field_stats(new, f)) for f in common}
    for name, (so, sn) in stats.items():
        if so["n"] and sn["n"]:
            if so["dominant"] != sn["dominant"] and "null" not in (so["dominant"], sn["dominant"]):
                findings.append(_finding("type_changed", BREAKING,
                                         f"{name}: values were {so['dominant']}s and are now {sn['dominant']}s", name,
                                         old=so["dominant"], new=sn["dominant"]))
            if abs(so["null_rate"] - sn["null_rate"]) >= NULL_RATE_JUMP:
                findings.append(_finding("null_rate", BREAKING,
                                         f"{name}: {so['null_rate']:.0%} null before, {sn['null_rate']:.0%} now", name,
                                         old=so["null_rate"], new=sn["null_rate"]))
            if sn["garbled_rate"] - so["garbled_rate"] >= GARBLED_JUMP:
                findings.append(_finding("garbled_strings", BREAKING,
                                         f"{name}: {sn['garbled_rate']:.0%} of the strings hold non-printable junk "
                                         f"(was {so['garbled_rate']:.0%}) - what a wrong offset reads", name))
            if (len(so["distinct"]) <= ENUM_MAX_DISTINCT and so["n"] >= ENUM_MIN_RECORDS and so["distinct"]
                    and sn["n"] and so["dominant"] not in ("list", "object")):
                outside = sum(1 for r in new.records if name in r and name not in unreadable(r)
                              and kind(r[name]) != "null" and hashable(r[name]) not in so["distinct"])
                if outside:
                    share = outside / sn["n"]
                    values = sorted(sn["distinct"] - so["distinct"])[:6]
                    if share >= DOMAIN_SHIFT_SHARE:
                        findings.append(_finding("domain_shift", BREAKING,
                                                 f"{name}: {share:.0%} of the new values are outside the {len(so['distinct'])} the "
                                                 f"old dump had ({', '.join(values)} ...)", name, share=share))
                    else:
                        findings.append(_finding("new_values", WARNING,
                                                 f"{name}: new value(s) the old dump never had: {', '.join(values)}", name))
            mo, mn = so["median_abs"], sn["median_abs"]
            if mo and mn and (mn / mo >= MAGNITUDE_FACTOR or mo / mn >= MAGNITUDE_FACTOR):
                findings.append(_finding("magnitude_shift", WARNING,
                                         f"{name}: typical size {mo:g} before, {mn:g} now", name, old=mo, new=mn))

    # ratios over the records both dumps have
    key_set = set(key)
    value_fields = [f for f in common if f not in key_set]
    pairs = []
    for ident in shared:
        o, n = old_by[ident], new_by[ident]
        o_bad, n_bad = unreadable(o), unreadable(n)
        pairs.append((o, n, o_bad, n_bad))
    if len(pairs) >= MIN_SHARED:
        ratios = {}
        for name in value_fields:
            valid = [(o[name], n[name]) for o, n, ob, nb in pairs
                     if name in o and name in n and name not in ob and name not in nb]
            if len(valid) >= MIN_SHARED:
                ratios[name] = sum(1 for a, b in valid if not same(a, b)) / len(valid)
        hot = [f for f, r in ratios.items() if r >= SYSTEMATIC_RATIO]
        if len(ratios) >= 2 and len(hot) == len(ratios):
            findings.append(_finding("all_fields_changed", BREAKING,
                                     f"every field ({', '.join(hot)}) changed in at least {SYSTEMATIC_RATIO:.0%} of the "
                                     f"{len(pairs)} shared records - a shifted layout, or not the same table"))
        else:
            for name in hot:
                findings.append(_finding("systematic_change", WARNING,
                                         f"{name} changed in {ratios[name]:.0%} of the shared records", name, ratio=ratios[name]))
        for a in value_fields:
            if len(stats[a][0]["distinct"]) < 2 or ratios.get(a, 1.0) < 1 - MOVED_RATIO:
                continue                                    # a constant column matches anything; an unchanged one is not moved
            for b in value_fields:
                if b == a or ratios.get(b, 0.0) < MOVED_DEST_CHANGED:
                    continue                                # B still holds what it held: A was only a copy of it
                valid = [(o[a], n[b]) for o, n, ob, nb in pairs
                         if a in o and b in n and a not in ob and b not in nb and kind(o[a]) != "null"]
                if len(valid) >= MIN_SHARED and sum(1 for x, y in valid if same(x, y)) / len(valid) >= MOVED_RATIO:
                    findings.append(_finding("field_moved", BREAKING,
                                             f"the old values of {a} are now in {b} ({len(valid)} shared records): "
                                             f"columns swapped, or the layout shifted", a, to=b))

    total = max(len(old_by), len(new_by))
    if old_by and abs(len(new_by) - len(old_by)) / len(old_by) >= COUNT_SHIFT:
        findings.append(_finding("count_shift", WARNING, f"{len(old_by)} records before, {len(new_by)} now"))
    if total and len(shared) / total < LOW_OVERLAP:
        findings.append(_finding("low_key_overlap", WARNING,
                                 f"only {len(shared)} of {total} keys are in both dumps: is the key right, or is this the same table?"))
    order = {BREAKING: 0, WARNING: 1, INFO: 2}
    findings.sort(key=lambda f: order[f["severity"]])
    return findings


def how_made(meta):
    """\"hooked\" for a dump taken from the app's own unpack calls, \"snapshot (static)\" / \"snapshot (heap)\" for
    one read from a running app (`meta.snapshot`, run_dump.py --snapshot): a table read from the heap holds
    whatever instances were alive, which is not the same set a hook sees."""
    snap = meta.get("snapshot") if isinstance(meta.get("snapshot"), dict) else None
    if not snap:
        return "hooked"
    used = [s.get("source") for s in snap.get("sources", []) if s.get("status") == "ok"]
    return f"snapshot ({'+'.join(used) if used else 'nothing'})"


def meta_differences(old, new):
    """What differs in the two exports' `meta` that is about the BUILD (offsets, module, ...), as strings."""
    out = []
    for name in ("target", "module", "agent", "profile"):
        a, b = old.meta.get(name), new.meta.get(name)
        if a != b and (a is not None or b is not None):
            out.append(f"{name}: {a} -> {b}")
    a, b = how_made(old.meta), how_made(new.meta)
    if a != b:
        out.append(f"how the table was read: {a} -> {b}")
    a, b = old.meta.get("offsets") or {}, new.meta.get("offsets") or {}
    for k in sorted(set(a) | set(b)):
        if a.get(k) != b.get(k):
            out.append(f"offsets.{k}: {a.get(k)} -> {b.get(k)}")
    return out


# --------------------------------------------------------------------------------------------
# the whole diff, and the console
# --------------------------------------------------------------------------------------------

def diff(old, new, key=None, key_source="cli", ignore=(), profile=None, record=None):
    """The full report (a dict, see the module docstring) for two loaded dumps."""
    ignore = set(ignore)
    if key is None:
        if profile is not None:
            key, key_source = key_from_profile(profile, record, old, new), "profile"
        else:
            key, key_source = infer_key(old, new), "inferred"
    problems = []
    old_by, new_by = index(old, key, "old", problems), index(new, key, "new", problems)
    fields = [f for f in dict.fromkeys(old.fields() + new.fields())]
    added, removed, changed, unchanged, inconclusive, shared = diff_records(old_by, new_by, key, fields, ignore)
    findings = schema_findings(old, new, key, ignore, old_by, new_by, shared)
    drift = any(f["severity"] == BREAKING for f in findings)
    return {
        "version": REPORT_VERSION,
        "old": {"path": old.label, "records": len(old.records)},
        "new": {"path": new.label, "records": len(new.records)},
        "key": {"fields": list(key), "source": key_source},
        "summary": {"added": len(added), "removed": len(removed), "changed": len(changed), "unchanged": unchanged,
                    "inconclusive": inconclusive},
        "added": added, "removed": removed, "changed": changed,
        "schema": {"drift": drift, "findings": findings, "fields": {"old": old.fields(), "new": new.fields()}},
        "build": meta_differences(old, new),
        "problems": problems,
    }


def status(report):
    """The exit status for a report."""
    if report["schema"]["drift"]:
        return EXIT_DRIFT
    s = report["summary"]
    return EXIT_DIFFERENT if (s["added"] or s["removed"] or s["changed"]) else EXIT_SAME


def _ident(key, rec):
    return " ".join(f"{k}={show(rec[k], 30)}" for k in key if k in rec)


def render(report, limit=20):
    """Console lines for `report`; `limit` caps each category's detail (0 = counts only, None = everything)."""
    key = report["key"]["fields"]
    s = report["summary"]
    lines = [f"[*] old: {report['old']['path']} ({report['old']['records']} records)",
             f"    new: {report['new']['path']} ({report['new']['records']} records)",
             f"[*] key: {', '.join(key)}" + ("  (inferred - pass --key or --profile to be sure)" if report["key"]["source"] == "inferred"
                                              else f"  ({report['key']['source']})")]
    for line in report["build"]:
        lines.append(f"[i] build: {line}")
    for p in report["problems"]:
        lines.append(f"[!] {p['detail']}: {', '.join(f'{k}={show(v, 20)}' for k, v in p['key'].items())}")
    lines.append(f"[+] {s['added']} added, {s['removed']} removed, {s['changed']} changed, {s['unchanged']} unchanged"
                 + (f" ({s['inconclusive']} compared only in part: a field was unreadable)" if s["inconclusive"] else ""))

    def cap(items):
        shown = items if limit is None else items[:limit]
        return shown, len(items) - len(shown)

    for sign, label, items in (("+", "added", report["added"]), ("-", "removed", report["removed"])):
        shown, more = cap(items)
        for rec in shown:
            fields = {k: v for k, v in rec.items() if k != UNREADABLE and k not in key}
            lines.append(f"  {sign} {label:<7} {_ident(key, rec)}  " + " ".join(f"{k}={show(v, 24)}" for k, v in list(fields.items())[:4]))
        if more:
            lines.append(f"  ... and {more} more {label}")
    shown, more = cap(report["changed"])
    for item in shown:
        ident = " ".join(f"{k}={show(v, 30)}" for k, v in item["key"].items())
        what = "; ".join(f"{c['field']} {show(c['old'], 24)} -> {show(c['new'], 24)}" for c in item["changes"][:5])
        lines.append(f"  ~ changed {ident}  {what}" + (f"; +{len(item['changes']) - 5} more" if len(item["changes"]) > 5 else ""))
    if more:
        lines.append(f"  ... and {more} more changed")

    findings = report["schema"]["findings"]
    breaking = [f for f in findings if f["severity"] == BREAKING]
    if breaking:
        lines.append("[!] SCHEMA DRIFT - the two dumps are probably not comparable as tables; read the record diff above with suspicion:")
    for f in findings:
        tag = {"breaking": "      -", "warning": "    note:", "info": "    info:"}[f["severity"]]
        lines.append(f"{tag} [{f['kind']}] {f['detail']}")
    if not breaking and not (s["added"] or s["removed"] or s["changed"]):
        lines.append("[+] The two dumps hold the same records.")
    return lines


def main(argv=None, prog=None):
    ap = argparse.ArgumentParser(prog=prog, description="Semantic diff of two run_dump.py exports, with schema-drift detection.")
    ap.add_argument("old", help="the older export (records*.json)")
    ap.add_argument("new", help="the newer export")
    ap.add_argument("--key", metavar="F1,F2", help="the field(s) that identify a record")
    ap.add_argument("--profile", metavar="NAME", help="take the key from this profile's layout")
    ap.add_argument("--record", metavar="NAME", help="which layout record of --profile the dumps are of")
    ap.add_argument("--ignore", metavar="F1,F2", default="", help="fields to leave out of the comparison")
    ap.add_argument("--limit", type=int, default=20, metavar="N",
                    help="records shown per category (0 = counts only; default 20; --json has everything)")
    ap.add_argument("--json", metavar="PATH", help="write the whole report here (holds real data: keep it out of git)")
    args = ap.parse_args(argv)

    if args.key and args.profile:
        ap.error("--key and --profile both say what identifies a record: use one")
    if args.record and not args.profile:
        ap.error("--record names a record of --profile")
    key = [k.strip() for k in args.key.split(",") if k.strip()] if args.key else None
    if args.key and not key:
        ap.error("--key is empty")
    try:
        old, new = load_dump(args.old), load_dump(args.new)
        report = diff(old, new, key=key, key_source="cli", ignore={f.strip() for f in args.ignore.split(",") if f.strip()},
                      profile=args.profile, record=args.record)
    except DiffError as e:
        print(f"[!] {e}", file=sys.stderr)
        return EXIT_USAGE

    if args.json:
        from ._common import is_gitignored
        if is_gitignored(args.json) is False:
            print(f"[!] --json {args.json} is NOT covered by .gitignore and holds real records and both dumps' meta. "
                  f"Keep it out of git - or use a diff_records*.json name.")
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    for line in render(report, None if args.limit < 0 else args.limit):
        print(line)
    if args.json:
        print(f"[+] Wrote {args.json}")
    return status(report)


if __name__ == "__main__":
    sys.exit(main())
