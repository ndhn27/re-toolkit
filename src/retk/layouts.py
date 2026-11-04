"""
layouts.py

Validation and description of record layouts - the `layouts` section of a
profile (see profiles.py and profile.example.json).

A layout says where each field of a record lives (offset, relative to the
object pointer), how it is read (type) and what it means. It reaches the Frida
agents at runtime, as part of the parameters the driver passes to
rpc.exports.init(), so nothing about a layout is compiled into an agent.

What validate() rejects is what would otherwise corrupt a dump silently: a
misaligned or overlapping field, a field inside the object header, an unknown
type, a `key` that names no field, a subset naming a field its record doesn't
have, a field named like something the agents add to a record themselves
(RESERVED_FIELD_NAMES).

A layout is still a hypothesis about a particular build, found by reading
memory and checked by nothing - so it can also carry what the author OBSERVED
about the data, and the agents check those claims against every record they
read (scripts/_canary.js; retk/layout_check.py judges the result):

    "klass":  "constant" | "pointer"      # record level, default "constant"
    "fields": [{"name": "enabled", "offset": "0x18", "type": "s8",
                "expect": {"oneOf": [0, 1]}}, ...]

`expect` takes `min` / `max` / `oneOf` on a numeric field and `nonEmpty` /
`maxLength` on a string field; an unknown key is an error (a typo must not
quietly switch a check off). `klass` is about the object header: the word at +0
should always be a valid pointer, and the same one for every record of one
class ("constant"); use "pointer" for a table that holds several subclasses.
Whatever the profile does not claim, the agents can only check structurally
(see layout_check.py), so each `expect` makes the canary stronger.

    retk profile layout PROFILE        # print every record's layout
"""
import keyword
import re
import textwrap
from collections import namedtuple

FieldType = namedtuple("FieldType", "size label")

# The vocabulary of `type`. Keep the keys equal to FIELD_READERS in
# scripts/_lib.js (tests/test_layouts.py checks they match).
TYPES = {
    "u32": FieldType(4, "uint32"),
    "s32": FieldType(4, "int32"),
    "s8": FieldType(1, "int8"),
    "string": FieldType(8, "System.String*"),
}

# Value range of each numeric type, so an `expect` can't name a value the field can never hold.
RANGES = {"u32": (0, 2**32 - 1), "s32": (-2**31, 2**31 - 1), "s8": (-128, 127)}
EXPECT_KEYS = {"numeric": ("min", "max", "oneOf"), "string": ("nonEmpty", "maxLength")}
KLASS_MODES = ("constant", "pointer")

# Names an agent adds to a record itself, so a layout may not use them for a
# field. Keep equal to UNREADABLE_KEY in scripts/_lib.js (tests/test_unreadable.py
# checks they match): a record whose string fields could not be read carries
# `_unreadable: [field names]` and those fields are null.
RESERVED_FIELD_NAMES = ("_unreadable",)

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class SchemaError(ValueError):
    pass


def _require(cond, msg):
    if not cond:
        raise SchemaError(msg)


def _offset(value, where):
    if isinstance(value, str) and re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        value = int(value, 16)
    _require(isinstance(value, int) and not isinstance(value, bool) and value >= 0,
             f"{where}: offset must be a 0x-prefixed hex string, got {value!r}")
    return value


def _ident(name, where):
    _require(isinstance(name, str) and _IDENT_RE.match(name) and not keyword.iskeyword(name),
             f"{where}: {name!r} is not a usable identifier")
    return name


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _expect(raw, ftype, where):
    """Validate one field's `expect` and return it normalised."""
    _require(isinstance(raw, dict) and raw, f"{where}.expect: must be a non-empty object")
    kind = "string" if ftype == "string" else "numeric"
    unknown = sorted(set(raw) - set(EXPECT_KEYS[kind]))
    _require(not unknown, f"{where}.expect: unknown key(s) {', '.join(map(repr, unknown))} - a "
                          f"{ftype} field takes {', '.join(EXPECT_KEYS[kind])}")
    out = {}
    if kind == "string":
        if "nonEmpty" in raw:
            _require(isinstance(raw["nonEmpty"], bool), f"{where}.expect.nonEmpty: must be true or false")
            out["nonEmpty"] = raw["nonEmpty"]
        if "maxLength" in raw:
            _require(_is_int(raw["maxLength"]) and raw["maxLength"] > 0,
                     f"{where}.expect.maxLength: must be a positive integer")
            out["maxLength"] = raw["maxLength"]
        return out

    lo, hi = RANGES[ftype]
    for bound in ("min", "max"):
        if bound in raw:
            v = raw[bound]
            _require(_is_int(v) and lo <= v <= hi,
                     f"{where}.expect.{bound}: must be an integer within {ftype}'s range {lo}..{hi}, got {v!r}")
            out[bound] = v
    _require(out.get("min", lo) <= out.get("max", hi), f"{where}.expect: min is above max")
    if "oneOf" in raw:
        values = raw["oneOf"]
        _require(isinstance(values, list) and values and all(_is_int(v) and lo <= v <= hi for v in values)
                 and len(set(values)) == len(values),
                 f"{where}.expect.oneOf: must be a non-empty list of distinct integers within "
                 f"{ftype}'s range {lo}..{hi}")
        out["oneOf"] = list(values)
    return out


def validate(raw):
    """Check `raw` (a profile's `layouts` object) and return a normalised copy:
    offsets as ints, fields in offset order, subsets expanded to their fields."""
    _require(isinstance(raw, dict), "layouts must be an object")
    header = raw.get("headerSize")
    _require(isinstance(header, int) and header > 0, "headerSize must be a positive integer")

    s_raw = raw.get("il2cppString") or {}
    length_at = _offset(s_raw.get("lengthOffset"), "il2cppString.lengthOffset")
    chars_at = _offset(s_raw.get("charsOffset"), "il2cppString.charsOffset")
    _require(length_at >= header, "il2cppString.lengthOffset overlaps the object header")
    _require(chars_at == length_at + TYPES["s32"].size,
             "il2cppString.charsOffset must start right after the int32 length")

    _require(raw.get("records"), "no records defined")
    records = {}
    for rname, r in raw["records"].items():
        rwhere = f"records.{_ident(rname, 'record name')}"
        fields, seen = [], set()
        for f in r.get("fields", []):
            fname = _ident(f.get("name"), f"{rwhere}.fields[].name")
            where = f"{rwhere}.{fname}"
            _require(fname not in RESERVED_FIELD_NAMES,
                     f"{where}: {fname!r} is reserved - the agents use it to list the fields of a "
                     f"record they could not read; pick another name")
            _require(fname not in seen, f"{where}: duplicate field name")
            seen.add(fname)
            _require(f.get("type") in TYPES, f"{where}: unknown type {f.get('type')!r} "
                                             f"(known: {', '.join(TYPES)})")
            off = _offset(f.get("offset"), where)
            size = TYPES[f["type"]].size
            _require(off % size == 0, f"{where}: offset {off:#x} is not naturally aligned "
                                      f"for a {size}-byte {f['type']}")
            field = {"name": fname, "offset": off, "type": f["type"], "doc": f.get("doc", "")}
            if f.get("expect") is not None:
                field["expect"] = _expect(f["expect"], f["type"], where)
            fields.append(field)
        _require(fields, f"{rwhere}: no fields")
        _require([f["offset"] for f in fields] == sorted(f["offset"] for f in fields),
                 f"{rwhere}: fields must be listed in ascending offset order")

        unread = []
        for u in r.get("unread", []):
            uname = _ident(u.get("name"), f"{rwhere}.unread[].name")
            where = f"{rwhere}.{uname}"
            _require(uname not in seen, f"{where}: duplicate field name")
            seen.add(uname)
            size = u.get("size")
            _require(isinstance(size, int) and size > 0, f"{where}: size must be a positive integer")
            _require(u.get("doc"), f"{where}: an unread region needs a doc line")
            unread.append({"name": uname, "offset": _offset(u.get("offset"), where),
                           "size": size, "doc": u["doc"]})

        end = header
        for e in sorted(fields + unread, key=lambda e: e["offset"]):
            size = e["size"] if "size" in e else TYPES[e["type"]].size
            _require(e["offset"] >= end, f"{rwhere}.{e['name']}: overlaps the previous field "
                                         f"or the {header}-byte object header")
            end = e["offset"] + size

        # What identifies a record in an agent's store: one field name, or
        # several (joined with ":") when `id` alone isn't unique.
        key = r.get("key", ["id"])
        _require(isinstance(key, list) and key and len(set(key)) == len(key),
                 f"{rwhere}: key must be a non-empty list of unique field names")
        unknown = [k for k in key if k not in {f["name"] for f in fields}]
        _require(not unknown, f"{rwhere}: key names no readable field: {', '.join(map(str, unknown))}")
        klass = r.get("klass", "constant")
        _require(klass in KLASS_MODES, f"{rwhere}: klass must be one of {', '.join(KLASS_MODES)}, got {klass!r}")
        records[rname] = {"description": r.get("description", ""), "key": key, "klass": klass,
                          "fields": fields, "unread": unread}

    subsets = {}
    for sname, s in raw.get("subsets", {}).items():
        swhere = f"subsets.{_ident(sname, 'subset name')}"
        _require(sname not in records, f"{swhere}: clashes with a record name")
        _require(s.get("of") in records, f"{swhere}: unknown record {s.get('of')!r}")
        names = s.get("fields") or []
        _require(names and len(set(names)) == len(names), f"{swhere}: fields must be non-empty and unique")
        parent = {f["name"] for f in records[s["of"]]["fields"]}
        missing = [n for n in names if n not in parent]
        _require(not missing, f"{swhere}: not readable fields of {s['of']}: {', '.join(missing)}")
        subsets[sname] = {"of": s["of"], "description": s.get("description", ""), "fields": list(names)}

    return {"header_size": header,
            "string": {"length_offset": length_at, "chars_offset": chars_at},
            "records": records, "subsets": subsets}


def for_agent(schema):
    """The part of a validated layout an agent needs, as plain JSON-able data
    (docs and unread regions stay on the Python side)."""
    def agent_field(f):
        out = {"name": f["name"], "offset": f["offset"], "type": f["type"]}
        if "expect" in f:
            out["expect"] = f["expect"]
        return out

    return {
        # The object header the layout assumes - only so the canary can report a measured one next to it.
        "headerSize": schema["header_size"],
        "string": {"lengthOffset": schema["string"]["length_offset"],
                   "charsOffset": schema["string"]["chars_offset"]},
        "records": {n: {"key": r["key"], "klass": r["klass"],
                        "fields": [agent_field(f) for f in r["fields"]]}
                    for n, r in schema["records"].items()},
        "subsets": {n: {"of": s["of"], "fields": s["fields"]} for n, s in schema["subsets"].items()},
    }


def describe_expect(expect):
    """One field's `expect` as a short phrase, e.g. `one of 0, 1` / `0..100` / `>= 1` / `non-empty, <= 64 chars`."""
    parts = []
    if "oneOf" in expect:
        parts.append("one of " + ", ".join(map(str, expect["oneOf"])))
    if "min" in expect and "max" in expect:
        parts.append(f"{expect['min']}..{expect['max']}")
    elif "min" in expect:
        parts.append(f">= {expect['min']}")
    elif "max" in expect:
        parts.append(f"<= {expect['max']}")
    if expect.get("nonEmpty"):
        parts.append("non-empty")
    if "maxLength" in expect:
        parts.append(f"<= {expect['maxLength']} chars")
    return ", ".join(parts)


def describe(schema, record):
    """A human-readable offset listing for one record, padding included."""
    header = schema["header_size"]
    r = schema["records"][record]
    entries = [dict(f, kind="field", size=TYPES[f["type"]].size) for f in r["fields"]]
    entries += [dict(u, kind="unread") for u in r["unread"]]
    entries.sort(key=lambda e: e["offset"])
    width = max(len(e["name"]) for e in entries) + 2

    klass_note = "" if r["klass"] == "constant" else "; the class word may differ between records"
    rows = [f"+0x00  {'klass':<{width}}object header ({header} bytes{klass_note})"]
    cursor = header
    for e in entries:
        if e["offset"] > cursor:
            rows.append(f"+{cursor:#04x}  (padding, {e['offset'] - cursor} bytes)")
        if e["kind"] == "field":
            doc = e["doc"]
            if "expect" in e:
                doc = f"{doc}  [expect: {describe_expect(e['expect'])}]".strip()
            row = f"+{e['offset']:#04x}  {e['name']:<{width}}{TYPES[e['type']].label:<16}{doc}"
        else:
            row = f"+{e['offset']:#04x}  {e['name']:<{width}}(not read; {e['size']} bytes)"
        rows.append(row.rstrip())
        cursor = e["offset"] + e["size"]
    out = [f"{record}  key={'+'.join(r['key'])}"]
    if r["description"]:
        out += textwrap.wrap(r["description"], width=78, initial_indent="  ", subsequent_indent="  ")
    out += [""] + rows
    for u in r["unread"]:
        out += ["", f"{u['name']} (+{u['offset']:#04x}..{u['offset'] + u['size'] - 1:#04x}): {u['doc']}"]
    return "\n".join(out)
