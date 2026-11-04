"""
Tests for record layouts and the agents that read with them.

A layout (a profile's `layouts` section, validated by retk/layouts.py) is
data: it reaches an agent at runtime through rpc.exports.init(stage, params),
so nothing about a layout is compiled into scripts/. profile.example.json is
the fixture. What is checked:

  * layouts.validate() rejects what would corrupt a dump silently (misaligned
    or overlapping fields, a key naming no field, ...);
  * the JS side really DECODES each type the way the layout says. The agents'
    output is compared, field by field, with an independent Python decoder
    (`struct`) over a fake process image - sign, width and nullability
    included - so e.g. `u32: (p) => p.readS8()` in _lib.js fails here;
  * the real agents, run under Node with a faked Frida, hook the profile's
    RVA, export records of exactly those types, and refuse to run on a
    profile that doesn't say what they need (an offset of 0, a missing layout);
  * scripts/ holds no target value at all - the structural replacement for
    scanning source files for one.

The Node-backed tests skip when `node` isn't installed (fail instead when $CI
is set, so CI can't silently stop running them). Run from the repo root:

    pytest
"""
import copy
import json
import re
import shutil
import struct
from pathlib import Path

import pytest

from retk import layouts
from retk import profiles
from node_support import run_harness

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"

PROFILE = profiles.load(REPO_ROOT / "profile.example.json")
RAW = json.loads((REPO_ROOT / "profile.example.json").read_text(encoding="utf-8"))["layouts"]
SCHEMA = PROFILE.layouts
RECORDS = SCHEMA["records"]
SUBSET = SCHEMA["subsets"]["LookupResult"]

# The independent oracle: how the Python side says each layout type is laid
# out in memory. Deliberately NOT derived from anything in scripts/ or src/retk/.
PACK = {"u32": "<I", "s32": "<i", "s8": "<b", "string": "<Q"}
RANGE = {"u32": (0, 2**32 - 1), "s32": (-2**31, 2**31 - 1), "s8": (-128, 127)}


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def _field(raw, name, record="TableBRecord"):
    return next(f for f in raw["records"][record]["fields"] if f["name"] == name)


def _swap_first_two(raw):
    fields = raw["records"]["TableBRecord"]["fields"]
    fields[0], fields[1] = fields[1], fields[0]


BAD_LAYOUTS = {
    "misaligned": (lambda r: _field(r, "id").update(offset="0x11"), "not naturally aligned"),
    "overlapping": (lambda r: _field(r, "kind").update(offset="0x10"), "overlaps"),
    "inside the header": (lambda r: _field(r, "id").update(offset="0x8"), "overlaps"),
    "unread overlaps a field": (
        lambda r: r["records"]["TableBRecord"]["unread"][0].update(offset="0x14"), "overlaps"),
    "unsorted": (_swap_first_two, "ascending offset order"),
    "unknown type": (lambda r: _field(r, "valueB").update(type="u64"), "unknown type"),
    "non-hex offset": (lambda r: _field(r, "id").update(offset="8"), "0x-prefixed"),
    "duplicate name": (lambda r: _field(r, "kind").update(name="id"), "duplicate"),
    "bad identifier": (lambda r: _field(r, "id").update(name="not valid"), "identifier"),
    "key names a missing field": (
        lambda r: r["records"]["TableBRecord"].update(key=["kind", "nope"]), "names no readable field"),
    "empty key": (lambda r: r["records"]["TableBRecord"].update(key=[]), "non-empty list"),
    "repeated key field": (lambda r: r["records"]["TableBRecord"].update(key=["id", "id"]), "unique"),
    "subset names a missing field": (
        lambda r: r["subsets"]["LookupResult"]["fields"].append("nope"), "not readable fields"),
    "subset of an unknown record": (
        lambda r: r["subsets"]["LookupResult"].update(of="Nope"), "unknown record"),
    "string chars not after length": (
        lambda r: r["il2cppString"].update(charsOffset="0x10"), "right after"),
    "no header size": (lambda r: r.pop("headerSize"), "headerSize"),
    "no records": (lambda r: r.update(records={}), "no records"),
    "expect with a typo'd key": (
        lambda r: _field(r, "id").update(expect={"oneof": [1]}), "unknown key.*oneof"),
    "numeric expect with a string key": (
        lambda r: _field(r, "id").update(expect={"nonEmpty": True}), "unknown key.*nonEmpty"),
    "string expect with a numeric key": (
        lambda r: _field(r, "label").update(expect={"min": 1}), "unknown key.*min"),
    "empty expect": (lambda r: _field(r, "id").update(expect={}), "non-empty object"),
    "expect that is not an object": (lambda r: _field(r, "id").update(expect=[0, 1]), "non-empty object"),
    "min above max": (lambda r: _field(r, "id").update(expect={"min": 5, "max": 4}), "min is above max"),
    "min outside the type's range": (
        lambda r: _field(r, "kind").update(expect={"min": -1}), "within u32's range"),
    "oneOf value outside the type's range": (
        lambda r: _field(r, "lo1").update(expect={"oneOf": [2**31]}), "within s32's range"),
    "oneOf with a duplicate": (lambda r: _field(r, "id").update(expect={"oneOf": [1, 1]}), "distinct"),
    "oneOf empty": (lambda r: _field(r, "id").update(expect={"oneOf": []}), "non-empty list"),
    "oneOf with a boolean": (lambda r: _field(r, "id").update(expect={"oneOf": [True]}), "integers"),
    "maxLength zero": (lambda r: _field(r, "label").update(expect={"maxLength": 0}), "positive integer"),
    "nonEmpty not a boolean": (lambda r: _field(r, "label").update(expect={"nonEmpty": "yes"}), "true or false"),
    "unknown klass mode": (lambda r: r["records"]["TableBRecord"].update(klass="same"), "klass must be one of"),
}


@pytest.mark.parametrize("case", sorted(BAD_LAYOUTS))
def test_invalid_layout_is_rejected(case):
    mutate, message = BAD_LAYOUTS[case]
    raw = copy.deepcopy(RAW)
    mutate(raw)
    with pytest.raises(layouts.SchemaError, match=message):
        layouts.validate(raw)


def test_expect_and_klass_are_normalised_and_default_sensibly():
    raw = copy.deepcopy(RAW)
    _field(raw, "id", "TableARecord").update(expect={"min": 1, "max": 9, "oneOf": [1, 5]})
    raw["records"]["TableBRecord"]["klass"] = "pointer"
    schema = layouts.validate(raw)
    assert _field(schema, "id", "TableARecord")["expect"] == {"min": 1, "max": 9, "oneOf": [1, 5]}
    assert schema["records"]["TableARecord"]["klass"] == "constant"       # the default
    assert schema["records"]["TableBRecord"]["klass"] == "pointer"
    assert layouts.for_agent(schema)["records"]["TableBRecord"]["klass"] == "pointer"


def test_describe_shows_what_a_profile_claims_about_its_fields():
    text = layouts.describe(SCHEMA, "TableARecord")
    assert "[expect: >= 1]" in text and "[expect: one of 0, 1]" in text
    assert "[expect: non-empty, <= 64 chars]" in text
    raw = copy.deepcopy(RAW)
    raw["records"]["TableBRecord"]["klass"] = "pointer"
    assert "the class word may differ between records" in layouts.describe(
        layouts.validate(raw), "TableBRecord")


def test_key_defaults_to_id():
    raw = copy.deepcopy(RAW)
    del raw["records"]["TableARecord"]["key"]
    assert layouts.validate(raw)["records"]["TableARecord"]["key"] == ["id"]


def test_the_agents_get_names_offsets_and_types_but_none_of_the_prose():
    sent = layouts.for_agent(SCHEMA)
    assert json.loads(json.dumps(sent)) == sent
    for r in sent["records"].values():
        # `expect` is data the agent acts on (the layout canary), `doc` is prose it never needs.
        assert all({"name", "offset", "type"} <= set(f) <= {"name", "offset", "type", "expect"}
                   for f in r["fields"])
    assert [f for f in sent["records"]["TableARecord"]["fields"] if "expect" in f] == [
        {"name": "id", "offset": 0x10, "type": "u32", "expect": {"min": 1}},
        {"name": "enabled", "offset": 0x18, "type": "s8", "expect": {"oneOf": [0, 1]}},
        {"name": "name", "offset": 0x20, "type": "string", "expect": {"nonEmpty": True, "maxLength": 64}},
    ]
    assert sent["subsets"]["LookupResult"] == {"of": "TableBRecord",
                                               "fields": ["id", "kind", "level", "valueB", "label"]}


def test_describe_lists_padding_unread_regions_and_the_key():
    text = layouts.describe(SCHEMA, "TableARecord")
    assert text.startswith("TableARecord  key=id")
    assert "(padding, 7 bytes)" in text and "(not read; 8 bytes)" in text
    assert "object header (16 bytes)" in text


def test_memory_layout_doc_shows_the_example_profile_verbatim():
    doc = (REPO_ROOT / "docs" / "MEMORY_LAYOUT.md").read_text(encoding="utf-8")
    for name in RECORDS:
        assert layouts.describe(SCHEMA, name) in doc, f"docs/MEMORY_LAYOUT.md is out of date for {name}"


# ---------------------------------------------------------------------------
# JS decoding vs an independent Python decoder (needs node)
# ---------------------------------------------------------------------------

IMAGE_SIZE = 0x4000
RECORD_BASE, RECORD_STRIDE = 0x1000, 0x200
STRING_BASE, STRING_STRIDE = 0x3000, 0x80
BASE_OFFSETS = {"table_a": 0x40, "table_b": 0x50, "probe": 0x60,
                "lookup_by_pattern": 0x70, "resolve_default": 0x80}


def params(**offsets):
    """What a driver would pass to init(): the example profile with some RVAs
    filled in (all of them by default)."""
    return profiles.agent_params(PROFILE, offsets={**BASE_OFFSETS, **offsets})


class Image:
    """A fake process address space; address N is mem[N]. Filled with 0xEE, so a
    read at a wrong offset or of the wrong width returns garbage, not zero."""

    def __init__(self):
        self.mem = bytearray(b"\xee" * IMAGE_SIZE)
        self._next_string = STRING_BASE

    def put_string(self, text):
        addr, self._next_string = self._next_string, self._next_string + STRING_STRIDE
        at = SCHEMA["string"]
        struct.pack_into("<i", self.mem, addr + at["length_offset"], len(text))
        data = text.encode("utf-16-le")
        self.mem[addr + at["chars_offset"]:addr + at["chars_offset"] + len(data)] = data
        return addr

    def put_record(self, rname, base, salt=1, **overrides):
        """Write one record of type `rname` at `base`, with values that are
        distinguishable under any wrong signedness/width, and return the
        {field: value} dict a correct reader must produce."""
        expected = {}
        for idx, f in enumerate(RECORDS[rname]["fields"]):
            t = f["type"]
            if t == "u32":
                value = 0xF0000000 + salt * 0x101 + idx        # > 2**31, more than 8 bits
            elif t == "s32":
                value = -70000 - salt * 7 - idx                # negative, more than 16 bits
            elif t == "s8":
                value = -3 - salt                              # negative: unsigned would be 253+
            else:
                value = f"cfg-{salt}-{f['name']}"
            value = overrides.get(f["name"], value)
            expected[f["name"]] = value
            if t == "string":
                value = 0 if value is None else self.put_string(value)
            struct.pack_into(PACK[t], self.mem, base + f["offset"], value)
        return expected


def read_record(scripts_dir, image, record, base=RECORD_BASE, only=None, p=None):
    [got] = run_harness(scripts_dir, image.mem, mode="readRecord", params=p or params(),
                        cases=[{"record": record, "base": base, "only": only}])
    return got


def assert_typed(rname, record):
    """What the Python side may rely on for a record it received over RPC."""
    fields = {f["name"]: f["type"] for f in RECORDS[rname]["fields"]}
    assert set(record) == set(fields)
    for name, t in fields.items():
        v = record[name]
        if t == "string":
            assert v is None or isinstance(v, str), (name, v)
        else:
            lo, hi = RANGE[t]
            assert type(v) is int and lo <= v <= hi, (name, t, v)


def test_js_readers_cover_exactly_the_layout_types(node_scripts):
    readers = run_harness(node_scripts, b"", mode="info")["readers"]
    assert set(readers) == set(layouts.TYPES) == set(PACK)


@pytest.mark.parametrize("rname", list(RECORDS))
def test_js_decodes_every_field_like_the_python_oracle(node_scripts, rname):
    image = Image()
    expected = image.put_record(rname, RECORD_BASE)
    got = read_record(node_scripts, image, rname)
    assert got == {"ok": expected}
    assert_typed(rname, got["ok"])


def test_js_follows_whatever_offsets_the_profile_gives(node_scripts):
    # The point of runtime layouts: move a field in the profile and the agent
    # reads it from there, with no change to scripts/.
    raw = copy.deepcopy(RAW)
    _field(raw, "label").update(offset="0x50")
    p = {**params(), "layouts": layouts.for_agent(layouts.validate(raw))}
    image = Image()
    struct.pack_into("<Q", image.mem, RECORD_BASE + 0x50, image.put_string("moved"))
    got = read_record(node_scripts, image, "TableBRecord", only=["label"], p=p)
    assert got == {"ok": {"label": "moved"}}


def test_js_reads_a_null_string_pointer_as_null(node_scripts):
    image = Image()
    expected = image.put_record("TableBRecord", RECORD_BASE, label=None)
    got = read_record(node_scripts, image, "TableBRecord")
    assert got["ok"]["label"] is None
    assert got == {"ok": expected}


def test_js_subset_read_returns_only_the_subset(node_scripts):
    image = Image()
    full = image.put_record(SUBSET["of"], RECORD_BASE)
    got = read_record(node_scripts, image, SUBSET["of"], only=SUBSET["fields"])
    assert got == {"ok": {n: full[n] for n in SUBSET["fields"]}}


def test_js_rejects_a_subset_naming_a_missing_field(node_scripts):
    image = Image()
    image.put_record(SUBSET["of"], RECORD_BASE)
    got = read_record(node_scripts, image, SUBSET["of"], only=["id", "nope"])
    assert "nope" in got["error"]


def test_js_string_reader_edge_cases(node_scripts):
    # MAX_STRING_LEN in scripts/_lib.js - keep in sync with the value there.
    # It's a runaway-read guard (misread pointer/offset), not a real content
    # limit, so this test also proves a genuinely long, valid string still
    # decodes correctly.
    max_string_len = 65536

    image = Image()
    length_at = SCHEMA["string"]["length_offset"]
    ok, empty = image.put_string("héllo"), image.put_string("")
    negative, huge = image.put_string("x"), image.put_string("x")
    struct.pack_into("<i", image.mem, negative + length_at, -1)
    struct.pack_into("<i", image.mem, huge + length_at, max_string_len + 1)
    long_valid_text = "y" * 1000
    long_valid = image.put_string(long_valid_text)
    got = run_harness(node_scripts, image.mem, mode="string", params=params(),
                      addrs=[0, ok, empty, negative, huge, long_valid, IMAGE_SIZE + 0x100])
    assert got[0] is None
    assert got[1] == "héllo"
    assert got[2] == ""
    assert got[3] == "<unexpected len: -1>"
    assert got[4] == f"<unexpected len: {max_string_len + 1}>"
    assert got[5] == long_valid_text
    assert got[6].startswith("<read error")


def test_js_string_layout_comes_from_the_profile(node_scripts):
    # A build whose System.String keeps its length elsewhere: only the profile changes.
    raw = copy.deepcopy(RAW)
    raw["il2cppString"] = {"lengthOffset": "0x18", "charsOffset": "0x1c"}
    p = {**params(), "layouts": layouts.for_agent(layouts.validate(raw))}
    image = Image()
    at = 0x3000
    struct.pack_into("<i", image.mem, at + 0x18, 5)
    image.mem[at + 0x1c:at + 0x1c + 10] = "moved".encode("utf-16-le")
    assert run_harness(node_scripts, image.mem, mode="string", params=p, addrs=[at]) == ["moved"]


def test_a_wrong_reader_would_be_caught(node_scripts, tmp_path):
    # Meta-test: prove the oracle above has teeth. Break FIELD_READERS.u32 in a
    # copy of the scripts (the `readS8()` scenario) and check the output no
    # longer matches what test_js_decodes_every_field_like_the_python_oracle
    # requires.
    broken = tmp_path / "scripts"
    shutil.copytree(node_scripts, broken)
    lib = broken / "_lib.js"
    source = lib.read_text(encoding="utf-8")
    assert "u32: (p) => p.readU32()," in source
    lib.write_text(source.replace("u32: (p) => p.readU32(),", "u32: (p) => p.readS8(),"), encoding="utf-8")

    image = Image()
    expected = image.put_record("TableBRecord", RECORD_BASE)
    assert read_record(broken, image, "TableBRecord") != {"ok": expected}


# ---------------------------------------------------------------------------
# the real agents, under Node with a faked Frida
# ---------------------------------------------------------------------------

# record -> (agent, the offset key it hooks)
RPC_AGENTS = {"TableARecord": ("dump_table_a.js", "table_a"),
              "TableBRecord": ("dump_table_b.js", "table_b")}
ALL_AGENTS = {"dump_table_a.js": ["table_a"], "dump_table_b.js": ["table_b"], "probe_record.js": ["probe"],
              "trace_lookup.js": ["lookup_by_pattern", "resolve_default"]}
DEFAULT = object()


def run_agent(scripts_dir, image, agent, events=(), p=DEFAULT, **request):
    return run_harness(scripts_dir, image.mem, mode="agent", agent=agent,
                       params=params() if p is DEFAULT else p, events=list(events), **request)


def _record_events(count):
    return [{"hook": 0, "args": [RECORD_BASE + i * RECORD_STRIDE], "retval": 0} for i in range(count)]


@pytest.mark.parametrize("rname", RPC_AGENTS)
def test_rpc_agent_exports_what_the_layout_decodes(node_scripts, rname):
    image = Image()
    expected = [image.put_record(rname, RECORD_BASE + i * RECORD_STRIDE, salt=i + 1) for i in range(2)]
    out = run_agent(node_scripts, image, RPC_AGENTS[rname][0],
                    _record_events(2) + _record_events(1))                     # last one re-sent
    assert out["initError"] is None
    assert out["rpc"] == {"count": 2, "records": expected}
    for rec in out["rpc"]["records"]:
        assert_typed(rname, rec)


@pytest.mark.parametrize("agent,keys", ALL_AGENTS.items())
def test_agents_hook_exactly_the_rvas_the_profile_gives(node_scripts, agent, keys):
    out = run_agent(node_scripts, Image(), agent, p=params(**{k: 0x1230 + i * 0x10 for i, k in enumerate(keys)}))
    assert out["initError"] is None
    assert out["attached"] == [0x1230 + i * 0x10 for i in range(len(keys))]   # module base is 0 in the harness


@pytest.mark.parametrize("agent,keys", ALL_AGENTS.items())
def test_agents_refuse_an_offset_that_is_zero(node_scripts, agent, keys):
    for key in keys:                                           # e.g. the template profile: every RVA is 0x0
        out = run_agent(node_scripts, Image(), agent, p=params(**{key: 0}))
        assert f"offsets.{key} is missing or 0" in out["initError"]
        assert out["attached"] == []                           # nothing was hooked at a guess
        assert any(line.startswith("[!] init failed") for line in out["log"])   # the Frida CLI hides a throwing init


@pytest.mark.parametrize("agent,keys", ALL_AGENTS.items())
def test_agents_refuse_a_profile_that_lacks_the_offset(node_scripts, agent, keys):
    out = run_agent(node_scripts, Image(), agent, p={**params(), "offsets": {}})
    assert f"offsets.{keys[0]} is missing or 0" in out["initError"]
    assert out["attached"] == []


@pytest.mark.parametrize("agent", ["dump_table_a.js", "dump_table_b.js", "trace_lookup.js"])
def test_agents_that_read_records_refuse_a_profile_without_layouts(node_scripts, agent):
    p = params()
    del p["layouts"]
    out = run_agent(node_scripts, Image(), agent, p=p)
    assert "layouts" in out["initError"]
    assert out["attached"] == []


def test_an_agent_names_the_record_the_profile_forgot(node_scripts):
    p = params()
    del p["layouts"]["records"]["TableBRecord"]
    assert 'no record "TableBRecord"' in run_agent(node_scripts, Image(), "dump_table_b.js", p=p)["initError"]
    assert run_agent(node_scripts, Image(), "dump_table_a.js", p=p)["initError"] is None


def test_agents_refuse_to_start_without_any_parameters(node_scripts):
    out = run_agent(node_scripts, Image(), "dump_table_a.js", p=None)
    assert "no parameters" in out["initError"]


def test_the_module_to_wait_for_comes_from_the_profile(node_scripts):
    image = Image()
    expected = image.put_record("TableARecord", RECORD_BASE)
    p = {**params(), "module": "libil2cpp.so"}
    out = run_agent(node_scripts, image, "dump_table_a.js", _record_events(1), p=p, moduleName="libil2cpp.so")
    assert out["rpc"] == {"count": 1, "records": [expected]}


@pytest.mark.parametrize("agent", sorted([*ALL_AGENTS, "list_il2cpp_exports.js"]))
def test_no_agent_assumes_a_platform_when_the_profile_names_no_module(node_scripts, agent):
    # UnityFramework is an iOS name; libil2cpp.so is Android's. An agent that fell back to
    # either would wait forever on the other platform, saying nothing.
    p = params()
    del p["module"]
    out = run_agent(node_scripts, Image(), agent, p=p)
    assert "no `module`" in out["initError"] and "libil2cpp.so" in out["initError"]
    assert out["attached"] == []


@pytest.mark.parametrize("bad", ["", None, 5])
def test_a_module_that_is_not_a_name_is_refused_too(node_scripts, bad):
    out = run_agent(node_scripts, Image(), "dump_table_a.js", p={**params(), "module": bad})
    assert "no `module`" in out["initError"]


def test_a_module_that_never_loads_is_called_out_with_what_does_load(node_scripts):
    # A wrong name looks exactly like "not loaded yet": say so after a while, and name the
    # loaded modules that look like the runtime so the fix is one flag away.
    out = run_agent(node_scripts, Image(), "dump_table_a.js", moduleAlreadyLoaded=False,
                    moduleNeverLoads=True, otherModules=["libil2cpp.so", "libc.so"], fireTimers=True)
    assert out["timers"] == [{"ms": 20000, "cleared": False}]
    [warning] = [line for line in out["log"] if "still not loaded" in line]
    assert "libil2cpp.so" in warning and "libc.so" not in warning and "--module" in warning


def test_the_wait_warning_without_any_candidate_names_the_platforms(node_scripts):
    out = run_agent(node_scripts, Image(), "dump_table_a.js", moduleAlreadyLoaded=False,
                    moduleNeverLoads=True, otherModules=["libc.so"], fireTimers=True)
    [warning] = [line for line in out["log"] if "still not loaded" in line]
    assert "No loaded module looks like" in warning and "UnityFramework on iOS, libil2cpp.so on Android" in warning


def test_the_wait_warning_names_a_windows_runtime_too(node_scripts):
    # GameAssembly.dll has neither "il2cpp" nor "unity" in its name; the hint's filter used to miss it.
    out = run_agent(node_scripts, Image(), "dump_table_a.js", moduleAlreadyLoaded=False,
                    moduleNeverLoads=True, otherModules=["GameAssembly.dll", "kernel32.dll"], fireTimers=True)
    [warning] = [line for line in out["log"] if "still not loaded" in line]
    assert "GameAssembly.dll" in warning and "kernel32.dll" not in warning
    out = run_agent(node_scripts, Image(), "dump_table_a.js", moduleAlreadyLoaded=False,
                    moduleNeverLoads=True, otherModules=["kernel32.dll"], fireTimers=True)
    [warning] = [line for line in out["log"] if "still not loaded" in line]
    assert "GameAssembly.dll on Windows" in warning


def test_the_wait_warning_is_cancelled_when_the_module_does_load(node_scripts):
    out = run_agent(node_scripts, Image(), "dump_table_a.js", moduleAlreadyLoaded=False, fireTimers=True)
    assert out["timers"] == [{"ms": 20000, "cleared": True}]
    assert not any("still not loaded" in line for line in out["log"])
    assert len(out["attached"]) == 1


def test_no_timer_is_started_for_a_module_that_is_already_loaded(node_scripts):
    out = run_agent(node_scripts, Image(), "dump_table_a.js", fireTimers=True)
    assert out["timers"] == [] and len(out["attached"]) == 1


@pytest.mark.parametrize("rname", RPC_AGENTS)
def test_rpc_agent_skips_a_failed_unpack(node_scripts, rname):
    image = Image()
    image.put_record(rname, RECORD_BASE)
    out = run_agent(node_scripts, image, RPC_AGENTS[rname][0],
                    [{"hook": 0, "args": [RECORD_BASE], "retval": 1}])
    assert out["rpc"]["count"] == 0
    assert any(line.startswith("[skip]") for line in out["log"])


def test_table_b_agent_keeps_same_id_records_of_different_kinds(node_scripts):
    image = Image()
    a = image.put_record("TableBRecord", RECORD_BASE, salt=1, id=77, kind=1)
    b = image.put_record("TableBRecord", RECORD_BASE + RECORD_STRIDE, salt=2, id=77, kind=2)
    out = run_agent(node_scripts, image, "dump_table_b.js", _record_events(2))
    assert out["rpc"] == {"count": 2, "records": [a, b]}
    log = "\n".join(out["log"])
    assert "key=1:77 " in log and "key=2:77 " in log     # the layout's key order: kind, then id


def test_the_key_comes_from_the_profile_not_from_the_agent(node_scripts):
    # Same two records; a profile that keys TableBRecord on `id` alone merges them.
    image = Image()
    image.put_record("TableBRecord", RECORD_BASE, salt=1, id=77, kind=1)
    second = image.put_record("TableBRecord", RECORD_BASE + RECORD_STRIDE, salt=2, id=77, kind=2)
    raw = copy.deepcopy(RAW)
    raw["records"]["TableBRecord"]["key"] = ["id"]
    p = {**params(), "layouts": layouts.for_agent(layouts.validate(raw))}
    out = run_agent(node_scripts, image, "dump_table_b.js", _record_events(2), p=p)
    assert out["rpc"] == {"count": 1, "records": [second]}


def test_table_a_agent_keys_on_id_alone(node_scripts):
    # TableARecord's key is ["id"]: a second record with the same id but other
    # contents replaces the first one (and is reported), it doesn't add a row.
    image = Image()
    image.put_record("TableARecord", RECORD_BASE, salt=1, id=5)
    second = image.put_record("TableARecord", RECORD_BASE + RECORD_STRIDE, salt=2, id=5)
    out = run_agent(node_scripts, image, "dump_table_a.js", _record_events(2))
    assert out["rpc"] == {"count": 1, "records": [second]}
    assert any("key 5 re-sent with DIFFERENT contents" in line for line in out["log"])


def test_trace_agent_prints_only_the_subset(node_scripts):
    image = Image()
    full = image.put_record(SUBSET["of"], RECORD_BASE, salt=3)
    expected = {n: full[n] for n in SUBSET["fields"]}
    lookup_key = image.put_string("example-key-9")
    out = run_agent(node_scripts, image, "trace_lookup.js", [
        {"hook": 0, "args": [lookup_key, 0, 5], "retval": RECORD_BASE},
        {"hook": 1, "retval": RECORD_BASE},
        {"hook": 1, "retval": 0},
    ])
    assert out["rpc"] is None                       # console-only agent: no getCount/getRecords
    log = "\n".join(out["log"])
    assert 'key="example-key-9" kind=5' in log
    assert json.loads(re.search(r"-> (\{.*\})", log).group(1)) == expected
    finals = re.findall(r"FINAL RESULT: (\{.*\}|NULL) =====", log)
    assert [json.loads(f) if f != "NULL" else None for f in finals] == [expected, None]


def test_rpc_agent_installs_after_the_module_observer_fires(node_scripts):
    image = Image()
    expected = image.put_record("TableARecord", RECORD_BASE)
    out = run_agent(node_scripts, image, "dump_table_a.js", _record_events(1), moduleAlreadyLoaded=False)
    assert out["rpc"] == {"count": 1, "records": [expected]}
    assert any("not loaded yet" in line for line in out["log"])


def test_rpc_agent_matches_module_by_basename_when_name_is_a_path(node_scripts):
    image = Image()
    expected = image.put_record("TableARecord", RECORD_BASE)
    out = run_agent(node_scripts, image, "dump_table_a.js", _record_events(1),
                    moduleByNameThrows=True, moduleName="/var/containers/Bundle/UnityFramework",
                    modulePath="/var/containers/Bundle/UnityFramework")
    assert out["rpc"] == {"count": 1, "records": [expected]}


# ---------------------------------------------------------------------------
# scripts/ holds no target value
# ---------------------------------------------------------------------------

# The one hex literal allowed anywhere in scripts/ above 0xfff: the 32-bit mask
# in unpackFailed(). Everything else - an RVA, a field offset - arrives in init().
ALLOWED_BIG_HEX = {"0xffffffff"}


def test_no_script_contains_an_address_a_field_offset_or_a_constant_for_one():
    offenders = []
    for path in sorted(SCRIPTS_DIR.glob("*.js")):
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"\b0[xX][0-9a-fA-F]+\b", text):
            lit = m.group(0).lower()
            if int(lit, 16) > 0xfff and lit not in ALLOWED_BIG_HEX:
                offenders.append(f"{path.name}: {m.group(0)}")
        for m in re.finditer(r"\b(?:FRIDA_OFFSET|OFFSET_\w+)\b", text):
            offenders.append(f"{path.name}: {m.group(0)}")
        for _ in re.finditer(r"\.add\(\s*0[xX]", text):
            offenders.append(f"{path.name}: hard-coded .add(0x...)")
    assert not offenders, "values belong in the profile, not in scripts/: " + "; ".join(offenders)


def test_every_entry_point_takes_its_configuration_through_init():
    entry_points = [p for p in sorted(SCRIPTS_DIR.glob("*.js")) if not p.name.startswith("_")]
    assert {p.name for p in entry_points} == {"dump_table_a.js", "dump_table_b.js", "probe_record.js",
                                              "trace_lookup.js", "list_il2cpp_exports.js", "verify_hook.js",
                                              "snapshot_records.js"}
    for p in entry_points:
        assert "init: agentInit(" in p.read_text(encoding="utf-8"), p.name


def test_the_example_profile_is_a_template_not_a_target():
    assert PROFILE.target == "com.example.unitygame"
    assert set(PROFILE.offsets.values()) == {0}
    assert set(PROFILE.offsets) == set(BASE_OFFSETS)           # every key an agent asks for is listed
