"""
Tests for the record-layout pipeline (see tools/gen_layouts.py):

    schema/layouts.json  -->  scripts/_layouts.js      (what the agents read with)
                         -->  tools/records.py         (what the drivers annotate with)
                         -->  docs/MEMORY_LAYOUT.md    (the offset listings)

Offsets and field types are written down once, in the schema. These tests
check the parts that could still go wrong:

  * the schema itself is sane (aligned, non-overlapping, known types);
  * nothing generated is stale, and nothing hand-written restates an offset;
  * the JS side really DECODES each type the way the schema says. This is the
    part a field-name diff can't see: the agents' output is compared, field
    by field, with an independent Python decoder (`struct`) over a fake
    process image - sign, width and nullability included - so e.g.
    `u32: (p) => p.readS8()` in _lib.js fails here;
  * the real agents, run under Node with a faked Frida, export records of
    exactly those types.

The Node-backed tests skip when `node` isn't installed (fail instead when
$CI is set, so CI can't silently stop running them). Run from the repo root:

    pytest
"""
import base64
import copy
import json
import os
import re
import shutil
import struct
import subprocess
import typing
from pathlib import Path

import pytest

import check_placeholders
import gen_layouts
import records

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
HARNESS = Path(__file__).resolve().parent / "frida_harness.mjs"

RAW = json.loads(gen_layouts.SCHEMA_PATH.read_text(encoding="utf-8"))
SCHEMA = gen_layouts.load_schema()
RECORDS = SCHEMA["records"]
SUBSET = SCHEMA["subsets"]["SelectionResult"]

# The independent oracle: how the Python side says each schema type is laid
# out in memory. Deliberately NOT derived from anything in scripts/ or tools/.
PACK = {"u32": "<I", "s32": "<i", "s8": "<b", "string": "<Q"}
RANGE = {"u32": (0, 2**32 - 1), "s32": (-2**31, 2**31 - 1), "s8": (-128, 127)}


# ---------------------------------------------------------------------------
# the schema itself
# ---------------------------------------------------------------------------

def _field(raw, name, record="RecommendConfigRecord"):
    return next(f for f in raw["records"][record]["fields"] if f["name"] == name)


def _swap_first_two(raw):
    fields = raw["records"]["RecommendConfigRecord"]["fields"]
    fields[0], fields[1] = fields[1], fields[0]


BAD_SCHEMAS = {
    "misaligned": (lambda r: _field(r, "id").update(offset="0x09"), "not naturally aligned"),
    "overlapping": (lambda r: _field(r, "type").update(offset="0x08"), "overlaps"),
    "inside the header": (lambda r: _field(r, "id").update(offset="0x04"), "overlaps"),
    "unread overlaps a field": (
        lambda r: r["records"]["RecommendConfigRecord"]["unread"][0].update(offset="0x0c"), "overlaps"),
    "unsorted": (_swap_first_two, "ascending offset order"),
    "unknown type": (lambda r: _field(r, "fpsGraphicMode").update(type="u64"), "unknown type"),
    "address-sized offset": (lambda r: _field(r, "szConfig").update(offset="0x10000"), "outside 0"),
    "non-hex offset": (lambda r: _field(r, "id").update(offset="8"), "0x-prefixed"),
    "duplicate name": (lambda r: _field(r, "type").update(name="id"), "duplicate"),
    "bad identifier": (lambda r: _field(r, "id").update(name="not valid"), "identifier"),
    "subset names a missing field": (
        lambda r: r["subsets"]["SelectionResult"]["fields"].append("nope"), "not readable fields"),
    "string chars not after length": (
        lambda r: r["il2cppString"].update(charsOffset="0x10"), "right after"),
}


@pytest.mark.parametrize("case", sorted(BAD_SCHEMAS))
def test_invalid_schema_is_rejected(case):
    mutate, message = BAD_SCHEMAS[case]
    raw = copy.deepcopy(RAW)
    mutate(raw)
    with pytest.raises(gen_layouts.SchemaError, match=message):
        gen_layouts.validate(raw)


def test_offset_cap_matches_the_placeholder_checkers():
    assert gen_layouts.MAX_FIELD_OFFSET == check_placeholders.FIELD_OFFSET_MAX


# ---------------------------------------------------------------------------
# generated files: not stale, and no second copy of an offset by hand
# ---------------------------------------------------------------------------

def test_generated_files_are_up_to_date():
    wanted = gen_layouts.expected_outputs(
        SCHEMA, gen_layouts.MEMORY_LAYOUT_MD_PATH.read_text(encoding="utf-8"))
    stale = [str(p.relative_to(REPO_ROOT)) for p, text in wanted.items()
             if p.read_text(encoding="utf-8") != text]
    assert not stale, f"stale: {', '.join(stale)} - run `python tools/gen_layouts.py`"


def test_changing_a_field_type_in_the_schema_changes_the_generated_js():
    # The scenario "someone makes supportsFPS60 a s8 read": the type lives in
    # the schema, so the JS layout table changes with it - and a hand edit of
    # scripts/_layouts.js alone is caught by test_generated_files_are_up_to_date.
    raw = copy.deepcopy(RAW)
    _field(raw, "supportsFPS60")["type"] = "s8"
    changed = gen_layouts.render_layouts_js(gen_layouts.validate(raw))
    assert changed != gen_layouts.LAYOUTS_JS_PATH.read_text(encoding="utf-8")
    assert '{ name: "supportsFPS60", offset: 0x34, type: "s8" }' in changed


def test_typeddicts_have_exactly_the_schema_fields_and_python_types():
    py = {"int": int, "Optional[str]": typing.Optional[str]}
    for name, spec in list(RECORDS.items()) + list(SCHEMA["subsets"].items()):
        hints = typing.get_type_hints(getattr(records, name))
        expected = {f["name"]: py[gen_layouts.TYPES[f["type"]].py] for f in spec["fields"]}
        assert hints == expected, name


def test_agents_never_spell_out_a_field_offset():
    offenders = []
    for path in sorted(SCRIPTS_DIR.glob("*.js")):
        if path.name == "_layouts.js":
            continue
        for m in re.finditer(r"\.add\(\s*0[xX][0-9a-fA-F]+|\+0[xX][0-9a-fA-F]+",
                             path.read_text(encoding="utf-8")):
            offenders.append(f"{path.name}: {m.group(0)}")
    assert not offenders, ("offsets belong in schema/layouts.json only: " + "; ".join(offenders))


def test_memory_layout_narrative_does_not_restate_offsets():
    text = gen_layouts.strip_generated_regions(
        gen_layouts.MEMORY_LAYOUT_MD_PATH.read_text(encoding="utf-8"))
    assert not re.findall(r"\+0[xX][0-9a-fA-F]+", text)


def test_every_agent_reads_its_record_through_its_layout():
    wanted = [(spec["agent"], [f"{name}Layout"]) for name, spec in RECORDS.items() if spec["agent"]]
    wanted += [(SUBSET["agent"], [f"{SUBSET['of']}Layout", "SelectionResultFields"])]
    for agent, names in wanted:
        source = (SCRIPTS_DIR / agent).read_text(encoding="utf-8")
        assert "readRecord(" in source, agent
        for n in names:
            assert n in source, f"{agent} doesn't use {n}"


# ---------------------------------------------------------------------------
# JS decoding vs an independent Python decoder (needs node)
# ---------------------------------------------------------------------------

IMAGE_SIZE = 0x4000
RECORD_BASE, RECORD_STRIDE = 0x1000, 0x200
STRING_BASE, STRING_STRIDE = 0x3000, 0x80


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


def _require_node():
    if shutil.which("node"):
        return
    if os.environ.get("CI"):
        pytest.fail("node is required to run these tests in CI")
    pytest.skip("node is not installed")


_PLACEHOLDER_RE = re.compile(r"^(const (?:FRIDA_OFFSET|OFFSET_\w+) = )0x0;", re.M)


@pytest.fixture(scope="module")
def node_scripts(tmp_path_factory):
    """A copy of scripts/ that Node can import as ES modules, with each
    agent's zero placeholder offsets replaced (in the copy only) so the agents
    get past their 'still 0x0' guards."""
    _require_node()
    dest = tmp_path_factory.mktemp("scripts")
    (dest / "package.json").write_text('{"type": "module"}\n', encoding="utf-8")
    for src in SCRIPTS_DIR.glob("*.js"):
        counter = iter(range(0x40, 0x400, 0x10))
        text = _PLACEHOLDER_RE.sub(lambda m: f"{m.group(1)}{next(counter):#x};",
                                   src.read_text(encoding="utf-8"))
        (dest / src.name).write_text(text, encoding="utf-8")
    return dest


def run_harness(scripts_dir, image, **request):
    payload = dict(request, scriptsDir=str(scripts_dir),
                   image=base64.b64encode(bytes(image)).decode("ascii"))
    proc = subprocess.run(["node", str(HARNESS)], input=json.dumps(payload),
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


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


def test_js_readers_cover_exactly_the_schema_types(node_scripts):
    readers = run_harness(node_scripts, b"", mode="info")["readers"]
    assert set(readers) == set(gen_layouts.TYPES) == set(PACK)


@pytest.mark.parametrize("rname", list(RECORDS))
def test_js_decodes_every_field_like_the_python_oracle(node_scripts, rname):
    image = Image()
    expected = image.put_record(rname, RECORD_BASE)
    layout = f"{rname}Layout"
    [got] = run_harness(node_scripts, image.mem, mode="readRecord",
                        cases=[{"layout": layout, "base": RECORD_BASE}])
    assert got == {"ok": expected}
    assert_typed(rname, got["ok"])


def test_js_reads_a_null_string_pointer_as_null(node_scripts):
    image = Image()
    expected = image.put_record("RecommendConfigRecord", RECORD_BASE, szConfig=None)
    [got] = run_harness(node_scripts, image.mem, mode="readRecord",
                        cases=[{"layout": "RecommendConfigRecordLayout", "base": RECORD_BASE}])
    assert got["ok"]["szConfig"] is None
    assert got == {"ok": expected}


def test_js_subset_read_returns_only_the_subset(node_scripts):
    image = Image()
    full = image.put_record(SUBSET["of"], RECORD_BASE)
    names = [f["name"] for f in SUBSET["fields"]]
    [got] = run_harness(node_scripts, image.mem, mode="readRecord",
                        cases=[{"layout": f"{SUBSET['of']}Layout", "base": RECORD_BASE, "only": names}])
    assert got == {"ok": {n: full[n] for n in names}}


def test_js_rejects_a_subset_naming_a_missing_field(node_scripts):
    image = Image()
    image.put_record(SUBSET["of"], RECORD_BASE)
    [got] = run_harness(node_scripts, image.mem, mode="readRecord",
                        cases=[{"layout": f"{SUBSET['of']}Layout", "base": RECORD_BASE, "only": ["id", "nope"]}])
    assert "nope" in got["error"]


def test_js_string_reader_edge_cases(node_scripts):
    # MAX_STRING_LEN in scripts/_lib.js - keep in sync with the value there.
    # It's a runaway-read guard (misread pointer/offset), not a real content
    # limit, so this test also proves a genuinely long, valid string (well
    # past the *old* 512 cap this bound replaced) still decodes correctly -
    # that's the actual regression being covered here.
    max_string_len = 65536

    image = Image()
    length_at = SCHEMA["string"]["length_offset"]
    ok, empty = image.put_string("h\u00e9llo"), image.put_string("")
    negative, huge = image.put_string("x"), image.put_string("x")
    struct.pack_into("<i", image.mem, negative + length_at, -1)
    struct.pack_into("<i", image.mem, huge + length_at, max_string_len + 1)
    # Longer than the old 512-unit cap, comfortably under the new one, with
    # real UTF-16 content behind it (not just a poked length field like
    # `huge` above) - this is the case that used to come back as
    # "<unexpected len: 1000>" before the cap was raised.
    long_valid_text = "y" * 1000
    long_valid = image.put_string(long_valid_text)
    got = run_harness(node_scripts, image.mem, mode="string",
                      addrs=[0, ok, empty, negative, huge, long_valid, IMAGE_SIZE + 0x100])
    assert got[0] is None
    assert got[1] == "h\u00e9llo"
    assert got[2] == ""
    assert got[3] == "<unexpected len: -1>"
    assert got[4] == f"<unexpected len: {max_string_len + 1}>"
    assert got[5] == long_valid_text
    assert got[6].startswith("<read error")


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
    expected = image.put_record("RecommendConfigRecord", RECORD_BASE)
    [got] = run_harness(broken, image.mem, mode="readRecord",
                        cases=[{"layout": "RecommendConfigRecordLayout", "base": RECORD_BASE}])
    assert got != {"ok": expected}


# ---------------------------------------------------------------------------
# the real agents, under Node with a faked Frida
# ---------------------------------------------------------------------------

RPC_AGENTS = [name for name, spec in RECORDS.items() if spec["agent"]]


def _record_events(count):
    return [{"hook": 0, "args": [RECORD_BASE + i * RECORD_STRIDE], "retval": 0} for i in range(count)]


@pytest.mark.parametrize("rname", RPC_AGENTS)
def test_rpc_agent_exports_what_the_layout_decodes(node_scripts, rname):
    image = Image()
    expected = [image.put_record(rname, RECORD_BASE + i * RECORD_STRIDE, salt=i + 1) for i in range(2)]
    out = run_harness(node_scripts, image.mem, mode="agent", agent=RECORDS[rname]["agent"],
                      events=_record_events(2) + _record_events(1))   # last one re-sent
    assert out["rpc"] == {"count": 2, "records": expected}
    for rec in out["rpc"]["records"]:
        assert_typed(rname, rec)


@pytest.mark.parametrize("rname", RPC_AGENTS)
def test_rpc_agent_skips_a_failed_unpack(node_scripts, rname):
    image = Image()
    image.put_record(rname, RECORD_BASE)
    out = run_harness(node_scripts, image.mem, mode="agent", agent=RECORDS[rname]["agent"],
                      events=[{"hook": 0, "args": [RECORD_BASE], "retval": 1}])
    assert out["rpc"]["count"] == 0
    assert any(line.startswith("[skip]") for line in out["log"])


def test_recommend_config_agent_keeps_same_id_records_of_different_types(node_scripts):
    image = Image()
    a = image.put_record("RecommendConfigRecord", RECORD_BASE, salt=1, id=77, type=1)
    b = image.put_record("RecommendConfigRecord", RECORD_BASE + RECORD_STRIDE, salt=2, id=77, type=2)
    out = run_harness(node_scripts, image.mem, mode="agent",
                      agent=RECORDS["RecommendConfigRecord"]["agent"], events=_record_events(2))
    assert out["rpc"] == {"count": 2, "records": [a, b]}


def test_selection_agent_prints_only_the_subset(node_scripts):
    image = Image()
    full = image.put_record(SUBSET["of"], RECORD_BASE, salt=3)
    expected = {f["name"]: full[f["name"]] for f in SUBSET["fields"]}
    device_name = image.put_string("iPhone99,9")
    out = run_harness(node_scripts, image.mem, mode="agent", agent=SUBSET["agent"], events=[
        {"hook": 0, "args": [device_name, 0, 5], "retval": RECORD_BASE},
        {"hook": 1, "retval": RECORD_BASE},
        {"hook": 1, "retval": 0},
    ])
    assert out["rpc"] is None                       # console-only agent, no rpc.exports
    log = "\n".join(out["log"])
    assert 'deviceName="iPhone99,9" type=5' in log
    assert json.loads(re.search(r"-> (\{.*\})", log).group(1)) == expected
    finals = re.findall(r"FINAL RESULT: (\{.*\}|NULL) =====", log)
    assert [json.loads(f) if f != "NULL" else None for f in finals] == [expected, None]


def test_rpc_agent_installs_after_the_module_observer_fires(node_scripts):
    image = Image()
    expected = image.put_record("DeviceQualityRecord", RECORD_BASE)
    out = run_harness(
        node_scripts, image.mem, mode="agent",
        agent=RECORDS["DeviceQualityRecord"]["agent"],
        moduleAlreadyLoaded=False,
        events=_record_events(1),
    )
    assert out["rpc"] == {"count": 1, "records": [expected]}
    assert any("not loaded yet" in line for line in out["log"])


def test_rpc_agent_matches_module_by_basename_when_name_is_a_path(node_scripts):
    image = Image()
    expected = image.put_record("DeviceQualityRecord", RECORD_BASE)
    out = run_harness(
        node_scripts, image.mem, mode="agent",
        agent=RECORDS["DeviceQualityRecord"]["agent"],
        moduleByNameThrows=True,
        moduleName="/var/containers/Bundle/UnityFramework",
        modulePath="/var/containers/Bundle/UnityFramework",
        events=_record_events(1),
    )
    assert out["rpc"] == {"count": 1, "records": [expected]}
