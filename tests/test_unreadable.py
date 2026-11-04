"""
Tests for two things the exported data and the drivers used to get wrong.

1. A read error must not look like data. readIl2CppString() returns
   "<unexpected len: -1>" / "<read error: ...>" instead of throwing (so one bad
   string can't abort the rest of a record), and those used to travel into the
   exported JSON next to real strings. Now the dump agents export the field as
   null and name it in `_unreadable: [...]` on the record, the driver lists
   those records by key in `meta`, and the layout check still sees the original
   failures (it counts them; the tolerance is unchanged). Pinned here:

     - sealUnreadable() on its own (scripts/_lib.js, through the Node harness);
     - the real dump agents, table_a and table_b (composite key), against a fake
       process image with unmapped pointers and absurd lengths in it - including
       the case that used to slip by: a few bad strings under the tolerance,
       verdict `ok`, nothing in the file telling them from data;
     - getUnreadable(), and that a later clean read of a record clears it;
     - the driver's report (`meta.unreadable_count` / `meta.unreadable_records`,
       console lines, the caps, the fallback for an agent without
       getUnreadable(), and that --no-layout-check doesn't hide it);
     - `_unreadable` can't be a field name in a layout, and the name is the same
       in JS and Python.

2. run_dump.py only exports from an agent that collects (dump_table_a.js,
   dump_table_b.js). trace_lookup.js and probe_record.js only print, yet their
   headers sent you to run_dump.py and the failure came after you had used the
   app and pressed Enter (exit status 0, no file). Now the driver checks before
   resuming the app, kills it, says what to run instead and exits non-zero; the
   headers say the same; and `profiles.py params` takes the --offset / --module
   overrides the drivers have, so those two agents are not second-class under
   `frida -P`.

Run from the repo root:

    pytest
"""
import copy
import json
import re
import struct
import sys
from pathlib import Path

import pytest

from retk import layout_check
from retk import layouts
from retk import profiles
from fake_frida import FakeDevice, FakeExports, FakeSession, make_frida_module
from stub_import import import_fresh
from node_support import SCRIPTS_DIR, run_harness
from test_canary import A_OFFSETS, STRING_AT, Table, judged, run
from test_layouts import RAW, RECORD_BASE as B_BASE, RECORDS, SCHEMA, Image, _record_events, params as all_params, run_agent

EXAMPLE = str(Path(__file__).resolve().parent.parent / "profile.example.json")
BAD_LEN = "<unexpected len: -1>"


# ---------------------------------------------------------------------------
# helpers: break a string in the fake process image
# ---------------------------------------------------------------------------

def _name_pointer(table, index):
    return struct.unpack_from("<Q", table.mem, table.bases[index] + A_OFFSETS["name"])[0]


def bad_length(table, index, length=-1):
    """Record `index`'s `name` string now claims an absurd length."""
    struct.pack_into("<i", table.mem, _name_pointer(table, index) + STRING_AT["length_offset"], length)


def unmapped(table, index):
    """Record `index`'s `name` pointer now points outside the process image."""
    struct.pack_into("<Q", table.mem, table.bases[index] + A_OFFSETS["name"], 0x100000)


def exported_text(out):
    return json.dumps(out["rpc"]["records"], ensure_ascii=False)


# ---------------------------------------------------------------------------
# sealUnreadable() on its own
# ---------------------------------------------------------------------------

def seal(node_scripts, *records):
    return run_harness(node_scripts, b"", mode="seal", records=list(records))


def test_seal_leaves_a_clean_record_exactly_as_it_was(node_scripts):
    rec = {"id": 1, "weight": -5, "enabled": 0, "name": "fine", "other": None}
    [sealed] = seal(node_scripts, rec)
    assert sealed == rec and "_unreadable" not in sealed


def test_seal_nulls_both_failure_placeholders_and_names_them(node_scripts):
    rec = {"id": 9, "a": BAD_LEN, "b": "<read error: access violation accessing 0x100000>", "c": "ok"}
    [sealed] = seal(node_scripts, rec)
    assert sealed == {"id": 9, "a": None, "b": None, "c": "ok", "_unreadable": ["a", "b"]}


def test_seal_keeps_a_string_that_merely_looks_like_markup(node_scripts):
    rec = {"id": 1, "name": "<b>bold</b>", "other": "<unexpected>"}
    [sealed] = seal(node_scripts, rec)
    assert sealed == rec


def test_the_key_is_the_one_layouts_reserve(node_scripts):
    info = run_harness(node_scripts, b"", mode="info")
    assert layouts.RESERVED_FIELD_NAMES == (info["unreadableKey"],)


def test_a_layout_cannot_use_the_reserved_name_for_a_field():
    raw = copy.deepcopy(RAW)
    weight = next(f for f in raw["records"]["TableARecord"]["fields"] if f["name"] == "weight")
    weight["name"] = layouts.RESERVED_FIELD_NAMES[0]
    with pytest.raises(layouts.SchemaError, match="reserved"):
        layouts.validate(raw)


# ---------------------------------------------------------------------------
# the real dump agents
# ---------------------------------------------------------------------------

def test_a_bad_length_is_null_and_named_in_its_record(node_scripts):
    table = Table().add_good(6)
    bad_length(table, 2)                                    # record id 3
    out = run(node_scripts, table)
    recs = out["rpc"]["records"]
    assert recs[2] == {"id": 3, "weight": -15, "enabled": 1, "name": None, "_unreadable": ["name"]}
    assert all("_unreadable" not in r for i, r in enumerate(recs) if i != 2)
    assert [r["name"] for i, r in enumerate(recs) if i != 2] == [f"name-{i}" for i in (1, 2, 4, 5, 6)]


def test_an_unmapped_pointer_is_null_and_named_too(node_scripts):
    table = Table().add_good(4)
    unmapped(table, 1)                                      # record id 2
    out = run(node_scripts, table)
    assert out["rpc"]["records"][1] == {"id": 2, "weight": -10, "enabled": 0, "name": None,
                                        "_unreadable": ["name"]}
    # what the driver sees must not be the error text under another name
    assert "<read error" not in exported_text(out) and "<unexpected len" not in exported_text(out)


def test_a_null_pointer_is_null_but_not_unreadable(node_scripts):
    table = Table().add_good(2)
    table.add(3, weight=-1, enabled=1, name=None)           # an unset field is a legitimate null
    out = run(node_scripts, table)
    assert out["rpc"]["records"][2]["name"] is None
    assert all("_unreadable" not in r for r in out["rpc"]["records"])
    assert out["unreadable"] == []


def test_the_canary_still_counts_what_the_export_no_longer_shows(node_scripts):
    table = Table().add_good(6)
    bad_length(table, 2)
    out = run(node_scripts, table)
    [rec] = out["health"]["records"]
    assert rec["fields"]["name"]["bad"] == 1
    assert rec["fields"]["name"]["examples"] == [f"unreadable ({BAD_LEN})"]
    assert judged(out).status == layout_check.FAIL                        # 1 of 6, over 5 %
    assert judged(out, tolerance=0.2).status == layout_check.OK           # the tolerance is unchanged


def test_a_few_bad_strings_under_the_tolerance_are_no_longer_indistinguishable_from_data(node_scripts):
    # The case that motivated all of this: 2 of 41 is under the 5 % tolerance, the
    # verdict is `ok`, and the file used to hold "<unexpected len: -1>" as a name.
    table = Table().add_good(41)
    bad_length(table, 6)
    bad_length(table, 29)
    out = run(node_scripts, table)
    assert judged(out).status == layout_check.OK
    assert any("2 of 41" in n for n in judged(out).notes)
    flagged = [r["id"] for r in out["rpc"]["records"] if r.get("_unreadable")]
    assert flagged == [7, 30]
    assert "<unexpected len" not in exported_text(out)
    assert out["unreadable"] == [{"key": 7, "fields": ["name"]}, {"key": 30, "fields": ["name"]}]


def test_get_unreadable_is_empty_for_a_clean_table(node_scripts):
    out = run(node_scripts, Table().add_good(5))
    assert out["unreadable"] == []


def test_a_later_clean_read_of_a_record_clears_it_and_a_later_bad_one_sets_it(node_scripts):
    # Two reads of the same key (same id): the store keeps the latest, and so must the list.
    bad_first = Table()
    bad_first.add(1, name="x")
    bad_first.add(1, name="y")
    bad_length(bad_first, 0)
    out = run(node_scripts, bad_first)
    assert out["rpc"]["count"] == 1 and out["unreadable"] == []

    good_first = Table()
    good_first.add(1, name="x")
    good_first.add(1, name="y")
    bad_length(good_first, 1)
    out = run(node_scripts, good_first)
    assert out["rpc"]["count"] == 1
    assert out["unreadable"] == [{"key": 1, "fields": ["name"]}]


def test_table_b_reports_its_composite_key(node_scripts):
    image = Image()
    image.put_record("TableBRecord", B_BASE, salt=1, id=77, kind=1)
    clean = image.put_record("TableBRecord", B_BASE + 0x200, salt=2, id=77, kind=2)
    field = next(f for f in RECORDS["TableBRecord"]["fields"] if f["type"] == "string")
    pointer = struct.unpack_from("<Q", image.mem, B_BASE + field["offset"])[0]
    struct.pack_into("<i", image.mem, pointer + SCHEMA["string"]["length_offset"], -1)

    out = run_agent(node_scripts, image, "dump_table_b.js", _record_events(2), p=all_params())
    first, second = out["rpc"]["records"]
    assert first[field["name"]] is None and first["_unreadable"] == [field["name"]]
    assert second == clean
    assert out["unreadable"] == [{"key": "1:77", "fields": [field["name"]]}]


# ---------------------------------------------------------------------------
# the driver: reporting unreadable records
# ---------------------------------------------------------------------------

@pytest.fixture
def driver(tmp_path, monkeypatch):
    """retk dump against a stub frida; install(session) -> device, argv(*extra) adds flags."""
    holder = {}
    monkeypatch.setitem(sys.modules, "frida", make_frida_module(holder))
    module = import_fresh(monkeypatch, "run_dump")

    agent = tmp_path / "agent.js"
    agent.write_text("// agent\n", encoding="utf-8")
    out = tmp_path / "records_test.json"
    monkeypatch.setattr("builtins.input", lambda *_: "")

    def argv(*extra):
        monkeypatch.setattr(sys, "argv", ["run_dump.py", "--agent", str(agent), "--out", str(out),
                                          "--target", "com.example.app", "--module", "UnityFramework",
                                          "--offset", "table_a=0x1234", *extra])

    def install(session):
        holder["device"] = FakeDevice(session)
        return holder["device"]

    argv()
    install.argv = argv
    yield module, install, out


def serve(monkeypatch, records, unreadable=None):
    """Make the stub agent hand over `records` (and getUnreadable() = `unreadable`; None: an agent without it)."""
    monkeypatch.setattr(FakeExports, "get_count", lambda self: len(records))
    monkeypatch.setattr(FakeExports, "get_records", lambda self: records)
    if unreadable is None:
        def missing(self):
            raise RuntimeError("unable to find method 'getUnreadable'")
        monkeypatch.setattr(FakeExports, "get_unreadable", missing, raising=False)
    else:
        monkeypatch.setattr(FakeExports, "get_unreadable", lambda self: unreadable, raising=False)


def test_the_key_name_is_the_same_in_the_driver(driver):
    module, _, _ = driver
    assert module.UNREADABLE_KEY == layouts.RESERVED_FIELD_NAMES[0]


def test_unreadable_records_are_named_in_meta_and_on_the_console(driver, monkeypatch, capsys):
    module, install, out = driver
    serve(monkeypatch,
          [{"id": 1, "name": None, "_unreadable": ["name"]}, {"id": 2, "name": "ok"}],
          unreadable=[{"key": 1, "fields": ["name"]}])
    install(FakeSession())

    module.main()

    meta = json.loads(out.read_text(encoding="utf-8"))["meta"]
    assert meta["unreadable_count"] == 1
    assert meta["unreadable_records"] == [{"key": 1, "fields": ["name"]}]
    text = capsys.readouterr().out
    assert "1 of 2 record(s) have string field(s) the agent could not read" in text
    assert "key 1: name" in text


def test_a_clean_dump_says_nothing_and_records_zero(driver, monkeypatch, capsys):
    module, install, out = driver
    serve(monkeypatch, [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}], unreadable=[])
    install(FakeSession())

    module.main()

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["meta"]["unreadable_count"] == 0 and data["meta"]["unreadable_records"] == []
    assert "could not read" not in capsys.readouterr().out
    assert all("_unreadable" not in r for r in data["records"])


def test_an_agent_built_before_get_unreadable_is_still_reported_from_the_records(driver, monkeypatch, capsys):
    module, install, out = driver
    serve(monkeypatch, [{"id": 5, "name": None, "_unreadable": ["name"]}, {"id": 6, "name": "ok"}])
    install(FakeSession())

    module.main()

    meta = json.loads(out.read_text(encoding="utf-8"))["meta"]
    assert meta["unreadable_count"] == 1
    assert meta["unreadable_records"] == [{"key": None, "fields": ["name"]}]
    assert "key unknown: agent too old" in capsys.readouterr().out


def test_skipping_the_layout_check_does_not_hide_unreadable_records(driver, monkeypatch, capsys):
    module, install, out = driver
    serve(monkeypatch, [{"id": 1, "name": None, "_unreadable": ["name"]}],
          unreadable=[{"key": 1, "fields": ["name"]}])
    install(FakeSession())
    install.argv("--no-layout-check")

    module.main()

    assert json.loads(out.read_text(encoding="utf-8"))["meta"]["unreadable_count"] == 1
    assert "key 1: name" in capsys.readouterr().out


def test_meta_and_console_are_capped_but_the_count_is_exact(driver, monkeypatch, capsys):
    module, install, out = driver
    entries = [{"key": i, "fields": ["name"]} for i in range(150)]
    serve(monkeypatch, [{"id": i, "name": None, "_unreadable": ["name"]} for i in range(150)], unreadable=entries)
    install(FakeSession())

    module.main()

    meta = json.loads(out.read_text(encoding="utf-8"))["meta"]
    assert meta["unreadable_count"] == 150
    assert meta["unreadable_records"] == entries[:module.UNREADABLE_IN_META]
    text = capsys.readouterr().out
    assert text.count("      - key ") == module.UNREADABLE_PRINTED
    assert f"and {150 - module.UNREADABLE_PRINTED} more" in text


# ---------------------------------------------------------------------------
# the driver: an agent that can't be exported from
# ---------------------------------------------------------------------------

def test_an_agent_without_get_count_is_refused_before_the_app_runs(driver, monkeypatch):
    module, install, out = driver

    def missing(self):
        raise RuntimeError("unable to find method 'getCount'")
    monkeypatch.setattr(FakeExports, "get_count", missing)
    session = FakeSession()
    device = install(session)

    with pytest.raises(SystemExit) as stop:
        module.main()

    message = str(stop.value)
    assert "getCount" in message and "frida -P" in message and "retk profile" in message
    assert device.calls == ["spawn", "attach", "kill"]            # never resumed, and not left frozen
    assert session.detached
    assert not out.exists()


def test_a_dump_agent_is_not_slowed_or_refused(driver):
    module, install, out = driver
    session = FakeSession()
    device = install(session)

    module.main()

    assert device.calls == ["spawn", "attach", "resume"]
    assert out.exists()


# ---------------------------------------------------------------------------
# `profiles.py params` takes the drivers' overrides
# ---------------------------------------------------------------------------

def test_params_takes_offset_and_module_overrides(capsys):
    assert profiles.main(["params", EXAMPLE, "--offset", "probe=0x40", "--offset", "lookup_by_pattern=70",
                          "--module", "libil2cpp.so"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed == profiles.agent_params(profiles.load(EXAMPLE), module="libil2cpp.so",
                                            offsets={"probe": 0x40, "lookup_by_pattern": 0x70})
    assert printed["offsets"]["probe"] == 0x40 and printed["offsets"]["lookup_by_pattern"] == 0x70
    assert printed["offsets"]["table_a"] == 0                    # the others stay as the profile has them


def test_params_rejects_a_malformed_override(capsys):
    with pytest.raises(SystemExit) as stop:
        profiles.main(["params", EXAMPLE, "--offset", "probe"])
    assert stop.value.code == 2
    assert "KEY=HEX" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# the agents' own headers
# ---------------------------------------------------------------------------

def _entry_points():
    return {p.name: p.read_text(encoding="utf-8")
            for p in sorted(SCRIPTS_DIR.glob("*.js")) if not p.name.startswith("_")}


def test_exactly_the_dump_agents_and_the_snapshot_agent_collect_what_run_dump_exports():
    collecting = {name for name, text in _entry_points().items() if "...rpcExports" in text}
    assert collecting == {"dump_table_a.js", "dump_table_b.js", "snapshot_records.js"}


def test_no_agent_that_only_prints_tells_you_to_run_it_through_run_dump():
    for name, text in _entry_points().items():
        if "...rpcExports" in text:
            continue
        assert not re.search(r"(?<!NOT )through retk dump", text), name


@pytest.mark.parametrize("name", ["trace_lookup.js", "probe_record.js"])
def test_the_two_agents_without_a_driver_say_how_to_run_them(name):
    text = _entry_points()[name]
    assert "NOT through retk dump" in text
    assert "retk profile params" in text and "frida -R" in text
