"""
The Python side of looking things up by name: the profile's `names` section, what the drivers hand
the agent, how run_dump.py reports where each hook point came from, and how layout_check.py judges
the field offsets the runtime reported.

  * profiles.parse_names / agent_params: a malformed `names` is refused naming where, an `--offset`
    on the command line beats the name for that key, `--resolve rva` hides the names, `--resolve names`
    with nothing to look up is an error before the app is spawned;
  * _common.resolve_settings prints what it resolved - including which hook points have a name and
    which have no RVA to fall back to;
  * run_dump: `meta.offsets` records the RVAs that were HOOKED (the name's, not the profile's, when they
    differ), `meta.resolution` the evidence, and a run where a hook point ended with no address exits 4;
  * layout_check: one field offset the runtime contradicts fails the layout check whatever the
    tolerance; confirmed offsets are noted; ones the runtime could not be asked about never decide.

Run from the repo root:

    pytest tests/test_names_driver.py
"""
import argparse
import copy
import json
import sys
from pathlib import Path

import pytest

from retk import _common as common
from retk import il2cpp_names
from retk import layout_check
from retk import profiles
from fake_frida import FakeDevice, FakeExports, FakeSession, make_frida_module
from stub_import import import_fresh
from test_layout_check import health, record

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "profile.example.json"
RAW = json.loads(EXAMPLE.read_text(encoding="utf-8"))
NS = "ExampleNamespace"


def write(tmp_path, raw, name="p.json"):
    path = tmp_path / name
    path.write_text(json.dumps(raw), encoding="utf-8")
    return str(path)


def with_names(names, **extra):
    raw = copy.deepcopy(RAW)
    raw["names"] = names
    raw.update(extra)
    return raw


def load(tmp_path, names, **extra):
    return profiles.load(write(tmp_path, with_names(names, **extra)))


# ---------------------------------------------------------------------------
# the names section
# ---------------------------------------------------------------------------

def test_the_example_profile_carries_names_for_every_hook_point_and_a_field_map():
    p = profiles.load(EXAMPLE)
    assert set(p.names["methods"]) == {"table_a", "table_b", "probe", "lookup_by_pattern", "resolve_default"}
    assert p.names["methods"]["table_a"] == il2cpp_names.parse_method_spec(f"{NS}.ExampleTableA::Unpack/1")
    assert p.names["methods"]["resolve_default"].assembly == "Assembly-CSharp"
    assert p.names["fields"]["TableARecord"]["map"] == {"id": "id", "weight": "weight", "enabled": "enabled", "name": "label"}


def test_a_profile_without_names_has_none(tmp_path):
    raw = copy.deepcopy(RAW)
    del raw["names"]
    assert profiles.load(write(tmp_path, raw)).names == {}


def test_names_may_hold_only_some_of_the_three_parts(tmp_path):
    p = load(tmp_path, {"exports": {"il2cpp_class_from_name": "renamed_export"}})
    assert p.names == {"methods": {}, "fields": {}, "exports": {"il2cpp_class_from_name": "renamed_export"}, "snapshot": {}}


@pytest.mark.parametrize("names, match", [
    ([], "names must be an object"),
    ({"method": {}}, "unknown key"),
    ({"methods": {"bad key": f"{NS}.A::M"}}, "not an offsets key"),
    ({"methods": {"table_a": "Unpack"}}, r"names\.methods\.table_a"),
    ({"methods": {"table_a": {"class": f"{NS}.A"}}}, r"names\.methods\.table_a"),
    ({"fields": {"TableARecord": {"class": f"{NS}.A"}}}, "needs at least one"),
    ({"fields": {"TableARecord": {"class": f"{NS}.A", "map": {}}}}, "needs at least one"),
    ({"fields": {"TableARecord": {"class": f"{NS}.A", "map": {"id": ""}}}}, "non-empty string"),
    ({"fields": {"TableARecord": {"class": f"{NS}.A", "map": {"nope": "x"}}}}, "not a field of the layout's TableARecord"),
    ({"fields": {"NoSuchRecord": {"class": f"{NS}.A", "map": {"id": "id"}}}}, "define no record 'NoSuchRecord'"),
    ({"fields": {"TableARecord": {"class": f"{NS}.A", "map": {"id": "id"}, "typo": 1}}}, "expected"),
    ({"exports": {"il2cpp_made_up": "x"}}, "not an IL2CPP function this toolkit calls"),
    ({"exports": {"il2cpp_class_from_name": ""}}, "non-empty string"),
])
def test_a_malformed_names_section_is_refused_naming_where(tmp_path, names, match):
    with pytest.raises(profiles.ProfileError, match=match):
        load(tmp_path, names)


# ---------------------------------------------------------------------------
# what the agent receives
# ---------------------------------------------------------------------------

def test_agent_params_carry_the_names_as_the_agent_reads_them():
    params = profiles.agent_params(profiles.load(EXAMPLE))
    assert params["names"]["methods"]["table_a"] == {"namespace": NS, "class": "ExampleTableA",
                                                     "method": "Unpack", "args": 1}
    assert params["names"]["fields"]["TableARecord"]["map"]["name"] == "label"
    assert "resolve" not in params                       # the agent's default (auto) is not restated


def test_an_rva_given_on_the_command_line_beats_the_name_for_that_key_only():
    params = profiles.agent_params(profiles.load(EXAMPLE), offsets={"table_a": 0x40})
    assert params["offsets"]["table_a"] == 0x40
    assert "table_a" not in params["names"]["methods"]   # probing --offset must hook exactly that address
    assert "table_b" in params["names"]["methods"]


def test_resolve_rva_sends_no_names_at_all_but_says_so():
    params = profiles.agent_params(profiles.load(EXAMPLE), resolve="rva")
    assert "names" not in params and params["resolve"] == "rva"


def test_resolve_names_and_auto_are_passed_through():
    p = profiles.load(EXAMPLE)
    assert profiles.agent_params(p, resolve="names")["resolve"] == "names"
    assert profiles.agent_params(p, resolve="auto")["resolve"] == "auto"


def test_resolve_names_with_nothing_to_look_up_is_an_error_before_anything_is_spawned(tmp_path):
    p = load(tmp_path, {"fields": {"TableARecord": {"class": f"{NS}.A", "map": {"id": "id"}}}})
    with pytest.raises(profiles.ProfileError, match="--resolve names needs"):
        profiles.agent_params(p, resolve="names")
    # also when every named key was overridden by an --offset
    every = {k: 0x10 for k in profiles.load(EXAMPLE).names["methods"]}
    with pytest.raises(profiles.ProfileError, match="--resolve names needs"):
        profiles.agent_params(profiles.load(EXAMPLE), offsets=every, resolve="names")


def test_an_unknown_resolve_mode_is_refused():
    with pytest.raises(profiles.ProfileError, match="resolve must be one of auto, names, rva"):
        profiles.agent_params(profiles.load(EXAMPLE), resolve="guess")


def test_a_profile_with_no_names_sends_exactly_what_it_always_sent(tmp_path):
    raw = copy.deepcopy(RAW)
    del raw["names"]
    params = profiles.agent_params(profiles.load(write(tmp_path, raw)), offsets={"table_a": 0x40})
    assert set(params) == {"module", "offsets", "layouts"}


def test_the_params_cli_takes_resolve(capsys):
    assert profiles.main(["params", str(EXAMPLE), "--resolve", "rva"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["resolve"] == "rva" and "names" not in out


def test_the_params_cli_reports_a_resolve_error_as_a_one_line_error(capsys):
    assert profiles.main(["params", str(EXAMPLE), "--offset", "table_a=0x1", "--offset", "table_b=0x1",
                          "--offset", "probe=0x1", "--offset", "lookup_by_pattern=0x1",
                          "--offset", "resolve_default=0x1", "--resolve", "names"]) == 2
    assert "--resolve names needs" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# _common: --resolve and what resolve_settings prints
# ---------------------------------------------------------------------------

def args(**kw):
    return argparse.Namespace(**{"profile": None, "target": None, "remote": None, "module": None,
                                 "offset": None, "resolve": None, **kw})


def test_resolve_is_a_flag_only_for_the_drivers_that_ask_for_it():
    plain = argparse.ArgumentParser()
    common.add_override_args(plain)
    assert not hasattr(plain.parse_args([]), "resolve")
    named = argparse.ArgumentParser()
    common.add_override_args(named, resolve=True)
    assert named.parse_args([]).resolve is None
    assert named.parse_args(["--resolve", "names"]).resolve == "names"
    with pytest.raises(SystemExit):
        named.parse_args(["--resolve", "guess"])


def test_resolve_settings_lists_names_and_the_rva_that_is_only_a_fallback(tmp_path, capsys):
    path = write(tmp_path, with_names(
        {"methods": {"table_a": f"{NS}.ExampleTableA::Unpack/1", "table_b": f"{NS}.ExampleTableB::Unpack/1"}},
        offsets={"table_a": "0x1230", "table_b": "0x0"}))
    settings = common.resolve_settings(args(profile=path))
    out = capsys.readouterr().out
    assert "[i] name   table_a = ExampleNamespace.ExampleTableA::Unpack/1" in out
    assert "offset table_a = 0x1230  (profile, fallback when the name does not resolve)" in out
    assert "note: table_b has a name but no RVA" in out
    assert "names" in settings.params


def test_resolve_settings_says_which_resolve_mode_is_in_force(tmp_path, capsys):
    common.resolve_settings(args(profile=str(EXAMPLE), resolve="rva", offset=[("table_a", 0x40)]))
    out = capsys.readouterr().out
    assert "resolve = rva  (CLI)" in out and "name   table_a" not in out


def test_an_offset_override_is_labelled_cli_and_its_name_is_not_listed(capsys):
    common.resolve_settings(args(profile=str(EXAMPLE), offset=[("table_a", 0x40)]))
    out = capsys.readouterr().out
    assert "offset table_a = 0x40  (CLI)" in out and "name   table_a" not in out and "name   table_b" in out


def test_a_profile_without_names_prints_no_name_lines(tmp_path, capsys):
    raw = copy.deepcopy(RAW)
    del raw["names"]
    common.resolve_settings(args(profile=write(tmp_path, raw), offset=[("table_a", 0x40)]))
    out = capsys.readouterr().out
    assert "name   " not in out and "resolve =" not in out


# ---------------------------------------------------------------------------
# run_dump: reporting where each hook point came from
# ---------------------------------------------------------------------------

@pytest.fixture
def run_dump_h(monkeypatch):
    """retk dump imported against a stub frida module -> (module, holder); the holder is where the
    stub looks for the FakeDevice a test installs (see fake_frida.make_frida_module)."""
    holder = {}
    monkeypatch.setitem(sys.modules, "frida", make_frida_module(holder))
    module = import_fresh(monkeypatch, "run_dump")
    yield module, holder


@pytest.fixture
def run_dump(run_dump_h):
    return run_dump_h[0]


def method(key, source, rva=None, name=None, name_rva=None, profile_rva=None, agrees=None, reason=None):
    return {"key": key, "source": source, "rva": rva, "name": name, "name_rva": name_rva,
            "profile_rva": profile_rva, "agrees": agrees, "reason": reason}


def test_a_run_that_used_only_rvas_prints_nothing_about_names(run_dump):
    report = {"mode": "auto", "methods": [method("table_a", "rva", 0x40, profile_rva=0x40)], "fields": [], "api": {}}
    assert run_dump.render_resolution(report) == [] and run_dump.not_hooked(report) == []


def test_each_way_a_named_hook_point_can_end_is_reported(run_dump):
    report = {"methods": [
        method("a", "name", 0x1230, "Ns.C::M/1", name_rva=0x1230),
        method("b", "name", 0x1230, "Ns.C::M/1", 0x1230, profile_rva=0x9990, agrees=False),
        method("c", "rva", 0x7770, "Ns.C::M/1", profile_rva=0x7770, reason="the module does not export x"),
        method("d", "none", None, "Ns.C::M/1", reason="no method of that name")]}
    a, b1, b2, c, d = run_dump.render_resolution(report)
    assert a == "[+] a: Ns.C::M/1 -> 0x1230, asked of the IL2CPP runtime"
    assert b1.startswith("[+] b:") and b2.startswith("[!] b:") and "set offsets.b to 0x1230" in b2 and "0x9990" in b2
    assert "[i] c: hooked the profile's RVA 0x7770" in c and "the module does not export x" in c
    assert d.startswith("[!] d: NOTHING WAS HOOKED") and "no method of that name" in d
    assert run_dump.not_hooked(report) == ["d"]


def test_resolution_meta_writes_addresses_as_hex_like_meta_offsets(run_dump):
    report = {"mode": "auto", "api": {"ready": True, "why": None},
              "methods": [method("a", "name", 0x1230, "Ns.C::M", name_rva=0x1230, profile_rva=None)],
              "fields": [{"record": "R", "field": "f", "il2cpp_field": "g", "layout_offset": 0x10,
                          "runtime_offset": 0x18, "status": "mismatch"}]}
    meta = run_dump.resolution_meta(report)
    assert meta["methods"][0]["rva"] == "0x1230" and meta["methods"][0]["name_rva"] == "0x1230"
    assert meta["methods"][0]["profile_rva"] is None and meta["methods"][0]["name"] == "Ns.C::M"
    assert meta["fields"][0]["layout_offset"] == "0x10" and meta["fields"][0]["runtime_offset"] == "0x18"
    assert run_dump.resolution_meta(None) is None
    json.dumps(meta)                                    # it has to go into the export


def test_collect_resolution_tolerates_an_agent_without_the_export(run_dump):
    script = FakeSession().create_script("")
    assert run_dump.collect_resolution(script) is None          # FakeExports has no get_resolution
    script.exports_sync.get_resolution = lambda: {"methods": []}
    assert run_dump.collect_resolution(script) == {"methods": []}
    script.exports_sync.get_resolution = lambda: "garbage"
    assert run_dump.collect_resolution(script) is None


@pytest.fixture
def driver(tmp_path, monkeypatch, run_dump_h):
    run_dump, holder = run_dump_h
    agent = tmp_path / "agent.js"
    agent.write_text("// agent\n", encoding="utf-8")
    out = tmp_path / "records_test.json"
    monkeypatch.setattr("builtins.input", lambda *_: "")

    def go(report, *extra):
        session = FakeSession()
        holder["device"] = FakeDevice(session)
        monkeypatch.setattr(FakeExports, "get_resolution", lambda self: report, raising=False)
        monkeypatch.setattr(sys, "argv", ["run_dump.py", "--agent", str(agent), "--out", str(out), "--no-layout-check",
                                          "--target", "com.example.app", "--module", "UnityFramework", *extra])
        return session

    return run_dump, go, out


def test_meta_records_the_rvas_that_were_hooked_and_the_evidence(driver):
    run_dump, go, out = driver
    report = {"mode": "auto", "api": {"ready": True, "why": None}, "fields": [],
              "methods": [method("table_a", "name", 0x1230, "Ns.C::M/1", name_rva=0x1230, profile_rva=0x9990, agrees=False)]}
    go(report, "--offset", "table_b=0x50")
    run_dump.main()
    meta = json.loads(out.read_text(encoding="utf-8"))["meta"]
    assert meta["offsets"] == {"table_a": "0x1230", "table_b": "0x50"}      # the name's, not the stale 0x9990
    assert meta["resolution"]["methods"][0]["agrees"] is False and meta["resolution"]["methods"][0]["rva"] == "0x1230"


def test_an_agent_without_resolution_still_exports_with_the_profile_offsets(driver):
    run_dump, go, out = driver
    go(None, "--offset", "table_a=0x1234")
    run_dump.main()
    meta = json.loads(out.read_text(encoding="utf-8"))["meta"]
    assert meta["offsets"] == {"table_a": "0x1234"} and meta["resolution"] is None


def test_a_hook_point_with_no_address_exits_4_after_writing_the_file(driver, capsys):
    run_dump, go, out = driver
    report = {"mode": "names", "api": {"ready": True, "why": None}, "fields": [],
              "methods": [method("table_a", "none", None, "Ns.C::M/1", reason="no method of that name")]}
    session = go(report, "--offset", "table_b=0x50")
    with pytest.raises(SystemExit) as e:
        run_dump.main()
    assert e.value.code == run_dump.EXIT_NOT_HOOKED == 4
    assert out.exists() and session.detached                    # nothing is lost, nothing is left attached
    assert "NOTHING WAS HOOKED" in capsys.readouterr().out


def test_resolve_reaches_the_agent_through_the_driver(driver):
    run_dump, go, _out = driver
    session = go(None, "--profile", str(EXAMPLE), "--resolve", "rva", "--offset", "table_a=0x40")
    run_dump.main()
    [(_stage, params)] = session.script.exports_sync.inits
    assert params["resolve"] == "rva" and "names" not in params


# ---------------------------------------------------------------------------
# layout_check: the runtime's field offsets
# ---------------------------------------------------------------------------

def base_health():
    return health(record())


def row(field, status, layout=0x10, runtime=0x10, reason=None):
    return {"record": "TableARecord", "field": field, "il2cpp_field": field, "layout_offset": layout,
            "runtime_offset": None if status == "unresolved" else runtime, "status": status, "reason": reason}


def test_a_confirmed_field_offset_is_a_note_and_counts_as_a_check():
    health = {**base_health(), "field_offsets": [row("id", "match"), row("weight", "match", 0x14, 0x14)]}
    verdict = layout_check.judge(health)
    assert verdict.status != layout_check.FAIL
    assert any("2 layout field offset(s) confirmed directly by the IL2CPP runtime" in n for n in verdict.notes)


def test_one_contradicted_field_offset_fails_the_check_whatever_the_tolerance():
    health = {**base_health(), "field_offsets": [row("id", "match"), row("weight", "mismatch", 0x14, 0x18)]}
    for tolerance in (0.0, 0.05, 1.0):
        verdict = layout_check.judge(health, tolerance=tolerance)
        assert verdict.status == layout_check.FAIL
        assert any("TableARecord.weight is at 0x14 in the profile, but the IL2CPP runtime puts weight at 0x18" in p
                   for p in verdict.problems)


def test_field_offsets_the_runtime_could_not_be_asked_about_are_notes_never_problems():
    health = {**base_health(), "field_offsets": [row("id", "unresolved", reason="hidden"), row("weight", "unresolved", reason="hidden")]}
    verdict = layout_check.judge(health)
    assert verdict.problems == []
    assert any("2 layout field offset(s) could not be checked against the runtime (TableARecord.id, TableARecord.weight): hidden" in n
               for n in verdict.notes)


def test_a_health_without_field_offsets_is_judged_as_before():
    assert layout_check.judge(base_health()).notes == layout_check.judge({**base_health(), "field_offsets": []}).notes
    assert layout_check.judge({**base_health(), "field_offsets": "garbage"}).problems == []
    assert layout_check.judge({**base_health(), "field_offsets": [None, 3]}).problems == []


def test_the_failed_field_check_is_rendered_like_any_failed_layout_check():
    health = {**base_health(), "field_offsets": [row("weight", "mismatch", 0x14, 0x18)]}
    text = "\n".join(layout_check.render(layout_check.judge(health)))
    assert "LAYOUT CHECK FAILED" in text and "weight" in text
