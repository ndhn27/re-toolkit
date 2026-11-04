"""
scripts/_resolve.js under Node: finding what an agent hooks BY NAME, with the RVA as the fallback.

Two levels, both against the real scripts/*.js:

  * the decision logic (resolveOffsets and the lookups under it) is driven through
    tests/frida_harness.mjs's `resolve` mode with a made-up IL2CPP runtime - plain data (assemblies,
    classes, methods, fields) in place of the Frida binding. This is where every "what if" lives: the
    name resolves / does not / is ambiguous, the profile's RVA agrees / is stale / is missing, the
    runtime is up now / later / never, a field's offset agrees with the layout or not;
  * the agents themselves run through the `agent` mode, whose faked module exports nothing - which is
    exactly what a build with hidden IL2CPP exports looks like - so what an agent does when the lookup
    cannot happen (hook the profile's RVA, or refuse) is checked end to end.

What this cannot tell is whether the Frida binding (NativeFunction over the module's exports) calls the
real IL2CPP API correctly: tests/test_frida_real.py runs it against a native library that exports a small
IL2CPP of its own.

Run from the repo root:

    pytest tests/test_names_agent.py
"""
import copy

import pytest

from retk import il2cpp_names
from retk import layouts
from retk import profiles
from node_support import run_harness
from test_layouts import PROFILE, SCHEMA, Image, params, run_agent

NS = "ExampleNamespace"
UNPACK_1, UNPACK_2, MODULE_SIZE = 0x1230, 0x1300, 0x100000


def method(name, argc, rva):
    return {"name": name, "argc": argc, "rva": rva}


def make_model(**over):
    """A made-up runtime: ExampleTableA with two Unpack overloads, a nested Outer/Inner, and a class that
    exists in two assemblies."""
    table_a = {"namespace": NS, "name": "ExampleTableA",
               "methods": [method("Unpack", 1, UNPACK_1), method("Unpack", 2, UNPACK_2),
                           method("Reset", 0, 0x1400), {"name": "Abstract", "argc": 0}],
               "fields": [{"name": "id", "offset": 0x10}, {"name": "weight", "offset": 0x14},
                          {"name": "enabled", "offset": 0x18}, {"name": "label", "offset": 0x20}]}
    outer = {"namespace": NS, "name": "Outer", "methods": [],
             "nested": [{"name": "Inner", "methods": [method("Run", 0, 0x1500)]}]}
    twin = {"namespace": NS, "name": "Twin", "methods": [method("Go", 0, 0x1600)]}
    model = {"ready": "now",
             "assemblies": [{"name": "Assembly-CSharp", "classes": [table_a, outer, twin]},
                            {"name": "Other.Assembly", "classes": [copy.deepcopy(twin)]}]}
    model.update(over)
    return model


def spec(text):
    return il2cpp_names.parse_method_spec(text).as_agent()


def rparams(methods=None, offsets=None, resolve=None, fields=None, exports=None):
    p = {"module": "UnityFramework", "offsets": offsets or {}, "layouts": layouts.for_agent(SCHEMA)}
    names = {}
    if methods:
        names["methods"] = {k: spec(v) for k, v in methods.items()}
    if fields:
        names["fields"] = fields
    if exports:
        names["exports"] = exports
    if names:
        p["names"] = names
    if resolve:
        p["resolve"] = resolve
    return p


def resolve(node_scripts, p, keys=("table_a",), model=None, **request):
    out = run_harness(node_scripts, b"", mode="resolve", keys=list(keys), params=p,
                      model=model or make_model(), **request)
    assert out["error"] is None, out["error"]
    return out


def entry(out, key="table_a"):
    return next(m for m in out["resolution"]["methods"] if m["key"] == key)


def said(out, text):
    return any(text in line for line in out["log"])


# ---------------------------------------------------------------------------
# the two lists the JS and Python sides share
# ---------------------------------------------------------------------------

def test_the_api_function_list_and_the_modes_are_the_same_on_both_sides(node_scripts):
    info = run_harness(node_scripts, b"", mode="info")
    assert info["apiFunctions"] == list(il2cpp_names.API_FUNCTIONS)
    assert info["resolveModes"] == list(profiles.RESOLVE_MODES)


# ---------------------------------------------------------------------------
# the name resolves
# ---------------------------------------------------------------------------

def test_a_name_is_resolved_to_the_rva_the_runtime_reports(node_scripts):
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Unpack/1"}))
    assert out["rvas"] == [{"table_a": UNPACK_1}]
    e = entry(out)
    assert (e["source"], e["rva"], e["name_rva"], e["profile_rva"], e["agrees"]) == ("name", UNPACK_1, UNPACK_1, None, None)
    assert e["name"] == f"{NS}.ExampleTableA::Unpack/1"
    assert said(out, "from the IL2CPP runtime")


def test_the_overload_is_picked_by_its_parameter_count(node_scripts):
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Unpack/2"}))
    assert out["rvas"] == [{"table_a": UNPACK_2}]


def test_a_name_works_without_any_rva_in_the_profile(node_scripts):
    # offsets.table_a is simply absent: the name is all there is
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Reset"}, offsets={}))
    assert out["rvas"] == [{"table_a": 0x1400}]


def test_a_profile_rva_that_agrees_is_recorded_as_agreeing(node_scripts):
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Unpack/1"}, offsets={"table_a": UNPACK_1}))
    e = entry(out)
    assert (e["source"], e["agrees"]) == ("name", True)
    assert not said(out, "update the profile")


def test_a_stale_profile_rva_loses_to_the_name_and_is_reported(node_scripts):
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Unpack/1"}, offsets={"table_a": 0x9990}))
    assert out["rvas"] == [{"table_a": UNPACK_1}]            # the name's address is hooked, not the old one
    e = entry(out)
    assert (e["source"], e["agrees"], e["profile_rva"]) == ("name", False, 0x9990)
    assert said(out, "update the profile's RVA")


def test_a_nested_class_is_found_through_its_outer_class(node_scripts):
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.Outer/Inner::Run"}))
    assert out["rvas"] == [{"table_a": 0x1500}]


def test_the_assembly_can_be_named_and_settles_a_class_that_exists_twice(node_scripts):
    twice = f"{NS}.Twin::Go"
    out = resolve(node_scripts, rparams({"table_a": twice}, offsets={"table_a": 0x7770}))
    e = entry(out)
    assert e["source"] == "rva" and "exists in Assembly-CSharp, Other.Assembly" in e["reason"]   # ambiguous: not a pick
    out = resolve(node_scripts, rparams({"table_a": {"class": f"{NS}.Twin", "method": "Go", "assembly": "Other.Assembly"}}))
    assert out["rvas"] == [{"table_a": 0x1600}]
    # the assembly may be written with or without .dll, in any case
    out = resolve(node_scripts, rparams({"table_a": {"class": f"{NS}.Twin", "method": "Go", "assembly": "assembly-csharp.dll"}}))
    assert out["rvas"] == [{"table_a": 0x1600}]


# ---------------------------------------------------------------------------
# the name does not resolve: the RVA is the fallback (or there is none)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name, why", [
    (f"{NS}.ExampleTableA::Unpack", "2 overloads answer to it"),               # ambiguous, no /N
    (f"{NS}.ExampleTableA::Unpack/9", "with 1, 2 parameter(s), not 9"),
    (f"{NS}.ExampleTableA::Missing", "no method of that name"),
    (f"{NS}.Missing::Unpack/1", "is not in any loaded assembly"),
    (f"{NS}.ExampleTableA::Abstract", "no code pointer"),
    (f"{NS}.Outer/Missing::Run", "is not in any loaded assembly"),
])
def test_a_name_the_runtime_cannot_settle_falls_back_to_the_profile_rva(node_scripts, name, why):
    out = resolve(node_scripts, rparams({"table_a": name}, offsets={"table_a": 0x7770}))
    assert out["rvas"] == [{"table_a": 0x7770}]
    e = entry(out)
    assert (e["source"], e["rva"], e["name_rva"]) == ("rva", 0x7770, None)
    assert why in e["reason"]
    assert said(out, "falling back to the profile's RVA 0x7770")


def test_a_named_assembly_that_is_not_loaded_is_a_reason_not_a_crash(node_scripts):
    out = resolve(node_scripts, rparams({"table_a": {"class": f"{NS}.ExampleTableA", "method": "Reset", "assembly": "Nope"}},
                                        offsets={"table_a": 0x7770}))
    assert "no assembly named Nope is loaded" in entry(out)["reason"]


def test_a_pointer_beyond_the_module_is_refused_as_not_code_of_this_module(node_scripts):
    far = make_model()
    far["assemblies"][0]["classes"][0]["methods"][0]["rva"] = MODULE_SIZE + 0x10
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Unpack/1"}, offsets={"table_a": 0x7770}),
                  model=far, moduleSize=MODULE_SIZE)
    assert "beyond the module" in entry(out)["reason"] and out["rvas"] == [{"table_a": 0x7770}]


def test_resolve_names_never_falls_back(node_scripts):
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Missing"}, offsets={"table_a": 0x7770}, resolve="names"))
    assert out["rvas"] == []                                       # nothing was hooked
    e = entry(out)
    assert (e["source"], e["rva"]) == ("none", None) and "no method of that name" in e["reason"]
    assert said(out, 'resolve is "names", so there is no fallback') and said(out, "nothing was hooked")


def test_no_name_resolution_and_no_rva_hooks_nothing_and_says_so(node_scripts):
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Missing"}, offsets={}))
    assert out["rvas"] == [] and entry(out)["source"] == "none"
    assert said(out, "the profile has no RVA for it") and said(out, "nothing was hooked: table_a")


def test_without_a_parameter_count_the_agent_that_cannot_list_methods_says_it_could_not_rule_out_overloads(node_scripts):
    model = make_model(can={"methods": False})
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Reset"}), model=model)
    assert out["rvas"] == [{"table_a": 0x1400}]
    assert "a second overload of this name could not be ruled out" in entry(out)["reason"]
    # with /N the lookup is exact and says nothing of the kind
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Unpack/2"}), model=model)
    assert out["rvas"] == [{"table_a": UNPACK_2}] and entry(out)["reason"] is None


def test_a_module_that_can_neither_list_nor_find_methods_falls_back(node_scripts):
    model = make_model(can={"methods": False, "methodByName": False})
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Reset"}, offsets={"table_a": 0x7770}), model=model)
    assert out["rvas"] == [{"table_a": 0x7770}] and "exports neither il2cpp_class_get_methods" in entry(out)["reason"]


def test_a_nested_name_needs_the_nested_type_api(node_scripts):
    model = make_model(can={"nest": False})
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.Outer/Inner::Run"}, offsets={"table_a": 0x7770}), model=model)
    assert "nested class" in entry(out)["reason"] and out["rvas"] == [{"table_a": 0x7770}]


# ---------------------------------------------------------------------------
# when the runtime is up - and when it is not available at all
# ---------------------------------------------------------------------------

def test_nothing_is_hooked_by_name_until_the_runtime_is_up(node_scripts):
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Unpack/1"}), model=make_model(ready="later"))
    assert out["readyBefore"] == 0                                 # nothing before il2cpp_init returned...
    assert out["rvas"] == [{"table_a": UNPACK_1}]                  # ...and the hook after it


def test_hidden_exports_fall_back_to_the_profile_rva_and_say_why(node_scripts):
    hidden = {"unavailable": "the module does not export il2cpp_class_from_name - hidden"}
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Unpack/1"}, offsets={"table_a": 0x7770}),
                  model=make_model(ready=hidden))
    assert out["rvas"] == [{"table_a": 0x7770}]
    e = entry(out)
    assert (e["source"], e["rva"], e["reason"]) == ("rva", 0x7770, hidden["unavailable"])
    assert out["resolution"]["api"] == {"ready": False, "why": hidden["unavailable"]}


def test_hidden_exports_with_resolve_names_and_no_rva_hook_nothing(node_scripts):
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Unpack/1"}, resolve="names"),
                  model=make_model(ready={"unavailable": "hidden"}))
    assert out["rvas"] == [] and entry(out)["source"] == "none"


def test_resolve_rva_ignores_the_names_and_never_waits_for_the_runtime(node_scripts):
    out = resolve(node_scripts, rparams({"table_a": f"{NS}.ExampleTableA::Missing"}, offsets={"table_a": 0x7770}, resolve="rva"),
                  model=make_model(ready="later"))
    assert out["readyBefore"] == 1 and out["rvas"] == [{"table_a": 0x7770}]
    e = entry(out)
    assert (e["source"], e["name"]) == ("rva", None)               # the name was never looked at


# ---------------------------------------------------------------------------
# several hook points at once (trace_lookup.js hooks two)
# ---------------------------------------------------------------------------

KEYS2 = ("lookup_by_pattern", "resolve_default")


def test_two_keys_are_reported_to_the_agent_together_once_both_have_an_address(node_scripts):
    p = rparams({"lookup_by_pattern": f"{NS}.ExampleTableA::Unpack/1"}, offsets={"resolve_default": 0x7770})
    out = resolve(node_scripts, p, keys=KEYS2)
    assert out["rvas"] == [{"lookup_by_pattern": UNPACK_1, "resolve_default": 0x7770}]
    assert [m["source"] for m in out["resolution"]["methods"]] == ["name", "rva"]


def test_if_one_of_two_keys_has_no_address_neither_is_hooked(node_scripts):
    p = rparams({"lookup_by_pattern": f"{NS}.ExampleTableA::Missing"}, offsets={"resolve_default": 0x7770})
    out = resolve(node_scripts, p, keys=KEYS2)
    assert out["rvas"] == []                                       # half a trace is worse than none
    assert said(out, "nothing was hooked: lookup_by_pattern")


# ---------------------------------------------------------------------------
# the layout's field offsets, asked of the runtime
# ---------------------------------------------------------------------------

FIELDS = {"TableARecord": {"namespace": NS, "class": "ExampleTableA", "assembly": None,
                           "map": {"id": "id", "weight": "weight", "enabled": "enabled", "name": "label"}}}


def field_rows(out):
    return {f["field"]: f for f in out["fields"]}


def test_field_offsets_the_runtime_confirms_are_matches(node_scripts):
    # the example layout: id 0x10, weight 0x14, enabled 0x18, name 0x20 - what make_model's class says too
    out = resolve(node_scripts, rparams(offsets={"table_a": 0x40}, fields=FIELDS))
    rows = field_rows(out)
    assert {k: (r["status"], r["layout_offset"], r["runtime_offset"]) for k, r in rows.items()} == {
        "id": ("match", 0x10, 0x10), "weight": ("match", 0x14, 0x14),
        "enabled": ("match", 0x18, 0x18), "name": ("match", 0x20, 0x20)}
    assert said(out, "4/4 layout field offset(s) confirmed")


def test_a_field_the_runtime_puts_elsewhere_is_a_mismatch_and_is_logged_as_stale(node_scripts):
    model = make_model()
    model["assemblies"][0]["classes"][0]["fields"][1]["offset"] = 0x18      # weight moved
    out = resolve(node_scripts, rparams(offsets={"table_a": 0x40}, fields=FIELDS), model=model)
    row = field_rows(out)["weight"]
    assert (row["status"], row["layout_offset"], row["runtime_offset"]) == ("mismatch", 0x14, 0x18)
    assert said(out, "layout field TableARecord.weight is at 0x14 in the profile, but the runtime puts") and said(out, "stale")
    assert field_rows(out)["id"]["status"] == "match"


def test_a_field_or_class_the_runtime_does_not_have_is_unresolved_never_a_mismatch(node_scripts):
    renamed = {"TableARecord": {**FIELDS["TableARecord"], "map": {"id": "id", "name": "nope"}}}
    out = resolve(node_scripts, rparams(offsets={"table_a": 0x40}, fields=renamed))
    assert field_rows(out)["name"]["status"] == "unresolved" and "has no field nope" in field_rows(out)["name"]["reason"]
    gone = {"TableARecord": {**FIELDS["TableARecord"], "class": "Missing"}}
    out = resolve(node_scripts, rparams(offsets={"table_a": 0x40}, fields=gone))
    assert {r["status"] for r in out["fields"]} == {"unresolved"}
    out = resolve(node_scripts, rparams(offsets={"table_a": 0x40}, fields=FIELDS), model=make_model(can={"fields": False}))
    assert {r["status"] for r in out["fields"]} == {"unresolved"} and "il2cpp_field_get_offset" in out["fields"][0]["reason"]


def test_a_record_the_agent_does_not_read_is_skipped(node_scripts):
    other = {"NotMyRecord": FIELDS["TableARecord"]}
    out = resolve(node_scripts, rparams(offsets={"table_a": 0x40}, fields=other))
    assert out["fields"] == []


def test_the_hook_does_not_wait_for_the_field_check(node_scripts):
    # RVA-only hook points, field offsets wanted, runtime not up yet: the hook goes in at once
    out = resolve(node_scripts, rparams(offsets={"table_a": 0x40}, fields=FIELDS), model=make_model(ready="later"))
    assert out["readyBefore"] == 1 and out["rvas"] == [{"table_a": 0x40}]
    assert {r["status"] for r in out["fields"]} == {"match"}        # and the fields were checked once it was up


def test_unavailable_runtime_leaves_every_field_unresolved_with_the_reason(node_scripts):
    out = resolve(node_scripts, rparams(offsets={"table_a": 0x40}, fields=FIELDS), model=make_model(ready={"unavailable": "hidden"}))
    assert out["rvas"] == [{"table_a": 0x40}]
    assert {(r["status"], r["reason"]) for r in out["fields"]} == {("unresolved", "hidden")}


def test_resolve_rva_skips_the_field_check_too(node_scripts):
    out = resolve(node_scripts, rparams(offsets={"table_a": 0x40}, fields=FIELDS, resolve="rva"))
    assert out["fields"] == []


# ---------------------------------------------------------------------------
# the agents, end to end, on a module that exports nothing (= hidden exports)
# ---------------------------------------------------------------------------

def agent_params(**kw):
    """The example profile's params with its names for `keys` kept: `params()` drops the name of every key it
    gives an RVA, so build from the profile directly."""
    return profiles.agent_params(PROFILE, **kw)


def test_the_example_profile_hands_its_names_to_the_agent_unless_an_rva_overrides_one():
    p = agent_params()
    assert set(p["names"]["methods"]) == {"table_a", "table_b", "probe", "lookup_by_pattern", "resolve_default"}
    assert p["names"]["methods"]["table_a"] == {"namespace": NS, "class": "ExampleTableA", "method": "Unpack", "args": 1}
    assert p["names"]["methods"]["resolve_default"]["assembly"] == "Assembly-CSharp"
    p = agent_params(offsets={"table_a": 0x40})
    assert "table_a" not in p["names"]["methods"] and "table_b" in p["names"]["methods"]


@pytest.mark.parametrize("agent, keys", [("dump_table_a.js", ["table_a"]), ("dump_table_b.js", ["table_b"]),
                                         ("probe_record.js", ["probe"]), ("trace_lookup.js", ["lookup_by_pattern", "resolve_default"])])
def test_an_agent_whose_names_cannot_be_looked_up_hooks_the_profiles_rvas(node_scripts, agent, keys):
    offsets = {k: 0x1230 + 0x10 * i for i, k in enumerate(keys)}
    out = run_agent(node_scripts, Image(), agent, p=agent_params(offsets=offsets, resolve=None) | {
        "names": agent_params()["names"]})            # keep the names AND give the RVAs: the fallback case
    assert out["initError"] is None
    assert out["attached"] == list(offsets.values())
    assert any("name lookup unavailable" in line and "does not export" in line for line in out["log"])
    if agent != "probe_record.js":
        assert [m["source"] for m in out["resolution"]["methods"]] == ["rva"] * len(keys)
        assert all("does not export" in m["reason"] for m in out["resolution"]["methods"])


def test_resolve_names_on_a_module_without_exports_refuses_to_hook(node_scripts):
    p = agent_params(resolve="names")
    p["offsets"]["table_a"] = 0x1230                               # an RVA exists, but "names" never falls back to it
    out = run_agent(node_scripts, Image(), "dump_table_a.js", p=p)
    assert out["initError"] is None and out["attached"] == []
    assert out["resolution"]["methods"][0]["source"] == "none"
    assert any('resolve is "names"' in line for line in out["log"])


def test_a_name_and_no_rva_is_accepted_by_the_agent_but_hooks_nothing_if_the_name_is_unavailable(node_scripts):
    out = run_agent(node_scripts, Image(), "dump_table_a.js", p=agent_params())      # offsets all 0 (the template)
    assert out["initError"] is None and out["attached"] == []
    assert any("no RVA in the profile to fall back to" in line for line in out["log"])


def test_resolve_rva_makes_a_template_profile_refuse_again(node_scripts):
    out = run_agent(node_scripts, Image(), "dump_table_a.js", p=agent_params(resolve="rva"))
    assert "offsets.table_a is missing or 0" in out["initError"] and out["attached"] == []


def test_a_name_does_not_excuse_a_bad_offset_value(node_scripts):
    p = agent_params()
    p["offsets"]["table_a"] = "0x40"                               # not an integer: that is a mistake, whatever the name says
    out = run_agent(node_scripts, Image(), "dump_table_a.js", p=p)
    assert "offsets.table_a is missing or 0" in out["initError"]


def test_an_unknown_resolve_mode_is_refused_by_the_agent(node_scripts):
    p = params()
    p["resolve"] = "guess"
    out = run_agent(node_scripts, Image(), "dump_table_a.js", p=p)
    assert "resolve must be one of auto, names, rva" in out["initError"]


def test_an_agent_without_names_behaves_exactly_as_before(node_scripts):
    out = run_agent(node_scripts, Image(), "dump_table_a.js", p={k: v for k, v in params().items() if k != "names"})
    assert out["attached"] == [0x40] and out["initError"] is None
    assert not any("name lookup" in line for line in out["log"])
    assert out["resolution"]["methods"][0]["source"] == "rva" and out["resolution"]["fields"] == []
    assert "field_offsets" not in out["health"]


def test_the_health_an_agent_exports_carries_the_field_offsets_it_asked_the_runtime_for(node_scripts):
    out = run_agent(node_scripts, Image(), "dump_table_a.js", p=params())    # the example's names.fields, hidden exports
    rows = out["health"]["field_offsets"]
    assert {r["field"] for r in rows} == {"id", "weight", "enabled", "name"}
    assert {r["status"] for r in rows} == {"unresolved"} and out["health"]["version"] == 1


def test_the_stage_reaches_the_resolver(node_scripts):
    # late stage: the lookup would ask the runtime at once; either way a module with no exports falls back
    out = run_agent(node_scripts, Image(), "dump_table_a.js", p=params(), stage="late")
    assert out["initError"] is None and out["attached"] == [0x40]


def test_every_agent_exports_getresolution(node_scripts):
    for agent in ("dump_table_a.js", "dump_table_b.js", "probe_record.js", "trace_lookup.js"):
        keys = {"dump_table_a.js": ["table_a"], "dump_table_b.js": ["table_b"], "probe_record.js": ["probe"],
                "trace_lookup.js": ["lookup_by_pattern", "resolve_default"]}[agent]
        out = run_agent(node_scripts, Image(), agent, p=params(**{k: 0x1230 for k in keys}))
        assert out["resolution"] is not None, agent
