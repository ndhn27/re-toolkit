"""
The agent's half of the build cache: scripts/_resolve.js's resolveOffsets() and what it does with
`params.cache`, run under Node against a made-up IL2CPP runtime (tests/test_names_agent.py's model) and a fake
process image that holds a real-looking ELF / Mach-O header at the module's base.

What is pinned: an address the cache holds for THIS build is hooked as it is, without asking the runtime (and
without waiting for it); a build the cache does not hold - or one whose id cannot be read - gets the lookup it
always had; "names" and "rva" mean what they say whatever the cache holds; an address outside the module is not
believed; a malformed `cache` is refused up front; and the report says which build it was and where each
address came from. The Node-backed tests skip when `node` is not installed (fail instead under $CI).

Run from the repo root:

    pytest tests/test_build_cache_agent.py
"""
import copy

import pytest

from node_support import run_harness
from test_buildid import BUILD_ID, UUID, elf, macho
from test_layouts import Image, params, run_agent
from test_names_agent import MODULE_SIZE, NS, UNPACK_1, make_model, rparams

NAME = f"{NS}.ExampleTableA::Unpack/1"
ELF_KEY = f"gnu-build-id:{BUILD_ID}"
MACHO_KEY = f"macho-uuid:{UUID}"
OTHER_BUILD = "gnu-build-id:" + "cd" * 20
CACHED = 0x2222                                   # not where the name resolves (UNPACK_1), so who answered is clear


@pytest.fixture
def run(node_scripts):
    def go(image=None, cache=None, resolve_mode=None, keys=("table_a",), methods=None, offsets=None, model=None, **req):
        p = rparams(methods=methods if methods is not None else {k: NAME for k in keys},
                    offsets=offsets, resolve=resolve_mode)
        if cache is not None:
            p["cache"] = {"builds": cache}
        out = run_harness(node_scripts, elf() if image is None else image, mode="resolve", keys=list(keys),
                          params=p, model=model or make_model(), moduleSize=MODULE_SIZE, **req)
        assert out["error"] is None, out["error"]
        return out
    return go


def entry(out, key="table_a"):
    return next(m for m in out["resolution"]["methods"] if m["key"] == key)


# --- a hit ---

def test_an_address_recorded_for_this_build_is_hooked_as_it_is(run):
    out = run(cache={ELF_KEY: {"table_a": CACHED}})
    e = entry(out)
    assert out["rvas"] == [{"table_a": CACHED}]
    assert (e["source"], e["rva"], e["name_rva"]) == ("cache", CACHED, None)          # the runtime was not asked
    assert out["resolution"]["build"] == {"kind": "gnu-build-id", "id": BUILD_ID}
    assert any(ELF_KEY in line and "as recorded for this build" in line for line in out["log"])


def test_a_hit_hooks_at_once_without_waiting_for_the_runtime(run):
    out = run(cache={ELF_KEY: {"table_a": CACHED}}, model=make_model(ready="later"))
    assert out["readyBefore"] == 1                                               # hooked before the runtime was up
    assert out["rvas"] == [{"table_a": CACHED}]


def test_a_mach_o_build_is_matched_the_same_way(run):
    out = run(image=macho(), cache={MACHO_KEY: {"table_a": CACHED}})
    assert entry(out)["source"] == "cache" and entry(out)["rva"] == CACHED
    assert out["resolution"]["build"] == {"kind": "macho-uuid", "id": UUID}


def test_only_the_keys_the_cache_holds_are_taken_from_it(run):
    out = run(cache={ELF_KEY: {"table_a": CACHED}}, keys=("table_a", "table_b"),
              methods={"table_a": NAME, "table_b": f"{NS}.Outer/Inner::Run"})
    assert (entry(out)["source"], entry(out)["rva"]) == ("cache", CACHED)
    assert (entry(out, "table_b")["source"], entry(out, "table_b")["rva"]) == ("name", 0x1500)


def test_the_profiles_rva_is_told_it_is_for_another_build(run):
    out = run(cache={ELF_KEY: {"table_a": CACHED}}, offsets={"table_a": 0x9990})
    e = entry(out)
    assert (e["source"], e["rva"], e["profile_rva"], e["agrees"]) == ("cache", CACHED, 0x9990, False)
    assert any("another build" in line for line in out["log"])


# --- a miss: the rescan ---

def test_a_build_the_cache_does_not_hold_is_looked_up_by_name(run):
    out = run(cache={OTHER_BUILD: {"table_a": CACHED}})
    e = entry(out)
    assert (e["source"], e["rva"]) == ("name", UNPACK_1)
    assert out["resolution"]["build"] == {"kind": "gnu-build-id", "id": BUILD_ID}


def test_with_no_cache_nothing_changes_except_that_the_build_is_reported(run):
    out = run()
    assert (entry(out)["source"], entry(out)["rva"]) == ("name", UNPACK_1)
    assert out["resolution"]["build"]["id"] == BUILD_ID


def test_a_build_whose_id_cannot_be_read_ignores_the_cache(run):
    out = run(image=b"\xee" * 256, cache={ELF_KEY: {"table_a": CACHED}})
    assert (entry(out)["source"], entry(out)["rva"]) == ("name", UNPACK_1)
    assert out["resolution"]["build"] is None


def test_without_a_name_a_new_build_falls_back_to_the_profiles_rva(run):
    out = run(cache={OTHER_BUILD: {"table_a": CACHED}}, methods={}, offsets={"table_a": 0x1234})
    assert (entry(out)["source"], entry(out)["rva"]) == ("rva", 0x1234)


# --- resolve modes that say where an address comes from ---

@pytest.mark.parametrize("mode, source, rva", [("names", "name", UNPACK_1), ("rva", "rva", 0x1234)])
def test_names_and_rva_modes_ignore_the_cache(run, mode, source, rva):
    out = run(cache={ELF_KEY: {"table_a": CACHED}}, resolve_mode=mode, offsets={"table_a": 0x1234})
    assert (entry(out)["source"], entry(out)["rva"]) == (source, rva)


# --- not believed ---

def test_an_address_outside_the_module_is_not_hooked(run):
    out = run(cache={ELF_KEY: {"table_a": MODULE_SIZE + 0x10}})
    assert (entry(out)["source"], entry(out)["rva"]) == ("name", UNPACK_1)
    assert any("outside this module" in line for line in out["log"])


# --- the parameters ---

@pytest.mark.parametrize("cache, message", [
    ("nope", "cache must be"),
    ({"builds": []}, "cache must be"),
    ({"builds": {"k": 5}}, "must map offsets keys to RVAs"),
    ({"builds": {"k": {"table_a": 0}}}, "positive integer RVA"),
    ({"builds": {"k": {"table_a": "0x10"}}}, "positive integer RVA"),
    ({"builds": {"k": {"table_a": -4}}}, "positive integer RVA"),
])
def test_a_malformed_cache_is_refused_by_the_agent(node_scripts, cache, message):
    p = params(table_a=0x1230)
    p["cache"] = cache
    out = run_agent(node_scripts, Image(), "dump_table_a.js", p=p)
    assert message in out["initError"]


def test_a_cache_in_the_parameters_is_accepted_by_every_agent(node_scripts):
    p = params(table_a=0x1230, table_b=0x1240, probe=0x1250, lookup_by_pattern=0x1260, resolve_default=0x1270)
    p["cache"] = {"builds": {ELF_KEY: {"table_a": 0x1230}}}
    for agent in ("dump_table_a.js", "dump_table_b.js", "probe_record.js", "trace_lookup.js"):
        assert run_agent(node_scripts, Image(), agent, p=copy.deepcopy(p))["initError"] is None


def test_an_agent_hooks_the_cached_address_when_the_profile_has_none(node_scripts):
    image = Image()
    image.mem[0:len(elf())] = elf()
    p = params(table_a=0x1230)
    p["cache"] = {"builds": {ELF_KEY: {"table_a": 0x1500}}}
    out = run_agent(node_scripts, image, "dump_table_a.js", p=p)
    assert out["initError"] is None
    assert out["attached"] == [0x1500]
    assert out["resolution"]["methods"][0]["source"] == "cache"
