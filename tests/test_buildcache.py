"""
The host's half of the build cache: where things live, what a record looks like on disk, and the driver's use of it.

  * retk/paths.py - the user's own data directory, the standard one per operating system (platformdirs), never
    inside the repo; $RE_DATA_DIR / $RE_PROFILES_DIR move it. (tests/conftest.py gives every test a data dir of its
    own, so nothing here touches a real one.)
  * retk/buildcache.py - one JSON file per build with a `schema_version`: written atomically, merged across
    agents, migrated when old, left alone when written by a newer toolkit, ignored (with a note) when damaged or
    not about the build its name says.
  * retk dump - run 1 on a build records what a dump that passed its layout check hooked; run 2 on the
    same build hands those addresses to the agent; a new build gets none and is recorded in turn. A dump that did
    not verify, or `--build-cache off`, or an address the user gave, records nothing / is not overridden.

No device and no Frida: the stub `frida` of tests/fake_frida.py. Run from the repo root:

    pytest tests/test_buildcache.py
"""
import json
import sys
from pathlib import Path

import platformdirs
import pytest

from retk import buildcache
from retk import buildid
from retk import paths
from fake_frida import FakeDevice, FakeExports, FakeSession, make_frida_module
from stub_import import import_fresh
from test_names_driver import with_names, write
from test_run_dump import _bad_health, _health

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET = "com.example.app"
BUILD = buildid.BuildId(buildid.KIND_ELF, "ab" * 20)
OTHER = buildid.BuildId(buildid.KIND_ELF, "cd" * 20)
UUID_BUILD = buildid.BuildId(buildid.KIND_MACHO, "6f1a2b3c-4d5e-4f60-8a7b-8c9d0e1f2a3b")


# ---------------------------------------------------------------------------
# where things live
# ---------------------------------------------------------------------------

def test_the_data_dir_is_the_platform_standard_and_never_inside_the_repo(monkeypatch):
    monkeypatch.delenv(paths.ENV_DATA_DIR, raising=False)
    where = paths.data_dir()
    assert where == Path(platformdirs.user_data_dir("re-toolkit", appauthor=False))
    assert where.name == "re-toolkit" and REPO_ROOT not in (where, *where.parents)


def test_RE_DATA_DIR_moves_everything(monkeypatch, tmp_path):
    monkeypatch.setenv(paths.ENV_DATA_DIR, str(tmp_path))
    assert (paths.data_dir(), paths.profiles_dir(), paths.builds_dir()) == (
        tmp_path, tmp_path / "profiles", tmp_path / "builds")


def test_RE_PROFILES_DIR_moves_only_the_profiles(monkeypatch, tmp_path):
    monkeypatch.setenv(paths.ENV_PROFILES_DIR, str(tmp_path / "mine"))
    assert paths.profiles_dir() == tmp_path / "mine"
    assert paths.builds_dir().parent == paths.data_dir()


def test_each_operating_system_has_its_own_standard_place(monkeypatch):
    # platformdirs' per-OS classes can be asked on any machine: this is the "one standard place each" claim
    from platformdirs.macos import MacOS
    from platformdirs.unix import Unix
    from platformdirs.windows import Windows
    monkeypatch.setattr("platformdirs.windows.get_win_folder", lambda _name: "/c/Users/me/AppData/Local")
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)          # macOS honours it when set; the plain default is asked here
    mac = Path(MacOS(appname=paths.APP_NAME, appauthor=False).user_data_dir)
    win = Path(Windows(appname=paths.APP_NAME, appauthor=False).user_data_dir)
    monkeypatch.setenv("XDG_DATA_HOME", "/home/me/.local/share")
    unix = Path(Unix(appname=paths.APP_NAME, appauthor=False).user_data_dir)
    assert unix == Path("/home/me/.local/share/re-toolkit")
    assert mac.parts[-3:] == ("Library", "Application Support", "re-toolkit")
    assert win == Path("/c/Users/me/AppData/Local/re-toolkit")
    assert len({unix, mac, win}) == 3


# ---------------------------------------------------------------------------
# a record on disk
# ---------------------------------------------------------------------------

def put(build=BUILD, offsets=None, sources=None, module="UnityFramework", target=TARGET, at="2026-11-02T10:00:00+00:00"):
    return buildcache.remember(target, module, build, offsets or {"table_a": 0x1230}, sources or {"table_a": "name"},
                               {"at": at, "tool": "run_dump.py", "profile": "p", "records": 2, "layout_check": "ok"})


def test_a_record_is_one_json_file_per_build_with_a_schema_version():
    path, how = put()
    assert how == "new"
    assert path == paths.builds_dir() / TARGET / f"gnu-build-id_{'ab' * 20}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["schema_version"] == buildcache.SCHEMA_VERSION == 1
    assert raw["build"] == {"kind": "gnu-build-id", "id": "ab" * 20}
    assert raw["offsets"] == {"table_a": "0x1230"} and raw["sources"] == {"table_a": "name"}
    assert (raw["target"], raw["module"]) == (TARGET, "UnityFramework")
    assert not [p for p in path.parent.iterdir() if p.suffix == ".tmp"]            # written atomically, no leftovers


def test_it_reads_back_as_it_was_written():
    put(offsets={"table_a": 0x1230, "table_b": 0x50}, sources={"table_a": "name", "table_b": "rva"})
    entries, problems = buildcache.load_target(TARGET)
    assert problems == []
    e = entries[BUILD.text]
    assert (e.module, e.offsets, e.sources) == ("UnityFramework", {"table_a": 0x1230, "table_b": 0x50},
                                                {"table_a": "name", "table_b": "rva"})


def test_the_same_addresses_again_are_not_rewritten():
    path, _ = put()
    before = path.read_text(encoding="utf-8")
    assert put(at="2030-01-01T00:00:00+00:00")[1] == "same"
    assert path.read_text(encoding="utf-8") == before


def test_another_agent_adds_its_keys_and_a_changed_address_updates():
    put(offsets={"table_a": 0x1230}, sources={"table_a": "name"})
    assert put(offsets={"table_b": 0x50}, sources={"table_b": "rva"})[1] == "updated"
    assert put(offsets={"table_a": 0x1240}, sources={"table_a": "name"})[1] == "updated"
    [(e)] = buildcache.load_target(TARGET)[0].values()
    assert e.offsets == {"table_a": 0x1240, "table_b": 0x50}


def test_builds_and_targets_are_kept_apart():
    put(build=BUILD)
    put(build=OTHER, offsets={"table_a": 0x7770})
    put(build=UUID_BUILD)
    put(target="com.other.app")
    assert sorted(buildcache.load_target(TARGET)[0]) == sorted([BUILD.text, OTHER.text, UUID_BUILD.text])
    assert list(buildcache.load_target("com.other.app")[0]) == [BUILD.text]
    assert buildcache.load_target("com.nobody")[0] == {}


@pytest.mark.parametrize("target", ["../../etc", "a/b", "a\\b", "..", "x:y", ""])
def test_a_target_id_cannot_climb_out_of_the_builds_dir(target):
    path, _ = put(target=target or "weird")
    assert paths.builds_dir() in path.parents


# --- schema_version ---

def test_a_file_from_a_newer_toolkit_is_never_read_or_overwritten():
    path, _ = put()
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["schema_version"] = buildcache.SCHEMA_VERSION + 1
    raw["offsets"]["table_a"] = "0x9999"
    path.write_text(json.dumps(raw), encoding="utf-8")
    before = path.read_text(encoding="utf-8")

    entries, problems = buildcache.load_target(TARGET)
    assert entries == {} and "newer re-toolkit" in problems[0]
    with pytest.raises(buildcache.NewerSchema):
        put(offsets={"table_a": 0x1})
    assert path.read_text(encoding="utf-8") == before


def test_an_older_file_is_migrated_when_read(monkeypatch):
    path, _ = put()
    raw = json.loads(path.read_text(encoding="utf-8"))

    def to_v2(r):                                   # an imagined change: `module` moved under `build`
        r = dict(r, schema_version=2)
        r["build"] = dict(r["build"])
        return r
    monkeypatch.setattr(buildcache, "SCHEMA_VERSION", 2)
    monkeypatch.setattr(buildcache, "MIGRATIONS", {1: to_v2})
    entries, problems = buildcache.load_target(TARGET)
    assert problems == [] and entries[BUILD.text].offsets == {"table_a": 0x1230}
    assert json.loads(path.read_text(encoding="utf-8")) == raw                   # reading never rewrites it
    put(offsets={"table_b": 0x50}, sources={"table_b": "rva"})                    # writing does, at the new version
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 2


def test_a_version_with_no_migration_step_is_a_problem_not_a_crash(monkeypatch):
    put()
    monkeypatch.setattr(buildcache, "SCHEMA_VERSION", 3)
    entries, problems = buildcache.load_target(TARGET)
    assert entries == {} and "no step to 2" in problems[0]


@pytest.mark.parametrize("mutate, message", [
    (lambda r: r.pop("schema_version"), "schema_version"),
    (lambda r: r.update(schema_version="1"), "schema_version"),
    (lambda r: r.update(schema_version=0), "schema_version"),
    (lambda r: r.update(build={"kind": "pe-guid", "id": "ab"}), "build"),
    (lambda r: r["build"].update(id="../x"), "build"),
    (lambda r: r.update(offsets={}), "offsets"),
    (lambda r: r.update(offsets={"table_a": "4660"}), "0x"),
    (lambda r: r.update(offsets={"table_a": "0x0"}), "not an address"),
    (lambda r: r.update(module=""), "module"),
    (lambda r: r.update(target=5), "target"),
    (lambda r: r["build"].update(id="cd" * 20), "different build"),
])
def test_a_damaged_or_mismatched_file_is_ignored_with_a_note(mutate, message):
    path, _ = put()
    raw = json.loads(path.read_text(encoding="utf-8"))
    mutate(raw)
    path.write_text(json.dumps(raw), encoding="utf-8")
    entries, problems = buildcache.load_target(TARGET)
    assert entries == {} and message in problems[0] and "ignored" in problems[0]


def test_text_that_is_not_json_is_ignored_and_a_verified_run_replaces_it():
    path, _ = put()
    path.write_text("{ not json", encoding="utf-8")
    assert "not valid JSON" in buildcache.load_target(TARGET)[1][0]
    assert put()[1] == "new"
    assert buildcache.load_target(TARGET)[1] == []


def test_the_same_build_under_another_module_name_starts_over():
    put(module="UnityFramework")
    put(module="libil2cpp.so", offsets={"table_a": 0x77})
    [e] = buildcache.load_target(TARGET)[0].values()
    assert (e.module, e.offsets) == ("libil2cpp.so", {"table_a": 0x77})


# --- what the agent is told ---

def test_the_agent_gets_the_builds_of_its_module_without_the_keys_the_user_overrode():
    put(offsets={"table_a": 0x1230, "table_b": 0x50}, sources={"table_a": "name", "table_b": "name"})
    put(build=OTHER, offsets={"table_a": 0x7770}, module="libil2cpp.so", sources={"table_a": "name"})
    entries, _ = buildcache.load_target(TARGET)
    assert buildcache.agent_cache(entries, "UnityFramework") == {"builds": {BUILD.text: {"table_a": 0x1230, "table_b": 0x50}}}
    assert buildcache.agent_cache(entries, "UnityFramework", skip=("table_a",)) == {"builds": {BUILD.text: {"table_b": 0x50}}}
    assert buildcache.agent_cache(entries, "UnityFramework", skip=("table_a", "table_b")) is None
    assert buildcache.agent_cache(entries, "nothing") is None


def test_modes_decide_what_is_read_and_sent():
    put()
    assert buildcache.BuildCache("auto", TARGET, "UnityFramework").agent_params() == {"builds": {BUILD.text: {"table_a": 0x1230}}}
    assert buildcache.BuildCache("rescan", TARGET, "UnityFramework").agent_params() is None
    off = buildcache.BuildCache("off", TARGET, "UnityFramework")
    assert off.agent_params() is None and off.entries == {} and off.intro() == ["[i] build cache = off"]
    with pytest.raises(ValueError):
        buildcache.BuildCache("sometimes", TARGET, "UnityFramework")


# ---------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------

def test_where_says_where(capsys):
    assert buildcache.main(["where"]) == 0
    out = capsys.readouterr().out
    assert str(paths.profiles_dir()) in out and str(paths.builds_dir()) in out


def test_list_shows_what_is_recorded(capsys):
    assert buildcache.main(["list"]) == 0 and "nothing recorded" in capsys.readouterr().out
    put()
    assert buildcache.main(["list", "--target", TARGET]) == 0
    out = capsys.readouterr().out
    assert BUILD.text in out and "table_a=0x1230 (name)" in out


def test_key_prints_a_binarys_build_id(tmp_path, capsys):
    from test_buildid import BUILD_ID, elf
    binary = tmp_path / "libil2cpp.so"
    binary.write_bytes(elf())
    assert buildcache.main(["key", str(binary)]) == 0
    assert capsys.readouterr().out.strip() == f"gnu-build-id:{BUILD_ID}"
    binary.write_bytes(b"MZ" + b"\0" * 200)
    assert buildcache.main(["key", str(binary)]) == 1
    assert buildcache.main(["key", str(tmp_path / "missing")]) == 2


# ---------------------------------------------------------------------------
# run_dump.py: run 1, run 2, a new build
# ---------------------------------------------------------------------------

def method(key, source, rva):
    return {"key": key, "name": "Ns.C::M/1", "source": source, "rva": rva, "name_rva": rva if source == "name" else None,
            "profile_rva": None, "agrees": None, "reason": None}


def report(build=BUILD, source="name", rva=0x1230, mode="auto", key="table_a"):
    return {"mode": mode, "api": {"ready": True, "why": None}, "fields": [],
            "build": {"kind": build.kind, "id": build.id} if build else None,
            "methods": [method(key, source, rva)]}


@pytest.fixture
def drive(tmp_path, monkeypatch):
    holder = {}
    monkeypatch.setitem(sys.modules, "frida", make_frida_module(holder))
    run_dump = import_fresh(monkeypatch, "run_dump")
    agent = tmp_path / "agent.js"
    agent.write_text("// agent\n", encoding="utf-8")
    out = tmp_path / "records_test.json"
    monkeypatch.setattr("builtins.input", lambda *_: "")

    def go(rep, *extra, health=None):
        session = FakeSession(health=_health() if health is None else health)
        holder["device"] = FakeDevice(session)
        monkeypatch.setattr(FakeExports, "get_resolution", lambda self: rep, raising=False)
        monkeypatch.setattr(sys, "argv", ["run_dump.py", "--agent", str(agent), "--out", str(out),
                                          "--target", TARGET, "--module", "UnityFramework", *extra])
        run_dump.main()
        return session.script.exports_sync.inits[0][1]

    yield go, out


def recorded():
    return buildcache.load_target(TARGET)[0]


def test_run_one_records_and_run_two_on_the_same_build_uses_it(drive, capsys):
    go, out = drive
    first = go(report())
    assert "cache" not in first                                              # nothing known yet
    shown = capsys.readouterr().out
    assert "not seen before - looked up by name" in shown and f"recorded table_a=0x1230 for {BUILD.text}" in shown
    assert recorded()[BUILD.text].offsets == {"table_a": 0x1230}

    second = go(report(source="cache"))
    assert second["cache"] == {"builds": {BUILD.text: {"table_a": 0x1230}}}   # the agent is handed it
    shown = capsys.readouterr().out
    assert "seen before - table_a taken from the build cache" in shown and "already holds exactly these" in shown
    assert recorded()[BUILD.text].sources == {"table_a": "name"}              # how it was FOUND is not overwritten
    meta = json.loads(out.read_text(encoding="utf-8"))["meta"]
    assert meta["resolution"]["build"] == {"kind": "gnu-build-id", "id": BUILD.id}
    assert meta["resolution"]["methods"][0]["source"] == "cache"


def test_a_new_build_is_looked_up_afresh_and_recorded_beside_the_old_one(drive, capsys):
    go, _ = drive
    go(report())
    capsys.readouterr()
    params = go(report(build=OTHER, rva=0x7770))                             # the app was rebuilt
    assert params["cache"] == {"builds": {BUILD.text: {"table_a": 0x1230}}}   # the agent reads its own build and finds no entry
    assert "not seen before" in capsys.readouterr().out
    assert {k: e.offsets for k, e in recorded().items()} == {BUILD.text: {"table_a": 0x1230}, OTHER.text: {"table_a": 0x7770}}


def test_a_dump_that_did_not_pass_its_layout_check_records_nothing(drive, capsys):
    go, _ = drive
    with pytest.raises(SystemExit) as e:
        go(report(), health=_bad_health())
    assert e.value.code == 3
    assert recorded() == {} and "not recorded - the dump did not pass its layout check" in capsys.readouterr().out


def test_an_unverified_dump_records_nothing(drive):
    go, _ = drive
    go(report(), "--no-layout-check")
    assert recorded() == {}


def test_build_cache_off_neither_reads_nor_writes(drive, capsys):
    go, _ = drive
    go(report())
    params = go(report(), "--build-cache", "off")
    assert "cache" not in params and "build cache = off" in capsys.readouterr().out
    go(report(build=OTHER, rva=0x7770), "--build-cache", "off")
    assert list(recorded()) == [BUILD.text]


def test_rescan_ignores_what_is_known_but_records_the_result(drive):
    go, _ = drive
    go(report())
    params = go(report(rva=0x1240), "--build-cache", "rescan")
    assert "cache" not in params
    assert recorded()[BUILD.text].offsets == {"table_a": 0x1240}


def test_an_address_given_on_the_command_line_is_not_overridden_and_is_recorded_as_given(drive):
    go, _ = drive
    go(report())
    params = go(report(source="rva", rva=0x99), "--offset", "table_a=0x99")
    assert "cache" not in params                                              # the one key it knew is the one overridden
    e = recorded()[BUILD.text]
    assert e.offsets == {"table_a": 0x99} and e.sources == {"table_a": "override"}


@pytest.mark.parametrize("mode", ["names", "rva"])
def test_explicit_resolve_modes_do_not_use_or_write_the_cache(drive, tmp_path, mode, capsys):
    go, _ = drive
    go(report())
    extra = ["--resolve", mode]
    if mode == "names":                           # "names" needs something to look up
        extra += ["--profile", write(tmp_path, with_names({"methods": {"table_a": "ExampleNamespace.ExampleTableA::Unpack/1"}}))]
    capsys.readouterr()
    params = go(report(mode=mode, rva=0x5555), *extra)
    assert "cache" not in params and f"build cache = off  (--resolve {mode})" in capsys.readouterr().out
    assert recorded()[BUILD.text].offsets == {"table_a": 0x1230}


def test_a_module_with_no_readable_build_is_simply_not_keyed(drive, capsys):
    go, _ = drive
    go(report(build=None))
    assert recorded() == {} and "not keyed by build" in capsys.readouterr().out


def test_a_hook_point_with_no_address_records_nothing(drive):
    go, _ = drive
    rep = report()
    rep["methods"].append({**method("table_b", "none", None)})
    with pytest.raises(SystemExit) as e:
        go(rep)
    assert e.value.code == 4
    assert recorded() == {}


def test_a_newer_schema_file_does_not_stop_a_run_or_get_overwritten(drive, capsys):
    path, _ = put()
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["schema_version"] = 99
    path.write_text(json.dumps(raw), encoding="utf-8")
    before = path.read_text(encoding="utf-8")
    go, _ = drive
    params = go(report())
    assert "cache" not in params
    shown = capsys.readouterr().out
    assert "newer re-toolkit" in shown and "could not record" in shown
    assert path.read_text(encoding="utf-8") == before
