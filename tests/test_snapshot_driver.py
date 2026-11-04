"""
The Python side of the snapshot mode (README.md's "Snapshot"): taking the table out of an app that is
ALREADY running, instead of hooking its unpack and waiting for a call that will not come again.

  * the profile's `names.snapshot` section and what the agent receives from it;
  * _common.attach_agent(): the lifecycle of an attach that is not ours to end - never resumed, never
    killed, always detached, "late" stage;
  * run_dump.py --attach / --snapshot: the polling of the agent, what is printed, what is written, and the
    one rule that matters - a snapshot that found nothing writes NOTHING, so it can't replace a good file;
  * diff_records noting that two dumps were made differently.

The agent itself (scripts/_snapshot.js, snapshot_records.js) is exercised against a real process by
tests/test_frida_real.py.

Run from the repo root:

    pytest tests/test_snapshot_driver.py
"""
import copy
import json
import sys
from pathlib import Path

import pytest

from retk import _common as common
from retk import diff_records
from retk import profiles
from fake_frida import PID, FakeDevice, FakeExports, FakeSession, make_frida_module
from stub_import import import_fresh
from node_support import run_harness

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "profile.example.json"
RAW = json.loads(EXAMPLE.read_text(encoding="utf-8"))
NS = "ExampleNamespace"


def load(tmp_path, snapshot, fields=True):
    raw = copy.deepcopy(RAW)
    raw["names"]["snapshot"] = snapshot
    if not fields:
        raw["names"]["fields"] = {}
    path = tmp_path / "p.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return profiles.load(str(path))


STATIC = {"class": f"{NS}.ExampleTableB", "field": "all", "container": "list"}


# ---------------------------------------------------------------------------
# the names.snapshot section
# ---------------------------------------------------------------------------

def test_the_example_profile_says_where_a_running_app_holds_its_table():
    p = profiles.load(EXAMPLE)
    entry = p.names["snapshot"]["TableARecord"]
    assert entry["static"] == {"namespace": NS, "class": "ExampleTableB", "assembly": None, "field": "all", "container": "list"}
    # `heap: true` took the class of names.fields for the same record
    assert entry["heap"] == {"namespace": NS, "class": "ExampleTableA", "assembly": None}


def test_heap_may_name_its_own_class_assembly_and_limits(tmp_path):
    p = load(tmp_path, {"TableARecord": {"heap": {"class": f"{NS}.Other", "assembly": "Assembly-CSharp", "max": 500, "budget_ms": 2000}}})
    assert p.names["snapshot"]["TableARecord"] == {"heap": {
        "namespace": NS, "class": "Other", "assembly": "Assembly-CSharp", "max": 500, "budget_ms": 2000}}


def test_static_and_heap_are_each_optional_but_one_is_needed(tmp_path):
    assert set(load(tmp_path, {"TableARecord": {"static": STATIC}}).names["snapshot"]["TableARecord"]) == {"static"}
    with pytest.raises(profiles.ProfileError, match="with at least one of them"):
        load(tmp_path, {"TableARecord": {}})


@pytest.mark.parametrize("entry, match", [
    ({"static": {**STATIC, "container": "dictionary"}}, "one of object, array, list"),
    ({"static": {k: v for k, v in STATIC.items() if k != "container"}}, "one of object, array, list"),
    ({"static": {**STATIC, "field": ""}}, "the name of the static field"),
    ({"static": {**STATIC, "field": "two words"}}, "the name of the static field"),
    ({"static": {"class": f"{NS}.A"}}, "the name of the static field"),
    ({"static": {**STATIC, "typo": 1}}, "expected"),
    ({"static": {**STATIC, "class": "NoNamespaceOrNot::"}}, "not a class name"),
    ({"heap": {"max": 0}}, "positive whole number"),
    ({"heap": {"max": True}}, "positive whole number"),
    ({"heap": {"budget_ms": "5"}}, "positive whole number"),
    ({"heap": {"classs": "x"}}, "true, or an object"),
    ({"heap": "yes"}, "true, or an object"),
    ({"other": {}}, "with at least one of them"),
])
def test_a_malformed_snapshot_entry_is_refused_naming_where(tmp_path, entry, match):
    with pytest.raises(profiles.ProfileError, match=match) as e:
        load(tmp_path, {"TableARecord": entry})
    assert "snapshot.TableARecord" in str(e.value)


def test_heap_true_needs_a_class_from_somewhere(tmp_path):
    with pytest.raises(profiles.ProfileError, match="no \"class\" given and names.fields has no entry for TableARecord"):
        load(tmp_path, {"TableARecord": {"heap": True}}, fields=False)


def test_a_snapshot_of_a_record_the_layout_does_not_define_is_refused(tmp_path):
    with pytest.raises(profiles.ProfileError, match="define no record 'Nope'"):
        load(tmp_path, {"Nope": {"static": STATIC}})


def test_snapshot_record_picks_the_only_entry_or_the_named_one(tmp_path):
    only = load(tmp_path, {"TableARecord": {"static": STATIC}})
    assert profiles.snapshot_record(only) == "TableARecord" == profiles.snapshot_record(only, "TableARecord")
    both = load(tmp_path, {"TableARecord": {"static": STATIC}, "TableBRecord": {"static": STATIC}})
    assert profiles.snapshot_record(both, "TableBRecord") == "TableBRecord"
    with pytest.raises(profiles.ProfileError, match="several records .*say which with --snapshot RECORD"):
        profiles.snapshot_record(both)
    with pytest.raises(profiles.ProfileError, match="has no record 'Nope' \\(has: TableARecord, TableBRecord\\)"):
        profiles.snapshot_record(both, "Nope")
    raw = copy.deepcopy(RAW)
    del raw["names"]["snapshot"]
    path = tmp_path / "none.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(profiles.ProfileError, match="the profile has no names.snapshot"):
        profiles.snapshot_record(profiles.load(str(path)))


def test_the_agent_receives_the_snapshot_spec_and_the_names_it_needs():
    p = profiles.load(EXAMPLE)
    params = profiles.agent_params(p, snapshot="TableARecord")
    assert params["snapshot"] == {"record": "TableARecord", **p.names["snapshot"]["TableARecord"]}
    assert params["names"]["fields"]["TableARecord"]["map"]["name"] == "label"
    assert "snapshot" not in profiles.agent_params(p)


def test_a_snapshot_contradicts_resolve_rva_and_needs_a_known_record():
    p = profiles.load(EXAMPLE)
    with pytest.raises(profiles.ProfileError, match="--resolve rva contradicts a snapshot"):
        profiles.agent_params(p, resolve="rva", snapshot="TableARecord")
    with pytest.raises(profiles.ProfileError, match="has no record 'Nope'"):
        profiles.agent_params(p, snapshot="Nope")


def test_the_params_an_agent_gets_are_copies_not_the_profiles_own_data():
    """The profile is shared by everything in the process; a caller editing its params must not edit it."""
    p = profiles.load(EXAMPLE)
    params = profiles.agent_params(p, snapshot="TableARecord")
    params["names"]["fields"]["TableARecord"]["map"]["weight"] = "changed"
    params["snapshot"]["static"]["field"] = "changed"
    assert p.names["fields"]["TableARecord"]["map"]["weight"] == "weight"
    assert p.names["snapshot"]["TableARecord"]["static"]["field"] == "all"
    again = profiles.agent_params(p, snapshot="TableARecord")
    assert again["names"]["fields"]["TableARecord"]["map"]["weight"] == "weight"


def test_the_containers_are_the_same_on_both_sides(node_scripts):
    info = run_harness(node_scripts, b"", mode="info")
    assert info["snapshotContainers"] == list(profiles.SNAPSHOT_CONTAINERS)


# ---------------------------------------------------------------------------
# attach_agent
# ---------------------------------------------------------------------------

def attach(device, process="TheGame", params=None, on_message=None):
    return common.attach_agent(device, process, "// agent", on_message or (lambda *a: None), params=params)


def test_attaching_never_spawns_resumes_or_kills_and_always_detaches():
    session = FakeSession()
    device = FakeDevice(session)
    with attach(device, params={"module": "m"}) as run:
        assert run.pid == PID and device.calls == ["attach"]
        assert run.script.exports_sync.inits == [("late", {"module": "m"})]      # the runtime is already up
        assert not session.detached
    assert session.detached and device.calls == ["attach"]                      # still no resume, no kill


def test_a_block_that_raises_still_detaches_and_still_does_not_kill():
    session = FakeSession()
    device = FakeDevice(session)
    with pytest.raises(RuntimeError, match="boom"):
        with attach(device):
            raise RuntimeError("boom")
    assert session.detached and "kill" not in device.calls


def test_a_process_is_found_by_pid_or_by_name_and_an_unknown_one_is_an_error():
    device = FakeDevice(FakeSession(), processes={"TheGame": PID})
    assert common.find_process(device, str(PID)) == PID
    assert common.find_process(device, " TheGame ") == PID
    with pytest.raises(common.ProcessNotFound, match="no running process named 'Nope'.*pass its pid"):
        common.find_process(device, "Nope")
    with pytest.raises(common.ProcessNotFound):
        with attach(device, "Nope"):
            pass
    assert device.calls == []                                                   # nothing was attached to


def test_an_agent_that_refuses_its_params_is_reported_and_the_app_is_left_alone():
    session = FakeSession(init_error=RuntimeError("bad params"))
    device = FakeDevice(session)
    with pytest.raises(common.AgentInitError, match="refused its parameters: bad params"):
        with attach(device, params={}):
            pass
    assert session.detached and device.calls == ["attach"]


def test_an_attach_that_fails_propagates_and_has_nothing_to_detach():
    device = FakeDevice(FakeSession(), attach_error=RuntimeError("unable to attach"))
    with pytest.raises(RuntimeError, match="unable to attach"):
        with attach(device):
            pass


# ---------------------------------------------------------------------------
# run_dump: polling and printing
# ---------------------------------------------------------------------------

@pytest.fixture
def run_dump_h(monkeypatch):
    holder = {}
    monkeypatch.setitem(sys.modules, "frida", make_frida_module(holder))
    module = import_fresh(monkeypatch, "run_dump")
    yield module, holder


def status(state, **kw):
    return {"state": state, "record": "TableARecord", "count": 0, "sources": [], "why": None, **kw}


class Clock:
    def __init__(self):
        self.now, self.slept = 0.0, []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def script_with(*statuses, ack=None):
    return FakeSession(snapshot=list(statuses), snapshot_ack=ack).create_script("")


def test_take_snapshot_polls_until_the_agent_says_done_and_prints_each_phase_once(run_dump_h):
    run_dump, _ = run_dump_h
    final = status("done", count=3)
    script = script_with(status("waiting"), status("running"), status("running"), final)
    clock, said = Clock(), []
    assert run_dump.take_snapshot(script, 30, poll=0.25, sleep=clock.sleep, clock=clock, say=said.append) == final
    assert said == ["[*] Snapshot waiting...", "[*] Snapshot running..."]
    assert clock.slept == [0.25, 0.25, 0.25] and script.exports_sync.snapshot_calls == 1


def test_a_failed_snapshot_is_returned_as_a_status_not_raised(run_dump_h):
    run_dump, _ = run_dump_h
    failed = status("failed", why="no live object of X found")
    assert run_dump.take_snapshot(script_with(failed), 5, say=lambda *_: None) == failed


def test_a_snapshot_that_never_finishes_times_out_with_what_the_agent_last_said(run_dump_h):
    run_dump, _ = run_dump_h
    clock = Clock()
    result = run_dump.take_snapshot(script_with(status("running")), 1.0, poll=0.25, sleep=clock.sleep, clock=clock,
                                    say=lambda *_: None)
    assert result["state"] == "failed" and "no result after 1s" in result["why"] and "'running'" in result["why"]


def test_an_agent_that_will_not_start_or_has_no_snapshot_is_a_failed_status(run_dump_h):
    run_dump, _ = run_dump_h
    refused = run_dump.take_snapshot(script_with(status("idle"), ack={"started": False, "why": "a snapshot is already running"}), 5)
    assert refused["state"] == "failed" and refused["why"] == "a snapshot is already running"
    plain = FakeSession().create_script("")                       # a dump agent: no snapshot() export
    result = run_dump.take_snapshot(plain, 5)
    assert result["state"] == "failed" and "has no snapshot()" in result["why"]


def test_the_console_says_per_source_what_was_found_and_what_was_rejected(run_dump_h):
    run_dump, _ = run_dump_h
    done = status("done", count=4, elapsed_ms=2500, sources=[
        {"source": "static", "status": "empty", "accepted": 0, "candidates": 0, "why": "the static field is null", "note": None},
        {"source": "heap", "status": "ok", "accepted": 4, "candidates": 9, "rejected": 5, "scanned_bytes": 3 * 1048576,
         "unreadable": 1, "why": None, "examples": [{"at": "0x10", "problems": ["enabled: 5 is not one of 0, 1"]}]}])
    lines = run_dump.render_snapshot(done)
    assert lines[0] == "[!] static: empty - 0 record(s) (the static field is null)"
    assert lines[1] == "[+] heap: ok - 4 of 9 candidate(s) fit the layout, 5 rejected, 3 MiB scanned, 1 unreadable"
    assert lines[2] == "      rejected 0x10: enabled: 5 is not one of 0, 1"
    assert lines[-1] == "[+] Snapshot: 4 unique record(s) in 2.5s"
    failed = run_dump.render_snapshot(status("failed", why="nothing"))
    assert failed == ["[!] Snapshot found nothing to export: nothing"]


# ---------------------------------------------------------------------------
# run_dump: the whole command
# ---------------------------------------------------------------------------

@pytest.fixture
def cli(tmp_path, monkeypatch, run_dump_h):
    run_dump, holder = run_dump_h
    agent = tmp_path / "agent.js"
    agent.write_text("// agent\n", encoding="utf-8")
    out = tmp_path / "records_test.json"
    monkeypatch.setattr("builtins.input", lambda *_: "")
    loaded = []
    monkeypatch.setattr(run_dump, "load_agent_source", lambda path: loaded.append(path) or "// agent")

    def go(*argv, snapshot=None, ack=None, processes=None, explicit_agent=True):
        session = FakeSession(snapshot=snapshot, snapshot_ack=ack)
        holder["device"] = FakeDevice(session, processes=processes)
        monkeypatch.setattr(FakeExports, "get_resolution", lambda self: None, raising=False)
        args = ["run_dump.py", "--out", str(out), "--no-layout-check", "--profile", str(EXAMPLE),
                "--module", "UnityFramework"]
        if explicit_agent:
            args += ["--agent", str(agent)]
        monkeypatch.setattr(sys, "argv", args + list(argv))
        return session, holder["device"]

    return run_dump, go, out, loaded


def exits(run_dump):
    with pytest.raises(SystemExit) as e:
        run_dump.main()
    return e.value.code


def test_snapshot_without_attach_is_a_usage_error(cli, capsys):
    run_dump, go, _out, _loaded = cli
    go("--snapshot")
    assert exits(run_dump) == 2 and "--snapshot reads a running app: add --attach" in capsys.readouterr().err


def test_a_snapshot_is_taken_from_the_running_app_and_exported_with_how_it_was_found(cli):
    run_dump, go, out, _loaded = cli
    done = status("done", count=2, elapsed_ms=40, sources=[{"source": "static", "status": "ok", "accepted": 2, "candidates": 2}])
    session, device = go("--attach", "TheGame", "--snapshot", snapshot=[status("running"), done])
    run_dump.main()
    assert device.calls == ["attach"] and session.detached                       # attached, never resumed or killed
    [(stage, params)] = session.script.exports_sync.inits
    assert stage == "late" and params["snapshot"]["record"] == "TableARecord"
    assert params["snapshot"]["static"]["field"] == "all" and params["snapshot"]["heap"]["class"] == "ExampleTableA"
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["records"] == [{"id": 1}, {"id": 2}]
    assert data["meta"]["snapshot"] == done and data["meta"]["target"] == "com.example.unitygame"


def test_the_snapshot_agent_is_the_default_agent_with_snapshot_and_the_dump_agent_without(cli):
    run_dump, go, _out, loaded = cli
    done = status("done", count=1, sources=[{"source": "heap", "status": "ok", "accepted": 1, "candidates": 1}])
    go("--attach", "TheGame", "--snapshot", snapshot=[done], explicit_agent=False)
    run_dump.main()
    assert loaded and Path(loaded[0]).name == "snapshot_records.js" and Path(loaded[0]).parent.name == "dist"
    loaded.clear()
    go("--attach", "TheGame", explicit_agent=False)
    run_dump.main()
    assert Path(loaded[0]).name == "dump_table_a.js"


def test_a_snapshot_that_found_nothing_exits_5_and_writes_nothing(cli, capsys):
    run_dump, go, out, _loaded = cli
    out.write_text('{"good": "earlier dump"}', encoding="utf-8")
    session, device = go("--attach", "TheGame", "--snapshot", snapshot=[status("failed", why="no live object of X found")])
    assert exits(run_dump) == run_dump.EXIT_SNAPSHOT_FAILED == 5
    assert out.read_text(encoding="utf-8") == '{"good": "earlier dump"}'           # an empty snapshot never replaces a file
    text = capsys.readouterr().out
    assert "Snapshot found nothing to export: no live object of X found" in text
    assert session.detached and device.calls == ["attach"]


def test_a_dump_agent_given_to_snapshot_is_refused_before_anything_is_taken(cli, capsys):
    run_dump, go, _out, _loaded = cli
    # FakeExports answers get_count for any agent, so what fails here is the snapshot() the agent does not have
    session, _device = go("--attach", "TheGame", "--snapshot", snapshot=None)
    assert exits(run_dump) == 5 and "has no snapshot()" in capsys.readouterr().out
    assert session.detached


def test_attach_without_snapshot_listens_exports_and_detaches_without_touching_the_app(cli, capsys):
    run_dump, go, out, _loaded = cli
    session, device = go("--attach", "TheGame")
    run_dump.main()
    text = capsys.readouterr().out
    assert device.calls == ["attach"] and session.detached
    assert "The app keeps running; it is not restarted or killed" in text and "use --snapshot for that" in text
    assert json.loads(out.read_text(encoding="utf-8"))["meta"]["snapshot"] is None


def test_an_attach_by_pid_needs_no_name_lookup(cli):
    run_dump, go, _out, _loaded = cli
    _session, device = go("--attach", str(PID), processes={})
    run_dump.main()
    assert device.calls == ["attach"]


def test_a_process_that_is_not_running_is_one_error_line_and_nothing_is_attached(cli, capsys):
    run_dump, go, out, _loaded = cli
    _session, device = go("--attach", "Nope")
    code = exits(run_dump)
    assert "no running process named 'Nope'" in str(code) and "the app was not left running" not in str(code)
    assert device.calls == [] and not out.exists()


def test_snapshot_needs_a_profile_that_says_where_the_table_lives(cli, monkeypatch, capsys):
    run_dump, go, _out, _loaded = cli
    go("--attach", "TheGame", "--snapshot")
    monkeypatch.setattr(sys, "argv", [a for a in sys.argv if a not in ("--profile", str(EXAMPLE))] + ["--target", "x"])
    assert "--snapshot needs --profile" in str(exits(run_dump))
    go("--attach", "TheGame", "--snapshot", "Nope")
    assert "has no record 'Nope'" in str(exits(run_dump))


def test_the_driver_says_what_it_will_look_for(cli, capsys):
    run_dump, go, _out, _loaded = cli
    done = status("done", count=1, sources=[{"source": "static", "status": "ok", "accepted": 1, "candidates": 1}])
    go("--attach", "TheGame", "--snapshot", snapshot=[done])
    run_dump.main()
    assert "[i] snapshot of TableARecord: static ExampleNamespace.ExampleTableB.all (list); heap ExampleNamespace.ExampleTableA" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# a diff between a hooked dump and a snapshot says they were made differently
# ---------------------------------------------------------------------------

def test_diff_notes_when_one_dump_was_read_from_the_heap_and_the_other_hooked():
    records = [{"id": i, "name": f"n{i}"} for i in range(1, 6)]
    hooked = diff_records.Dump("a.json", records, {"snapshot": None})
    snap = diff_records.Dump("b.json", records, {"snapshot": {"state": "done", "sources": [
        {"source": "static", "status": "empty"}, {"source": "heap", "status": "ok"}]}})
    report = diff_records.diff(hooked, snap, key=["id"])
    assert report["build"] == ["how the table was read: hooked -> snapshot (heap)"]
    both = diff_records.diff(snap, snap, key=["id"])
    assert both["build"] == []
