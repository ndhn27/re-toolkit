"""
Unit tests for the spawn -> attach -> load -> init -> resume -> export ->
detach lifecycle in retk dump.

No device and no real Frida: a stub `frida` module is installed in
sys.modules before the driver is imported, and its device/session/script are
small fakes that record what was called. What's pinned here:

  - a failure anywhere before resume kills the still-suspended process and
    detaches the session, and the error still propagates;
  - the profile and --offset overrides reach the agent through init(), and
    the export's `meta` says which offsets were used;
  - an agent that refuses its parameters (a missing offset) exits cleanly with
    the reason and leaves nothing running;
  - the happy path resumes, exports and detaches without killing anything;
  - Ctrl+C at the "press Enter" prompt still exports and detaches;
  - the layout self-check: the agent's health is judged at export, the verdict is
    printed and recorded in `meta.layout_check`, a failed layout still writes the
    file (marked) and exits with status 3 AFTER detaching, --no-layout-check and
    --layout-tolerance do what they say, and an agent without getHealth() is
    "unverified", never "ok".

Run from the repo root:

    pytest
"""
import json
import sys
from pathlib import Path

import pytest

from fake_frida import FakeDevice, FakeSession, make_frida_module
from stub_import import import_fresh

EXAMPLE = str(Path(__file__).resolve().parent.parent / "profile.example.json")


@pytest.fixture
def driver(tmp_path, monkeypatch):
    """Import retk dump against a stub frida module and return
    (module, install, out_path); install.argv(*args) replaces the command line."""
    holder = {}

    monkeypatch.setitem(sys.modules, "frida", make_frida_module(holder))
    module = import_fresh(monkeypatch, "run_dump")

    agent = tmp_path / "agent.js"
    agent.write_text("// agent\n", encoding="utf-8")
    out = tmp_path / "records_test.json"
    monkeypatch.setattr("builtins.input", lambda *_: "")

    def argv(*extra):
        monkeypatch.setattr(sys, "argv", ["run_dump.py", "--agent", str(agent), "--out", str(out), *extra])

    argv("--target", "com.example.app", "--module", "UnityFramework", "--offset", "table_a=0x1234")

    def install(session, **device_kwargs):
        holder["device"] = FakeDevice(session, **device_kwargs)
        return holder["device"]

    install.argv = argv
    yield module, install, out


@pytest.mark.parametrize("kwargs", [
    {"create_script_error": RuntimeError("bad script")},
    {"load_error": RuntimeError("hook install failed")},
])
def test_failure_before_resume_kills_process_and_detaches(driver, kwargs):
    module, install, out = driver
    session = FakeSession(**kwargs)
    device = install(session)

    with pytest.raises(RuntimeError):
        module.main()

    assert "resume" not in device.calls
    assert "kill" in device.calls
    assert session.detached
    assert not out.exists()


def test_happy_path_resumes_exports_and_detaches(driver):
    module, install, out = driver
    session = FakeSession()
    device = install(session)

    module.main()

    assert device.calls == ["spawn", "attach", "resume"]
    assert session.detached
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["records"] == [{"id": 1}, {"id": 2}]
    assert data["meta"]["offsets"] == {"table_a": "0x1234"}
    assert data["meta"]["target"] == "com.example.app"
    assert session.script.exports_sync.inits == [
        ("early", {"module": "UnityFramework", "offsets": {"table_a": 0x1234},
                   "check": {"sample": 16, "gate": True}})]


def test_profile_layouts_and_cli_offsets_reach_the_agent(driver):
    module, install, out = driver
    session = FakeSession()
    install(session)
    install.argv("--profile", EXAMPLE, "--offset", "table_a=0x40")

    module.main()

    [(stage, params)] = session.script.exports_sync.inits
    assert stage == "early"
    assert params["offsets"]["table_a"] == 0x40          # CLI override of the profile's 0x0
    assert set(params["layouts"]["records"]) == {"TableARecord", "TableBRecord"}
    meta = json.loads(out.read_text(encoding="utf-8"))["meta"]
    assert meta["profile"] == "profile.example"
    assert meta["offsets"] == {"table_a": "0x40"}        # zero offsets aren't "in use"


def test_an_agent_that_refuses_its_params_exits_with_the_reason_and_kills_the_app(driver):
    module, install, out = driver
    session = FakeSession(init_error=RuntimeError("offsets.table_a is missing or 0"))
    device = install(session)

    with pytest.raises(SystemExit, match="offsets.table_a is missing or 0"):
        module.main()

    assert device.calls == ["spawn", "attach", "kill"]
    assert session.detached
    assert not out.exists()


def test_ctrl_c_at_prompt_still_exports_and_detaches(driver, monkeypatch):
    module, install, out = driver
    session = FakeSession()
    device = install(session)

    def interrupted(*_):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", interrupted)
    module.main()

    assert "kill" not in device.calls
    assert session.detached
    assert out.exists()


def test_attach_failure_kills_process(driver):
    # No session ever existed, so there is nothing to detach - but the
    # process is still suspended at spawn and must not be left frozen.
    module, install, out = driver
    session = FakeSession()
    device = install(session, attach_error=RuntimeError("attach failed"))

    with pytest.raises(RuntimeError):
        module.main()

    assert device.calls == ["spawn", "attach", "kill"]
    assert not session.detached
    assert not out.exists()


# --- the layout self-check ---------------------------------------------------

def _field(**kw):
    base = {"type": "u32", "checked": 6, "violations": 0, "bad": 0, "nulls": 0, "has_expect": True,
            "examples": [], "distinct": 6, "min": 1, "max": 6}
    return {**base, **kw}


def _health(bad_pointer=0, violations=0):
    return {"version": 1, "records": [{
        "record": "TableARecord", "calls": 6, "read_errors": 0, "key_conflicts": 0, "internal_errors": 0,
        "klass": {"mode": "constant", "checked": 6, "bad_pointer": bad_pointer, "other": 0,
                  "variants": [["0x200", 6]]},
        "fields": {"id": _field(), "enabled": _field(type="s8", violations=violations, distinct=2,
                                                      examples=["-18 is not one of 0, 1"] * bool(violations))},
    }]}


def test_an_agent_without_getHealth_is_unverified_not_ok(driver, capsys):
    module, install, out = driver
    install(FakeSession())

    module.main()                                  # no exit: unverified is not a failure

    meta = json.loads(out.read_text(encoding="utf-8"))["meta"]
    assert meta["layout_check"]["status"] == "unverified"
    assert any("getHealth" in n and "npm run build" in n for n in meta["layout_check"]["notes"])
    assert "Layout NOT verified" in capsys.readouterr().out


def test_a_layout_that_held_up_is_reported_and_recorded(driver, capsys):
    module, install, out = driver
    install(FakeSession(health=_health()))

    module.main()

    meta = json.loads(out.read_text(encoding="utf-8"))["meta"]
    assert meta["layout_check"]["status"] == "ok" and meta["layout_check"]["problems"] == []
    assert meta["layout_check"]["records"][0]["record"] == "TableARecord"
    assert meta["module"] == "UnityFramework"
    assert "Layout check passed" in capsys.readouterr().out


def test_a_failed_layout_still_writes_the_file_but_marks_it_and_exits_3_after_detaching(driver, capsys):
    module, install, out = driver
    session = FakeSession(health=_health(bad_pointer=6, violations=6))
    device = install(session)

    with pytest.raises(SystemExit) as e:
        module.main()

    assert e.value.code == 3
    assert session.detached and "kill" not in device.calls          # the app is not left attached or killed
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["records"] == [{"id": 1}, {"id": 2}]                  # nothing is thrown away...
    assert data["meta"]["layout_check"]["status"] == "fail"           # ...but it can't pass for a good dump
    printed = capsys.readouterr().out
    assert "LAYOUT CHECK FAILED" in printed and "TableARecord.enabled" in printed
    assert printed.index("LAYOUT CHECK FAILED") < printed.index("Wrote ")


def test_no_layout_check_skips_the_judgement_and_says_so(driver, capsys):
    module, install, out = driver
    session = FakeSession(health=_health(bad_pointer=6))
    install(session)
    install.argv("--target", "com.example.app", "--module", "UnityFramework", "--offset", "table_a=0x1234",
                 "--no-layout-check")

    module.main()                                                      # would have exited 3

    assert json.loads(out.read_text(encoding="utf-8"))["meta"]["layout_check"]["status"] == "skipped"
    assert "Layout check skipped" in capsys.readouterr().out


def test_layout_tolerance_moves_the_line(driver):
    module, install, out = driver
    health = _health(violations=1)                                     # 1 of 6 reads breaks `expect`
    install(FakeSession(health=health))
    with pytest.raises(SystemExit) as e:
        module.main()
    assert e.value.code == 3

    install(FakeSession(health=health))
    install.argv("--target", "com.example.app", "--module", "UnityFramework", "--offset", "table_a=0x1234",
                 "--layout-tolerance", "0.2")
    module.main()
    check = json.loads(out.read_text(encoding="utf-8"))["meta"]["layout_check"]
    assert check["status"] == "ok" and check["tolerance"] == 0.2
    assert any("-18 is not one of 0, 1" in n for n in check["notes"])  # tolerated, still reported


@pytest.mark.parametrize("value", ["2", "-0.1", "lots"])
def test_layout_tolerance_must_be_a_fraction(driver, value, capsys):
    module, install, _out = driver
    install(FakeSession())
    install.argv("--target", "com.example.app", "--module", "UnityFramework", "--offset", "table_a=0x1234",
                 "--layout-tolerance", value)
    with pytest.raises(SystemExit) as e:
        module.main()
    assert e.value.code == 2 and "layout-tolerance" in capsys.readouterr().err


def test_no_module_anywhere_is_refused_before_anything_is_spawned(driver):
    module, install, _out = driver
    device = install(FakeSession())
    install.argv("--target", "com.example.app", "--offset", "table_a=0x1234")
    with pytest.raises(SystemExit, match="--module"):
        module.main()
    assert device.calls == []


# --- the early layout gate ---------------------------------------------------

def _bad_health():
    return _health(bad_pointer=6, violations=6)


def _sample(health, sample=16):
    """What the agent send()s after its first N records."""
    return {"type": "layout-sample", "sample": sample, "health": health}


GATE_ARGS = ("--target", "com.example.app", "--module", "UnityFramework", "--offset", "table_a=0x1234")


def test_a_failing_gate_stops_the_run_and_writes_a_suspect_file_not_the_dump(driver, capsys):
    module, install, out = driver
    session = FakeSession(health=_bad_health(), messages=[_sample(_bad_health())])
    device = install(session)

    with pytest.raises(SystemExit) as e:
        module.main()

    assert e.value.code == 3
    assert session.detached and "kill" not in device.calls
    suspect = out.with_name("records_test.suspect.json")
    assert not out.exists() and suspect.exists()                         # never at the path a good dump goes
    meta = json.loads(suspect.read_text(encoding="utf-8"))["meta"]
    assert meta["suspect"] is True
    assert meta["layout_gate"] == {"sample": 16, "action": "stop", "status": "fail", "stopped": True}
    printed = capsys.readouterr().out
    assert "LAYOUT MAY HAVE CHANGED - the first 16 records already contradict" in printed
    assert "Stopping now" in printed and "SUSPECT" in printed
    assert printed.index("LAYOUT MAY HAVE CHANGED") < printed.index("Collected")      # said BEFORE the export


def test_on_drift_warn_reports_but_keeps_the_normal_flow(driver, capsys):
    module, install, out = driver
    install(FakeSession(health=_bad_health(), messages=[_sample(_bad_health())]))
    install.argv(*GATE_ARGS, "--on-drift", "warn")

    with pytest.raises(SystemExit) as e:
        module.main()                                                    # the final check fails too -> 3, as before

    assert e.value.code == 3
    data = json.loads(out.read_text(encoding="utf-8"))                   # written where a dump goes, marked as before
    assert data["meta"]["suspect"] is False and data["meta"]["layout_check"]["status"] == "fail"
    assert data["meta"]["layout_gate"]["stopped"] is False and data["meta"]["layout_gate"]["action"] == "warn"
    printed = capsys.readouterr().out
    assert "LAYOUT MAY HAVE CHANGED" in printed and "Continuing (--on-drift warn)" in printed
    assert not out.with_name("records_test.suspect.json").exists()


def test_a_gate_that_passes_says_so_and_the_export_is_normal(driver, capsys):
    module, install, out = driver
    install(FakeSession(health=_health(), messages=[_sample(_health())]))

    module.main()                                                        # no exit

    meta = json.loads(out.read_text(encoding="utf-8"))["meta"]
    assert meta["suspect"] is False and meta["layout_gate"]["status"] == "ok"
    assert "The first 16 records fit the profile's layout" in capsys.readouterr().out


def test_a_snapshot_that_cannot_be_judged_never_stops_the_run(driver, capsys):
    module, install, out = driver
    install(FakeSession(messages=[_sample({"version": 1, "records": []})]))

    module.main()

    assert json.loads(out.read_text(encoding="utf-8"))["meta"]["layout_gate"]["status"] == "unverified"
    assert "could not be checked" in capsys.readouterr().out


def test_the_gate_judges_with_its_own_looser_line_but_follows_a_looser_tolerance(driver):
    module, install, out = driver
    one_in_six = _health(violations=1)                                   # 17 %: over 5 %, under the gate's 25 %
    install(FakeSession(health=one_in_six, messages=[_sample(one_in_six)]))
    with pytest.raises(SystemExit):
        module.main()                                                    # the export-time check (5 %) fails it...
    meta = json.loads(out.read_text(encoding="utf-8"))["meta"]
    assert meta["layout_gate"]["status"] == "ok" and meta["suspect"] is False    # ...the gate did not stop the run


def test_the_gate_size_reaches_the_agent_and_zero_turns_it_off(driver):
    module, install, out = driver
    session = FakeSession()
    install(session)
    install.argv(*GATE_ARGS, "--layout-gate", "5")
    module.main()
    assert session.script.exports_sync.inits[0][1]["check"] == {"sample": 5, "gate": True}

    session = FakeSession(messages=[_sample(_bad_health())])             # a message nobody asked for is just printed
    install(session)
    install.argv(*GATE_ARGS, "--layout-gate", "0")
    module.main()
    assert "check" not in session.script.exports_sync.inits[0][1]
    assert json.loads(out.read_text(encoding="utf-8"))["meta"]["layout_gate"] is None


def test_no_layout_check_means_no_gate_either(driver):
    module, install, out = driver
    session = FakeSession(health=_bad_health(), messages=[_sample(_bad_health())])
    install(session)
    install.argv(*GATE_ARGS, "--no-layout-check")
    module.main()                                                        # would have stopped
    assert "check" not in session.script.exports_sync.inits[0][1]
    assert json.loads(out.read_text(encoding="utf-8"))["meta"]["layout_check"]["status"] == "skipped"


def test_other_messages_from_the_agent_are_still_printed(driver, capsys):
    module, install, _out = driver
    install(FakeSession(messages=["hello from the agent", {"type": "something-else"}]))
    module.main()
    printed = capsys.readouterr().out
    assert "hello from the agent" in printed and "something-else" in printed


@pytest.mark.parametrize("value", ["-1", "many", "1.5"])
def test_layout_gate_must_be_a_whole_number_of_records(driver, value, capsys):
    module, install, _out = driver
    install(FakeSession())
    install.argv(*GATE_ARGS, "--layout-gate", value)
    with pytest.raises(SystemExit) as e:
        module.main()
    assert e.value.code == 2 and "layout-gate" in capsys.readouterr().err


def test_suspect_path_keeps_the_stem_so_the_gitignore_rule_still_covers_it(driver):
    module, _install, _out = driver
    assert module.suspect_path("records.json") == "records.suspect.json"
    assert module.suspect_path("/x/records_ab68fc8.json") == "/x/records_ab68fc8.suspect.json"
    assert module.suspect_path("dump") == "dump.suspect"
