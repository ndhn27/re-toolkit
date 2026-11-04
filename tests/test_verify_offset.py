"""
Tests for the driver retk verify: candidates in, a verdict and an exit status out.

No device and no real Frida (a stub `frida` module, as in test_run_dump.py): the fakes record
what was called and what the agent was handed, and answer getVerification() with whatever the
test scripts. What is pinned here:

  * where the candidates come from - a relocate report, --candidate, the profile's own offset -
    each RVA hooked once, a candidate without an RVA refused, and nothing to verify is an error;
  * what reaches the agent (the record, the candidates by id) and the lifecycle around it: an
    agent that is not the verification agent is caught BEFORE the app is resumed, a failure
    kills the suspended app, the session is always detached;
  * the waiting: it ends as soon as every hooked candidate has enough records, at --wait, or
    when the session dies; progress is printed once per change;
  * the verdicts and exit statuses: 0 verified, 3 rejected/crashed, 4 not verified, 5 ambiguous,
    and a crash reported as a crash.

Run from the repo root:

    pytest
"""
import json
import sys
import threading
from pathlib import Path

import pytest

from fake_frida import FakeDevice, FakeSession, make_frida_module
from stub_import import import_fresh
from test_verification import cand, health, snap

EXAMPLE = str(Path(__file__).resolve().parent.parent / "profile.example.json")
EMPTY = health(calls=0, fields={})


@pytest.fixture
def driver(tmp_path, monkeypatch):
    """retk verify against a stub frida: (module, install, run, tmp_path). `run(*args)` calls
    main() with the standard arguments plus `args`; it returns the exit status (0 if main() returned)."""
    holder = {}
    monkeypatch.setitem(sys.modules, "frida", make_frida_module(holder))
    module = import_fresh(monkeypatch, "verify_offset")
    monkeypatch.setattr(module, "POLL_SECONDS", 0.01)
    agent = tmp_path / "verify_hook.js"
    agent.write_text("// agent\n", encoding="utf-8")

    def install(session, **device_kwargs):
        holder["device"] = FakeDevice(session, **device_kwargs)
        return holder["device"]

    def run(*args, standard=True):
        base = ["--profile", EXAMPLE, "--agent", str(agent), "--wait", "0.2"] if standard else []
        try:
            module.main([*base, *args])
        except SystemExit as e:
            return e.code
        return 0

    yield module, install, run, tmp_path


def sent(session):
    [(stage, params)] = session.script.exports_sync.inits
    assert stage == "early"
    return params


# --- the happy path and what reaches the agent -----------------------------------

def test_a_verified_candidate_exits_0_and_the_agent_gets_the_record_and_the_candidates(driver, capsys):
    _module, install, run, _ = driver
    session = FakeSession(verification=snap(cand("c0", rva=0x1234)))
    device = install(session)

    assert run("--candidate", "0x1234", "--module", "UnityFramework") == 0

    assert device.calls == ["spawn", "attach", "resume"] and session.detached
    params = sent(session)
    assert params["verify"] == {"record": "TableARecord", "candidates": [{"id": "c0", "rva": 0x1234}]}
    assert set(params["layouts"]["records"]) == {"TableARecord", "TableBRecord"}
    out = capsys.readouterr().out
    assert "[+] VERIFIED  c0 RVA 0x1234 (--candidate)" in out and "[+] VERIFIED - the app calls it" in out


def test_it_stops_waiting_as_soon_as_every_hooked_candidate_has_enough_records(driver, capsys):
    _module, install, run, _ = driver
    partial = snap(cand("c0", h=health(calls=1)), cand("c1", rva=0x2000, enters=0, h=EMPTY))
    done = snap(cand("c0", h=health(calls=4)), cand("c1", rva=0x2000, h=health(calls=3)))
    session = FakeSession(verification=[partial, partial, done])
    install(session)

    code = run("--candidate", "0x1234", "--candidate", "0x2000", "--module", "UnityFramework", "--wait", "30")

    assert code == 5                                                       # both verified: ambiguous
    out = capsys.readouterr().out
    assert "Every hooked candidate has enough records" in out
    assert out.count("[~] c0 0x1234: 6 call(s), 1 record(s) | c1 0x2000: 0 call(s), 0 record(s)") == 1   # one line per CHANGE


def test_the_wait_ends_at_the_deadline_with_what_was_seen(driver, capsys):
    _module, install, run, _ = driver
    install(FakeSession(verification=snap(cand("c0", enters=0, h=EMPTY))))

    assert run("--candidate", "0x1234", "--module", "UnityFramework", "--wait", "0.05") == 4

    out = capsys.readouterr().out
    assert "--wait 0.05 s is up" in out and "NOT EXERCISED" in out and "was never called" in out


def test_a_rejected_candidate_exits_3(driver, capsys):
    _module, install, run, _ = driver
    install(FakeSession(verification=snap(cand("c0", h=health(bad_pointer=6)))))
    assert run("--candidate", "0x1234", "--module", "UnityFramework") == 3
    assert "[!] REJECTED  c0" in capsys.readouterr().out


def test_two_candidates_that_verify_exit_5(driver):
    _module, install, run, _ = driver
    install(FakeSession(verification=snap(cand("c0"), cand("c1", rva=0x2000))))
    assert run("--candidate", "0x1234", "--candidate", "0x2000", "--module", "UnityFramework") == 5


def test_a_weak_run_is_not_a_pass(driver):
    _module, install, run, _ = driver
    install(FakeSession(verification=snap(cand("c0", h=health(calls=2)))))
    assert run("--candidate", "0x1234", "--module", "UnityFramework") == 4


def test_min_records_reaches_the_judge(driver):
    _module, install, run, _ = driver
    install(FakeSession(verification=snap(cand("c0", h=health(calls=2)))))
    assert run("--candidate", "0x1234", "--module", "UnityFramework", "--min-records", "2") == 0


# --- where the candidates come from ---------------------------------------------------

def relocate_report(tmp_path, *entries, result="ambiguous"):
    path = tmp_path / "relocate_new.json"
    path.write_text(json.dumps({"version": 1, "result": result, "candidates": [
        {"file_offset": fo, "rva": rva, "confidence": conf} for fo, rva, conf in entries]}), encoding="utf-8")
    return str(path)


def test_every_candidate_of_a_relocate_report_is_hooked_and_labelled(driver, capsys):
    _module, install, run, tmp_path = driver
    session = FakeSession(verification=snap(cand("c0", rva=0x1000), cand("c1", rva=0x2000, enters=0, h=EMPTY)))
    install(session)
    report = relocate_report(tmp_path, ("0x5000", "0x1000", "HIGH"), ("0x6000", "0x2000", "MEDIUM"))

    assert run("--from-relocate", report, "--module", "UnityFramework") == 0

    assert sent(session)["verify"]["candidates"] == [{"id": "c0", "rva": 0x1000}, {"id": "c1", "rva": 0x2000}]
    out = capsys.readouterr().out
    assert "c0 RVA 0x1000 (relocate HIGH, file offset 0x5000)" in out
    assert "c1 RVA 0x2000 (relocate MEDIUM, file offset 0x6000)" in out


def test_a_report_candidate_without_an_rva_is_refused_with_the_way_out(driver):
    module, install, _run, tmp_path = driver
    device = install(FakeSession(verification=snap()))
    report = relocate_report(tmp_path, ("0x5000", None, "HIGH"))
    with pytest.raises(SystemExit) as e:
        module.main(["--profile", EXAMPLE, "--module", "UnityFramework", "--from-relocate", report])
    assert "has no RVA" in str(e.value) and "--candidate RVA" in str(e.value) and device.calls == []


@pytest.mark.parametrize("content, message", [
    ("not json", "Expecting value"),
    ('{"version": 2, "candidates": []}', "not a relocate_offset.py --json report"),
    ('{"version": 1, "candidates": [], "result": "none"}', "found no candidate \\(result: none\\)"),
    ("[]", "not a relocate_offset.py --json report"),
])
def test_a_bad_report_is_refused_before_anything_is_spawned(driver, content, message):
    module, install, _run, tmp_path = driver
    device = install(FakeSession())
    path = tmp_path / "relocate_bad.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(SystemExit, match=message):
        module.main(["--profile", EXAMPLE, "--module", "UnityFramework", "--from-relocate", str(path)])
    assert device.calls == []


def test_a_missing_report_is_refused(driver):
    module, install, _run, tmp_path = driver
    install(FakeSession())
    with pytest.raises(SystemExit, match="relocate_nope.json"):
        module.main(["--profile", EXAMPLE, "--module", "UnityFramework", "--from-relocate",
                     str(tmp_path / "relocate_nope.json")])


def test_without_any_candidate_the_profiles_own_offset_is_checked(driver, capsys):
    _module, install, run, _ = driver
    session = FakeSession(verification=snap(cand("c0", rva=0x40)))
    install(session)
    assert run("--module", "UnityFramework", "--offset", "table_a=0x40") == 0
    assert sent(session)["verify"]["candidates"] == [{"id": "c0", "rva": 0x40}]
    assert "the profile's table_a" in capsys.readouterr().out


def test_with_nothing_to_verify_it_says_how_to_give_a_candidate(driver):
    module, install, _run, _ = driver
    device = install(FakeSession())
    with pytest.raises(SystemExit, match="no candidate to verify"):
        module.main(["--profile", EXAMPLE, "--module", "UnityFramework"])       # the example profile's offsets are 0
    assert device.calls == []


def test_a_candidate_given_twice_is_hooked_once(driver):
    _module, install, run, _ = driver
    session = FakeSession(verification=snap(cand("c0", rva=0x1234)))
    install(session)
    run("--candidate", "0x1234", "--candidate", "1234", "--module", "UnityFramework")
    assert sent(session)["verify"]["candidates"] == [{"id": "c0", "rva": 0x1234}]


def test_gather_candidates_orders_by_source_dedupes_and_caps(driver):
    module, *_ = driver
    got = module.gather_candidates([(0x10, "relocate")], [0x20, 0x10], 0x30, "table_a")
    assert [(c["id"], c["rva"], c["label"]) for c in got] == [("c0", 0x10, "relocate"), ("c1", 0x20, "--candidate")]
    with pytest.raises(module.CandidateError, match="more than 16"):
        module.gather_candidates([], list(range(1, 20)), None, "table_a")


# --- the record --------------------------------------------------------------------------

def test_the_record_defaults_per_key_and_can_be_named(driver):
    _module, install, run, _ = driver
    session = FakeSession(verification=snap(cand("c0", rva=0x40)))
    install(session)
    run("--candidate", "0x40", "--module", "UnityFramework", "--key", "table_b")
    assert sent(session)["verify"]["record"] == "TableBRecord"

    session = FakeSession(verification=snap(cand("c0", rva=0x40)))
    install(session)
    run("--candidate", "0x40", "--module", "UnityFramework", "--record", "TableBRecord")
    assert sent(session)["verify"]["record"] == "TableBRecord"


@pytest.mark.parametrize("args, message", [
    (["--key", "lookup_by_pattern"], "which record does `lookup_by_pattern` hand back"),
    (["--record", "Nope"], "define no record 'Nope' \\(it has: TableARecord, TableBRecord\\)"),
])
def test_an_unknown_record_is_refused_before_anything_is_spawned(driver, args, message):
    module, install, _run, _ = driver
    device = install(FakeSession())
    with pytest.raises(SystemExit, match=message):
        module.main(["--profile", EXAMPLE, "--module", "UnityFramework", "--candidate", "0x40", *args])
    assert device.calls == []


def test_a_profile_without_layouts_cannot_verify(driver):
    module, install, _run, _ = driver
    device = install(FakeSession())
    with pytest.raises(SystemExit, match="no `layouts`"):
        module.main(["--target", "com.example.app", "--module", "UnityFramework", "--candidate", "0x40"])
    assert device.calls == []


# --- lifecycle -----------------------------------------------------------------------------

def test_an_agent_that_is_not_the_verification_agent_is_caught_before_the_app_is_resumed(driver):
    module, install, _run, tmp_path = driver
    session = FakeSession()                                                 # no getVerification()
    device = install(session)
    with pytest.raises(SystemExit, match="exposes no getVerification"):
        module.main(["--profile", EXAMPLE, "--agent", str(tmp_path / "verify_hook.js"), "--module", "UnityFramework",
                     "--candidate", "0x40"])
    assert device.calls == ["spawn", "attach", "kill"] and session.detached


def test_an_agent_that_refuses_its_params_kills_the_app_and_says_why(driver):
    module, install, _run, tmp_path = driver
    session = FakeSession(init_error=RuntimeError("verify.candidates[c0].rva is missing or 0"))
    device = install(session)
    with pytest.raises(SystemExit, match="rva is missing or 0"):
        module.main(["--profile", EXAMPLE, "--agent", str(tmp_path / "verify_hook.js"), "--module", "UnityFramework",
                     "--candidate", "0x40"])
    assert device.calls == ["spawn", "attach", "kill"]


# --- the session dying -------------------------------------------------------------------

def test_an_app_that_dies_is_reported_as_a_crash_with_the_last_counts(driver, capsys):
    _module, install, run, _ = driver
    session = FakeSession()
    sequence = snap(cand("c0", h=health(calls=1)))

    def verification(n):
        if n == 3:
            session.fire_detached("process-terminated")                    # the app dies after the second poll
            raise RuntimeError("the connection is closed")
        return sequence

    session._verification = verification
    install(session)

    assert run("--candidate", "0x1234", "--module", "UnityFramework", "--wait", "30") == 3

    out = capsys.readouterr().out
    assert "Session detached, reason: process-terminated" in out
    assert "[!] CRASHED  c0" in out and "one at a time" in out


def test_a_connection_that_drops_is_not_called_a_crash(driver, capsys):
    _module, install, run, _ = driver
    session = FakeSession()

    def verification(n):
        session.fire_detached("connection-terminated")
        raise RuntimeError("gone")

    session._verification = lambda n: snap(cand("c0", h=health(calls=1))) if n < 3 else verification(n)   # n=1 is the pre-resume check
    install(session)

    assert run("--candidate", "0x1234", "--module", "UnityFramework", "--wait", "30") == 4
    out = capsys.readouterr().out
    assert "CRASHED" not in out and "WEAK" in out and "Session detached, reason: connection-terminated" in out


def test_our_own_detach_is_not_a_session_loss(driver, capsys):
    _module, install, run, _ = driver
    session = FakeSession(verification=snap(cand("c0")))
    install(session)
    run("--candidate", "0x1234", "--module", "UnityFramework")
    assert "Session detached, reason" not in capsys.readouterr().out


def test_an_agent_that_never_answers_gives_unverified_with_the_reason(driver, capsys):
    _module, install, run, _ = driver
    session = FakeSession(verification=lambda n: (_ for _ in ()).throw(RuntimeError("no answer")) if n > 1 else snap())
    install(session)
    code = run("--candidate", "0x1234", "--module", "UnityFramework", "--wait", "0.05")
    assert code == 4 and "NOT VERIFIED" in capsys.readouterr().out


# --- the report file and arguments ---------------------------------------------------------

def test_json_writes_the_verdict_with_what_was_verified(driver, capsys):
    _module, install, run, tmp_path = driver
    install(FakeSession(verification=snap(cand("c0", rva=0x1234))))
    out_path = tmp_path / "verify_test.json"

    assert run("--candidate", "0x1234", "--module", "UnityFramework", "--json", str(out_path)) == 0

    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["outcome"] == "verified" and data["exit_code"] == 0
    assert data["meta"]["record"] == "TableARecord" and data["meta"]["candidates"] == [
        {"id": "c0", "rva": "0x1234", "label": "--candidate"}]
    assert data["meta"]["profile"] == "profile.example" and data["candidates"][0]["status"] == "verified"


@pytest.mark.parametrize("args, flag", [
    (["--min-records", "0"], "min-records"), (["--min-records", "x"], "min-records"),
    (["--wait", "-1"], "wait"), (["--layout-tolerance", "2"], "layout-tolerance"),
    (["--candidate", "zz"], "candidate"),
])
def test_bad_numbers_are_usage_errors(driver, args, flag, capsys):
    module, install, _run, _ = driver
    device = install(FakeSession())
    with pytest.raises(SystemExit) as e:
        module.main(["--profile", EXAMPLE, "--module", "UnityFramework", "--candidate", "0x40", *args])
    assert e.value.code == 2 and flag in capsys.readouterr().err and device.calls == []


def test_no_module_anywhere_is_refused_before_anything_is_spawned(driver):
    module, install, _run, _ = driver
    device = install(FakeSession())
    with pytest.raises(SystemExit, match="--module"):
        module.main(["--target", "com.example.app", "--candidate", "0x40"])
    assert device.calls == []


# --- watch() on its own -----------------------------------------------------------------------

def test_watch_returns_the_last_snapshot_even_when_the_final_ask_fails(driver):
    module, *_ = driver
    session = FakeSession(verification=lambda n: snap(cand("c0", h=health(calls=1))) if n < 3 else (_ for _ in ()).throw(RuntimeError("x")))
    script = session.create_script("")
    result = module.watch(script, threading.Event(), 3, 0.05, {}, poll=0.01)
    assert result["candidates"][0]["health"]["calls"] == 1


def test_watch_does_not_ask_a_dead_session(driver):
    module, *_ = driver
    session = FakeSession(verification=snap(cand("c0")))
    script = session.create_script("")
    gone = threading.Event()
    gone.set()
    assert module.watch(script, gone, 3, 5, {}, poll=0.01) is None
    assert script.exports_sync.verification_calls == 0
