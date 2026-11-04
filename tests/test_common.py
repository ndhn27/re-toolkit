"""
Unit tests for retk/_common.py: the command line -> profile -> agent
parameters resolution that every driver shares, and the spawn -> attach ->
load -> init -> resume -> detach lifecycle.

No device and no real Frida: a profile is a JSON file written to tmp_path (or
profile.example.json), and the lifecycle runs against the fakes in
fake_frida.py.

Run from the repo root:

    pytest
"""
import argparse
import json
import subprocess
import threading
import types
from pathlib import Path

import pytest

from retk import _common as common
from retk import profiles
from fake_frida import PID, FakeDevice, FakeSession

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "profile.example.json"


def args(**kw):
    """What resolve_settings() reads off the parsed command line."""
    return argparse.Namespace(**{"profile": None, "target": None, "remote": None, "module": None,
                                 "offset": None, **kw})


def write_profile(tmp_path, **fields):
    """A profile file; its module is UnityFramework unless said otherwise (module=None omits it)."""
    raw = {"target": "com.example.profiled", "module": "UnityFramework", **fields}
    path = tmp_path / "p.json"
    path.write_text(json.dumps({k: v for k, v in raw.items() if v is not None}), encoding="utf-8")
    return str(path)


# --- parse_offset / parse_offset_override ---

def test_parse_offset_with_and_without_0x_prefix():
    assert common.parse_offset("0xab68fc8") == common.parse_offset("ab68fc8") == 0xab68fc8


@pytest.mark.parametrize("text", ["not-a-hex-value", "-5", ""])
def test_parse_offset_rejects_non_hex_and_negative(text):
    with pytest.raises(argparse.ArgumentTypeError):
        common.parse_offset(text)


def test_parse_offset_override():
    assert common.parse_offset_override("table_a=0xab68fc8") == ("table_a", 0xab68fc8)
    assert common.parse_offset_override("table_a=ab68fc8") == ("table_a", 0xab68fc8)


@pytest.mark.parametrize("text", ["0xab68fc8", "=0x10", "bad key=0x10", "table_a=zz"])
def test_parse_offset_override_rejects_anything_but_key_equals_hex(text):
    with pytest.raises(argparse.ArgumentTypeError):
        common.parse_offset_override(text)


# --- add_override_args ---

def test_offset_flag_is_repeatable_and_collected_as_pairs():
    parser = argparse.ArgumentParser()
    common.add_override_args(parser)
    got = parser.parse_args(["--offset", "table_a=0x10", "--offset", "table_b=20"])
    assert got.offset == [("table_a", 0x10), ("table_b", 0x20)]


def test_offset_flag_is_absent_when_disabled():
    # e.g. list_exports.py's driver: its agent hooks no address.
    parser = argparse.ArgumentParser()
    common.add_override_args(parser, offsets=False)
    with pytest.raises(SystemExit):
        parser.parse_args(["--offset", "table_a=0x10"])


# --- resolve_settings ---

def test_cli_target_and_module_are_enough_without_a_profile():
    s = common.resolve_settings(args(target="com.example.cli", module="UnityFramework"))
    assert (s.target, s.remote_addr, s.profile) == ("com.example.cli", profiles.DEFAULT_REMOTE, None)
    assert s.params == {"module": "UnityFramework", "offsets": {}}


def test_no_module_anywhere_exits_and_says_how_to_set_it(capsys):
    # There is no platform default: UnityFramework is an iOS name, and silently
    # waiting for it on Android looks exactly like an app that loads late.
    with pytest.raises(SystemExit) as e:
        common.resolve_settings(args(target="com.example.cli"))
    assert "--module" in str(e.value) and "libil2cpp.so" in str(e.value)


def test_a_profile_without_a_module_needs_the_flag(tmp_path):
    ref = write_profile(tmp_path, module=None)
    with pytest.raises(SystemExit, match="--module"):
        common.resolve_settings(args(profile=ref))
    assert common.resolve_settings(args(profile=ref, module="libil2cpp.so")).params["module"] == "libil2cpp.so"


def test_the_module_flag_beats_the_profile_and_both_say_where_it_came_from(tmp_path, capsys):
    ref = write_profile(tmp_path, module="UnityFramework")
    assert common.resolve_settings(args(profile=ref)).params["module"] == "UnityFramework"
    assert "module = UnityFramework  (profile)" in capsys.readouterr().out
    assert common.resolve_settings(args(profile=ref, module="libil2cpp.so")).params["module"] == "libil2cpp.so"
    assert "module = libil2cpp.so  (CLI)" in capsys.readouterr().out


def test_module_flag_is_offered_with_and_without_offsets():
    for offsets in (True, False):
        parser = argparse.ArgumentParser()
        common.add_override_args(parser, offsets=offsets)
        assert parser.parse_args(["--module", "libil2cpp.so"]).module == "libil2cpp.so"
        assert parser.parse_args([]).module is None


def test_no_target_anywhere_exits_and_points_at_profiles():
    with pytest.raises(SystemExit, match="--profile"):
        common.resolve_settings(args())


def test_profile_supplies_target_remote_module_offsets_and_layouts(tmp_path):
    ref = write_profile(tmp_path, remote="10.0.0.5:1", module="libil2cpp.so",
                        offsets={"table_a": "0x40"})
    s = common.resolve_settings(args(profile=ref))
    assert (s.target, s.remote_addr) == ("com.example.profiled", "10.0.0.5:1")
    assert s.params == {"module": "libil2cpp.so", "offsets": {"table_a": 0x40}}
    assert s.offsets == {"table_a": 0x40}
    assert s.profile.name == "p"


def test_the_example_profile_resolves_with_its_layouts_and_zero_offsets():
    s = common.resolve_settings(args(profile=str(EXAMPLE)))
    assert set(s.params["layouts"]["records"]) == {"TableARecord", "TableBRecord"}
    assert set(s.offsets.values()) == {0}


def test_cli_overrides_beat_the_profile_and_say_so(tmp_path, capsys):
    ref = write_profile(tmp_path, offsets={"table_a": "0x40", "table_b": "0x50"})
    s = common.resolve_settings(args(profile=ref, target="com.example.cli", remote="h:1",
                                     offset=[("table_a", 0x99)]))
    assert (s.target, s.remote_addr) == ("com.example.cli", "h:1")
    assert s.offsets == {"table_a": 0x99, "table_b": 0x50}
    out = capsys.readouterr().out
    assert "offset table_a = 0x99  (CLI)" in out
    assert "offset table_b = 0x50  (profile)" in out
    assert "target = com.example.cli  (CLI)" in out


def test_zero_offsets_are_not_announced_as_in_use(tmp_path, capsys):
    common.resolve_settings(args(profile=str(EXAMPLE)))
    assert "offset " not in capsys.readouterr().out


def test_unknown_profile_exits_with_the_reason(tmp_path, monkeypatch):
    monkeypatch.setenv(profiles.ENV_PROFILES_DIR, str(tmp_path))
    with pytest.raises(SystemExit, match="not found"):
        common.resolve_settings(args(profile="nope"))


# --- load_agent_source ---

def test_load_agent_source_reads_the_bundle_verbatim(tmp_path):
    f = tmp_path / "agent.js"
    f.write_text("rpc.exports = {};\n")
    assert common.load_agent_source(f) == "rpc.exports = {};\n"


def test_load_agent_source_missing_file_explains_how_to_build(tmp_path):
    with pytest.raises(FileNotFoundError, match="npm run build"):
        common.load_agent_source(tmp_path / "dist" / "dump_table_a.js")


# --- is_gitignored ---

def _git(cwd, *argv):
    subprocess.run(["git", *argv], cwd=cwd, check=True, capture_output=True)


def test_is_gitignored_true_for_a_covered_name(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("records*.json\n")
    assert common.is_gitignored(tmp_path / "records_ab68fc8.json") is True


def test_is_gitignored_false_for_an_uncovered_name(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("records*.json\n")
    assert common.is_gitignored(tmp_path / "dump_ab68fc8.json") is False


def test_is_gitignored_works_when_the_output_dir_does_not_exist_yet(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("records*.json\n")
    assert common.is_gitignored(tmp_path / "not" / "made" / "yet" / "records.json") is True


def test_is_gitignored_none_outside_a_git_repo(tmp_path):
    # tmp_path has no .git anywhere above it: git can't answer, so the driver
    # must stay quiet, not warn.
    assert common.is_gitignored(tmp_path / "records.json") is None


# --- spawn_agent ---

def run_spawn(session, params, **device_kwargs):
    device = FakeDevice(session, **device_kwargs)
    with common.spawn_agent(device, "com.example.app", "// agent", lambda *_: None, params=params) as run:
        run.resume()
    return device


def test_params_reach_the_agent_through_init_before_resume():
    session = FakeSession()
    params = {"module": "UnityFramework", "offsets": {"table_a": 0x40}}
    device = run_spawn(session, params)
    assert session.script.exports_sync.inits == [("early", params)]
    assert device.calls == ["spawn", "attach", "resume"]
    assert session.detached


def test_no_params_means_init_is_not_called():
    session = FakeSession()
    run_spawn(session, None)
    assert session.script.exports_sync.inits == []


def test_an_agent_that_refuses_its_params_is_reported_and_the_app_is_killed():
    # The agent's init() throws when e.g. an offset is missing; the process is
    # still suspended at spawn and must not be left frozen.
    session = FakeSession(init_error=RuntimeError("offsets.table_a is missing or 0"))
    device = FakeDevice(session)
    with pytest.raises(common.AgentInitError, match="offsets.table_a is missing or 0"):
        with common.spawn_agent(device, "com.example.app", "//", lambda *_: None, params={}):
            pytest.fail("the body must not run")
    assert device.calls == ["spawn", "attach", "kill"]
    assert session.detached


def test_pid_is_exposed_to_the_caller():
    session = FakeSession()
    device = FakeDevice(session)
    with common.spawn_agent(device, "com.example.app", "//", lambda *_: None) as run:
        assert run.pid == PID
        run.resume()


# --- wait_for_enter ------------------------------------------------------------

class _Tty:
    """A stdin that is a terminal and has one line waiting (or none)."""

    def __init__(self, lines=0):
        self.lines = lines
        self.read = 0

    def isatty(self):
        return True

    def readline(self):
        self.read += 1
        return "\n"


def _no_input(*_):
    raise AssertionError("input() must not be called on a terminal when a stop event is given")


def test_without_a_stop_event_it_is_plain_input(monkeypatch):
    asked = []
    monkeypatch.setattr("builtins.input", lambda *_: asked.append(1) or "")
    assert common.wait_for_enter() == "enter" and asked == [1]


def test_off_a_terminal_it_blocks_on_input_and_reports_a_stop_that_happened_meanwhile(monkeypatch):
    stop = threading.Event()
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr("builtins.input", lambda *_: stop.set() or "")   # the gate trips while we wait
    assert common.wait_for_enter(stop) == "stop"
    stop.clear()
    monkeypatch.setattr("builtins.input", lambda *_: "")
    assert common.wait_for_enter(stop) == "enter"


def test_on_a_terminal_a_stop_event_ends_the_wait_without_a_keypress(monkeypatch):
    stop = threading.Event()
    tty = _Tty()
    monkeypatch.setattr("sys.stdin", tty)
    monkeypatch.setattr("builtins.input", _no_input)
    polls = []

    def ready(timeout):
        polls.append(timeout)
        if len(polls) == 3:
            stop.set()                                                    # the agent's snapshot arrives
        return False

    monkeypatch.setattr(common, "_stdin_ready", ready)
    assert common.wait_for_enter(stop, poll=0.01) == "stop"
    assert polls == [0.01, 0.01, 0.01] and tty.read == 0


def test_on_a_terminal_a_line_ends_the_wait_and_is_consumed(monkeypatch):
    tty = _Tty()
    monkeypatch.setattr("sys.stdin", tty)
    monkeypatch.setattr("builtins.input", _no_input)
    monkeypatch.setattr(common, "_stdin_ready", lambda timeout: True)
    assert common.wait_for_enter(threading.Event()) == "enter" and tty.read == 1


def test_ctrl_c_on_a_terminal_propagates_like_input(monkeypatch):
    monkeypatch.setattr("sys.stdin", _Tty())

    def interrupted(timeout):
        raise KeyboardInterrupt

    monkeypatch.setattr(common, "_stdin_ready", interrupted)
    with pytest.raises(KeyboardInterrupt):
        common.wait_for_enter(threading.Event())
