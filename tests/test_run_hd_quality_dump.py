"""
Unit tests for the spawn -> attach -> load -> resume -> export -> detach
lifecycle in tools/run_hd_quality_dump.py.

No device and no real Frida: a stub `frida` module is installed in
sys.modules before the driver is imported, and its device/session/script are
small fakes that record what was called. What's pinned here:

  - a failure anywhere before resume kills the still-suspended process and
    detaches the session, and the error still propagates;
  - the happy path resumes, exports and detaches without killing anything;
  - Ctrl+C at the "press Enter" prompt still exports and detaches.

Run from the repo root:

    pytest
"""
import importlib
import json
import sys
import types

import pytest

PID = 4242


class FakeExports:
    def get_count(self):
        return 2

    def get_records(self):
        return [{"id": 1}, {"id": 2}]


class FakeScript:
    def __init__(self, load_error=None):
        self.exports_sync = FakeExports()
        self._load_error = load_error

    def on(self, *_):
        pass

    def load(self):
        if self._load_error:
            raise self._load_error


class FakeSession:
    def __init__(self, create_script_error=None, load_error=None):
        self._create_script_error = create_script_error
        self._load_error = load_error
        self.detached = False

    def on(self, *_):
        pass

    def create_script(self, _source):
        if self._create_script_error:
            raise self._create_script_error
        return FakeScript(self._load_error)

    def detach(self):
        self.detached = True


class FakeDevice:
    def __init__(self, session):
        self.session = session
        self.calls = []

    def spawn(self, _argv):
        self.calls.append("spawn")
        return PID

    def attach(self, pid):
        assert pid == PID
        self.calls.append("attach")
        return self.session

    def resume(self, pid):
        assert pid == PID
        self.calls.append("resume")

    def kill(self, pid):
        assert pid == PID
        self.calls.append("kill")


@pytest.fixture
def driver(tmp_path, monkeypatch):
    """Import tools/run_hd_quality_dump.py against a stub frida module and
    return (module, argv-setter, out_path)."""
    holder = {}

    fake_frida = types.ModuleType("frida")
    fake_frida.get_device_manager = lambda: types.SimpleNamespace(
        add_remote_device=lambda _addr: holder["device"])
    monkeypatch.setitem(sys.modules, "frida", fake_frida)
    monkeypatch.delitem(sys.modules, "run_hd_quality_dump", raising=False)
    module = importlib.import_module("run_hd_quality_dump")

    agent = tmp_path / "agent.js"
    agent.write_text("const FRIDA_OFFSET = 0x0;\n", encoding="utf-8")
    out = tmp_path / "records_test.json"
    monkeypatch.setattr(sys, "argv", [
        "run_hd_quality_dump.py", "--offset", "0x1234",
        "--agent", str(agent), "--out", str(out)])
    monkeypatch.setattr("builtins.input", lambda *_: "")

    def install(session):
        holder["device"] = FakeDevice(session)
        return holder["device"]

    yield module, install, out
    sys.modules.pop("run_hd_quality_dump", None)


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
    assert data["meta"]["offset"] == "0x1234"


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
