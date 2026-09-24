"""
Unit tests for the spawn -> attach -> load -> resume -> wait -> detach
lifecycle in tools/list_exports.py.

Same approach as test_run_hd_quality_dump.py (stub `frida`, fakes from
fake_frida.py). list_exports.py used to open-code this lifecycle without any
cleanup, so a failed attach / create_script / load left the app frozen at
spawn; it now shares _common.spawn_agent() with the main driver. What's
pinned here:

  - a failure anywhere before resume kills the still-suspended process,
    detaches the session if there is one, and the error still propagates;
  - the happy path resumes, waits for scan-complete and detaches without killing anything;
  - Ctrl+C during the wait detaches and exits cleanly.

Run from the repo root:

    pytest
"""
import importlib
import sys

import pytest

from fake_frida import FakeDevice, FakeSession, make_frida_module


@pytest.fixture
def driver(tmp_path, monkeypatch):
    """Import tools/list_exports.py against a stub frida module and return
    (module, install)."""
    holder = {}

    monkeypatch.setitem(sys.modules, "frida", make_frida_module(holder))
    monkeypatch.delitem(sys.modules, "list_exports", raising=False)
    module = importlib.import_module("list_exports")

    agent = tmp_path / "list_il2cpp_exports.js"
    agent.write_text("// agent\n", encoding="utf-8")
    monkeypatch.setattr(module, "AGENT_PATH", str(agent))
    monkeypatch.setattr(module, "wait_for_scan", lambda _event, _timeout: True)
    monkeypatch.setattr(sys, "argv", [
        "list_exports.py", "--target", "com.example.app", "--remote", "127.0.0.1:1"])

    def install(session, **device_kwargs):
        holder["device"] = FakeDevice(session, **device_kwargs)
        return holder["device"]

    yield module, install
    sys.modules.pop("list_exports", None)


@pytest.mark.parametrize("kwargs", [
    {"create_script_error": RuntimeError("bad script")},
    {"load_error": RuntimeError("agent failed to load")},
])
def test_failure_before_resume_kills_process_and_detaches(driver, kwargs):
    module, install = driver
    session = FakeSession(**kwargs)
    device = install(session)

    with pytest.raises(RuntimeError):
        module.main()

    assert "resume" not in device.calls
    assert "kill" in device.calls
    assert session.detached


def test_attach_failure_kills_process(driver):
    module, install = driver
    session = FakeSession()
    device = install(session, attach_error=RuntimeError("attach failed"))

    with pytest.raises(RuntimeError):
        module.main()

    assert device.calls == ["spawn", "attach", "kill"]
    assert not session.detached


def test_resume_failure_kills_process_and_detaches(driver):
    # resume() never completed, so the process is still suspended.
    module, install = driver
    session = FakeSession()
    device = install(session, resume_error=RuntimeError("resume failed"))

    with pytest.raises(RuntimeError):
        module.main()

    assert "kill" in device.calls
    assert session.detached


def test_happy_path_resumes_waits_and_detaches(driver):
    module, install = driver
    session = FakeSession()
    device = install(session)

    module.main()

    assert device.calls == ["spawn", "attach", "resume"]
    assert session.detached


def test_ctrl_c_during_wait_detaches_without_killing(driver, monkeypatch):
    module, install = driver
    session = FakeSession()
    device = install(session)

    def interrupted(_event, _timeout):
        raise KeyboardInterrupt

    monkeypatch.setattr(module, "wait_for_scan", interrupted)
    module.main()

    assert device.calls == ["spawn", "attach", "resume"]
    assert session.detached
