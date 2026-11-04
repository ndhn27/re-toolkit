"""
Unit tests for the spawn -> attach -> load -> init -> resume -> wait ->
detach lifecycle in retk exports.

Same approach as test_run_dump.py (stub `frida`, fakes from
fake_frida.py). list_exports.py used to open-code this lifecycle without any
cleanup, so a failed attach / create_script / load left the app frozen at
spawn; it now shares _common.spawn_agent() with the main driver. What's
pinned here:

  - a failure anywhere before resume kills the still-suspended process,
    detaches the session if there is one, and the error still propagates;
  - the module to scan comes from the profile (--profile) and reaches the
    agent through init(); no offset is involved;
  - the happy path resumes, waits for scan-complete and detaches without killing anything;
  - Ctrl+C during the wait detaches and exits cleanly.

Run from the repo root:

    pytest
"""
import json
import sys

import pytest

from fake_frida import FakeDevice, FakeSession, make_frida_module
from stub_import import import_fresh


@pytest.fixture
def driver(tmp_path, monkeypatch):
    """Import retk exports against a stub frida module and return
    (module, install)."""
    holder = {}

    monkeypatch.setitem(sys.modules, "frida", make_frida_module(holder))
    module = import_fresh(monkeypatch, "list_exports")

    agent = tmp_path / "list_il2cpp_exports.js"
    agent.write_text("// agent\n", encoding="utf-8")
    monkeypatch.setattr(module, "AGENT_PATH", str(agent))
    monkeypatch.setattr(module, "wait_for_scan", lambda _event, _timeout: True)

    def argv(*extra):
        monkeypatch.setattr(sys, "argv", ["list_exports.py", *extra])

    argv("--target", "com.example.app", "--module", "UnityFramework", "--remote", "127.0.0.1:1")

    def install(session, **device_kwargs):
        holder["device"] = FakeDevice(session, **device_kwargs)
        return holder["device"]

    install.argv = argv
    yield module, install


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
    assert session.script.exports_sync.inits == [
        ("early", {"module": "UnityFramework", "offsets": {}})]


def test_the_profiles_module_is_what_the_agent_scans(driver, tmp_path):
    module, install = driver
    session = FakeSession()
    install(session)
    profile = tmp_path / "android.json"
    profile.write_text(json.dumps({"target": "com.example.app", "module": "libil2cpp.so"}),
                       encoding="utf-8")
    install.argv("--profile", str(profile))

    module.main()

    [(_, params)] = session.script.exports_sync.inits
    assert params["module"] == "libil2cpp.so"
    assert params["offsets"] == {}


def test_offset_flag_does_not_exist_here(driver):
    # The export lister hooks no address, so --offset is rejected rather than ignored.
    module, install = driver
    install(FakeSession())
    install.argv("--target", "com.example.app", "--offset", "table_a=0x10")
    with pytest.raises(SystemExit):
        module.main()


def test_an_agent_that_refuses_its_params_exits_and_kills_the_app(driver):
    module, install = driver
    session = FakeSession(init_error=RuntimeError("no parameters"))
    device = install(session)

    with pytest.raises(SystemExit, match="no parameters"):
        module.main()

    assert device.calls == ["spawn", "attach", "kill"]
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
