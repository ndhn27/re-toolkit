"""
Small fakes of frida's device / session / script, shared by the driver tests
(test_run_hd_quality_dump.py, test_list_exports.py). No device and no real
Frida: each fake just records what was called and can be told to fail at a
given step, so the tests can pin the spawn -> attach -> load -> resume ->
detach lifecycle in tools/_common.spawn_agent().
"""
import types

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
    def __init__(self, session, attach_error=None, resume_error=None):
        self.session = session
        self.calls = []
        self._attach_error = attach_error
        self._resume_error = resume_error

    def spawn(self, _argv):
        self.calls.append("spawn")
        return PID

    def attach(self, pid):
        assert pid == PID
        self.calls.append("attach")
        if self._attach_error:
            raise self._attach_error
        return self.session

    def resume(self, pid):
        assert pid == PID
        self.calls.append("resume")
        if self._resume_error:
            raise self._resume_error

    def kill(self, pid):
        assert pid == PID
        self.calls.append("kill")


def make_frida_module(holder):
    """A stand-in `frida` module whose remote device is holder["device"]."""
    fake = types.ModuleType("frida")
    fake.get_device_manager = lambda: types.SimpleNamespace(
        add_remote_device=lambda _addr: holder["device"])
    return fake
