"""
Small fakes of frida's device / session / script, shared by the driver tests
(test_run_dump.py, test_list_exports.py, test_common.py). No device and no
real Frida: each fake just records what was called and can be told to fail at
a given step, so the tests can pin the spawn -> attach -> load -> init ->
resume -> detach lifecycle in retk/_common.spawn_agent().
"""
import types

PID = 4242


class FakeExports:
    """Stands in for script.exports_sync; init() records what the driver hands
    the agent, and can be made to fail like an agent that refuses its params.
    get_health() returns `health` - or fails like an agent built before the
    layout check existed, when `health` is None. get_verification() is what the
    verification agent exports: `verification` is one result, a list of results
    (one per call, the last repeated) or a callable; None fails like an agent that
    has no such export (i.e. not dist/verify_hook.js). snapshot() / get_snapshot() are the snapshot agent's:
    `snapshot` is a list of statuses get_snapshot() returns one per call (the last repeated), or None for an
    agent that has no such export; `snapshot_ack` is what snapshot() answers."""

    def __init__(self, init_error=None, health=None, verification=None, snapshot=None, snapshot_ack=None):
        self.snapshot_calls = 0
        self.status_calls = 0
        self._snapshot = snapshot
        self._snapshot_ack = {"started": True} if snapshot_ack is None else snapshot_ack
        self.inits = []                    # [(stage, params)]
        self._init_error = init_error
        self._health = health
        self._verification = verification
        self.verification_calls = 0

    def init(self, stage, params):
        self.inits.append((stage, params))
        if self._init_error:
            raise self._init_error

    def get_count(self):
        return 2

    def get_records(self):
        return [{"id": 1}, {"id": 2}]

    def get_health(self):
        if self._health is None:
            raise RuntimeError("unable to find method 'getHealth'")
        return self._health

    def snapshot(self):
        if self._snapshot is None:
            raise RuntimeError("unable to find method 'snapshot'")
        self.snapshot_calls += 1
        return self._snapshot_ack

    def get_snapshot(self):
        if self._snapshot is None:
            raise RuntimeError("unable to find method 'getSnapshot'")
        self.status_calls += 1
        return self._snapshot[min(self.status_calls, len(self._snapshot)) - 1]

    def get_verification(self):
        v = self._verification
        if v is None:
            raise RuntimeError("unable to find method 'getVerification'")
        self.verification_calls += 1
        if callable(v):
            return v(self.verification_calls)
        if isinstance(v, list):
            return v[min(self.verification_calls, len(v)) - 1]
        return v


class FakeScript:
    """`messages` are what the agent `send()`s once the app runs: delivered, in order, to the
    "message" handler the driver registered, when the device resumes the process."""

    def __init__(self, load_error=None, init_error=None, health=None, messages=(), verification=None, snapshot=None,
                 snapshot_ack=None):
        self.exports_sync = FakeExports(init_error, health, verification, snapshot, snapshot_ack)
        self._load_error = load_error
        self._messages = list(messages)
        self._handlers = {}

    def on(self, event, handler=None):
        self._handlers[event] = handler

    def deliver_messages(self):
        handler = self._handlers.get("message")
        for payload in self._messages:
            handler({"type": "send", "payload": payload}, None)

    def load(self):
        if self._load_error:
            raise self._load_error


class FakeSession:
    """`fire_detached(reason)` calls the "detached" handler the driver registered, as Frida does when the
    process dies under the session."""

    def __init__(self, create_script_error=None, load_error=None, init_error=None, health=None, messages=(),
                 verification=None, snapshot=None, snapshot_ack=None):
        self._snapshot = snapshot
        self._snapshot_ack = snapshot_ack
        self._verification = verification
        self._create_script_error = create_script_error
        self._load_error = load_error
        self._init_error = init_error
        self._health = health
        self._messages = messages
        self.script = None                 # the FakeScript create_script() returned
        self.detached = False
        self._handlers = {}

    def on(self, event, handler=None):
        self._handlers[event] = handler

    def fire_detached(self, reason):
        self._handlers["detached"](reason)

    def create_script(self, _source):
        if self._create_script_error:
            raise self._create_script_error
        self.script = FakeScript(self._load_error, self._init_error, self._health, self._messages,
                                 self._verification, self._snapshot, self._snapshot_ack)
        return self.script

    def detach(self):
        self.detached = True


class FakeDevice:
    def __init__(self, session, attach_error=None, resume_error=None, processes=None):
        self.session = session
        self.processes = {"TheGame": PID} if processes is None else processes     # name -> pid, for get_process()
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

    def get_process(self, name):
        if name not in self.processes:
            raise RuntimeError(f"unable to find process with name '{name}'")
        return types.SimpleNamespace(pid=self.processes[name], name=name)

    def resume(self, pid):
        assert pid == PID
        self.calls.append("resume")
        if self._resume_error:
            raise self._resume_error
        if self.session is not None and self.session.script is not None:
            self.session.script.deliver_messages()

    def kill(self, pid):
        assert pid == PID
        self.calls.append("kill")


def make_frida_module(holder):
    """A stand-in `frida` module whose remote device is holder["device"]."""
    fake = types.ModuleType("frida")
    fake.get_device_manager = lambda: types.SimpleNamespace(
        add_remote_device=lambda _addr: holder["device"])
    return fake
