"""
The agents under REAL Frida, end to end.

Every other test that touches an agent runs it under Node against a hand-written
Frida stand-in (tests/frida_harness.mjs). That is the right tool for checking
what an agent decodes, but a stand-in can only agree with what its author
believes Frida does. The parts that hinge on Frida itself are exactly the ones
it cannot settle:

  * `Interceptor.attach` really firing on the profile's RVA, with `args[0]` the
    record pointer;
  * what `retval` is in `onLeave` - the whole 64-bit register - so that
    `unpackFailed()`'s "low 32 bits are zero" rule does what its comment says
    when the upper half is garbage;
  * `NativePointer` reads (u32/s32/s8, UTF-16 strings, 64-bit pointers above
    4 GiB) against real memory;
  * `waitForModule()` waiting for a library that is loaded later;
  * what the Python side really sees: `spawn_agent()` spawning, attaching,
    loading and calling `init()`; `rpc.exports`; the exception a missing export
    raises (which `run_dump.require_dump_agent` relies on).

So this file builds a small native program and library (tests/native/), compiles
the real scripts/*.js with Frida's own compiler (`frida.Compiler`, no npm
needed), spawns the program through the repo's own `spawn_agent()` and checks
what comes back over RPC. The program maps the same kind of record table the
Node tests use (`test_canary.Table`) at an address above 4 GiB, and calls the
hooked function with return values chosen to expose a register-width mistake.

Looking things up by name (scripts/_resolve.js) is checked here against a small native
IL2CPP of its own (tests/native/fake_il2cpp.c: the real C API signatures over a made-up
metadata model, methods pointing at real functions): the lookup must end at the address
Frida can hook, early (hook il2cpp_init, look up in its onLeave) and late (attach after init),
and must fall back to the RVA when the exports are hidden, renamed, or the name is not settled.

What this does NOT cover: it runs on whatever machine runs the tests (x86-64 or
AArch64 Linux), never on the phone the toolkit is really for. AArch64 `x0`/`w0`
and iOS/Android runtime behaviour (the IL2CPP library, ASLR, JIT, jailbreak
tweaks) still need a run against the real app; an x86-64 `rax` is the same
64-bit NativePointer to Frida, which is all the agents see, but that is a
reasoned claim about ARM, not a measurement.

Skips when frida, a C compiler or `nm` is missing, off Linux (the target uses
MAP_FIXED_NOREPLACE), or when this environment will not let Frida spawn and
attach (a container without ptrace). With $CI set a missing frida/compiler/nm
FAILS instead, like the Node tests, so CI cannot silently stop running them; with
$REQUIRE_REAL_FRIDA set (the workflow does) so does an environment that will not let Frida spawn.
Run from the repo root:

    pytest tests/test_frida_real.py
"""
import json
import os
import shutil
import struct
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

import pytest

from stub_import import import_detached
from retk import buildid
from retk import diff_records
from retk import il2cpp_names
from retk import layout_check
from retk import profiles
from retk import verification
from retk._common import load_agent_source, spawn_agent
from node_support import SCRIPTS_DIR
from test_canary import A_OFFSETS, CLASS_WORD, PROFILE, STRING_AT, Table

try:
    import frida
except ImportError:  # pragma: no cover - depends on the machine
    frida = None

NATIVE_DIR = Path(__file__).resolve().parent / "native"
DIST_DIR = Path(__file__).resolve().parent.parent / "dist"
REAL_BASE = 0x2_0000_0000        # where the target maps the record table: above 4 GiB
TIMEOUT = 15.0                   # generous: a cold machine, not a slow agent


# ---------------------------------------------------------------------------
# what has to be there, and the fixtures that build it
# ---------------------------------------------------------------------------

def _require(what, available):
    """Skip when `what` is missing - or fail when $CI is set, so CI can't silently stop running these."""
    if available:
        return
    if os.environ.get("CI"):
        pytest.fail(f"{what} is required to run these tests in CI")
    pytest.skip(f"{what} is not installed")


@pytest.fixture(scope="module")
def native(tmp_path_factory):
    """The compiled target: libtarget.so, the two programs, and unpack_a's RVA."""
    if not sys.platform.startswith("linux"):
        pytest.skip("the native target uses Linux-only calls (MAP_FIXED_NOREPLACE, /proc/self/exe)")
    _require("frida", frida is not None)
    _require("frida.Compiler", hasattr(frida, "Compiler"))
    cc = shutil.which("gcc") or shutil.which("cc")
    _require("a C compiler (gcc or cc)", cc)
    nm = shutil.which("nm")
    _require("nm (binutils)", nm)

    out = tmp_path_factory.mktemp("native")

    def build(*args):
        subprocess.run([cc, "-O0", *args], check=True, cwd=out, capture_output=True, text=True)

    # an explicit build-id on every library: the agent names the build it runs in by it (_buildid.js)
    so = ["-shared", "-fPIC", "-Wl,--build-id=sha1"]
    build(*so, "-o", "libtarget.so", str(NATIVE_DIR / "libtarget.c"))
    # the same library with an IL2CPP of its own (a normal build of the game), and with that IL2CPP's
    # exports renamed (a build that hides them behind other names)
    il2cpp_sources = [str(NATIVE_DIR / "libtarget.c"), str(NATIVE_DIR / "fake_il2cpp.c")]
    build(*so, "-o", "libil2cpp.so", *il2cpp_sources)
    build(*so, "-DPFX=renamed_", "-o", "libil2cpp_renamed.so", *il2cpp_sources)
    build("-o", "target_linked", str(NATIVE_DIR / "target.c"), "-L.", "-ltarget", "-Wl,-rpath,$ORIGIN")
    build("-DUSE_DLOPEN", "-o", "target_dl", str(NATIVE_DIR / "target.c"), "-ldl")

    listing = subprocess.run([nm, "-D", "--defined-only", "libtarget.so"], check=True, cwd=out,
                             capture_output=True, text=True).stdout
    rva = next(int(line.split()[0], 16) for line in listing.splitlines() if line.split()[-1] == "unpack_a")

    def rvas(lib):
        text = subprocess.run([nm, "-D", "--defined-only", lib], check=True, cwd=out,
                              capture_output=True, text=True).stdout
        return {line.split()[-1]: int(line.split()[0], 16) for line in text.splitlines() if line.split()}

    class Built:
        lib = out / "libtarget.so"
        linked = out / "target_linked"
        dlopened = out / "target_dl"
        il2cpp_lib = out / "libil2cpp.so"
        renamed_lib = out / "libil2cpp_renamed.so"
    Built.rva = rva
    Built.data_rva = rvas("libtarget.so")["target_data_marker"]     # inside the module, writable, not code
    Built.il2cpp_rvas = rvas("libil2cpp.so")          # unpack_a, unpack_a2, reset_fn, inner_run
    Built.renamed_rvas = rvas("libil2cpp_renamed.so")
    return Built


@pytest.fixture(scope="module")
def bundle(native):
    """bundle("dump_table_a.js") -> the agent as Frida runs it: scripts/ compiled to one script."""
    cache = {}

    def get(name):
        if name not in cache:
            cache[name] = frida.Compiler().build(str(SCRIPTS_DIR / name))
        return cache[name]
    return get


@pytest.fixture(scope="module")
def shipped(native):
    """shipped("dump_table_a.js") -> the file `npm run build` wrote to dist/: not what frida.Compiler makes
    of scripts/ here, but the very file retk dump loads (through load_agent_source()), built by
    frida-compile. Missing (`npm ci && npm run build` not run): skipped, or a failure with $REQUIRE_DIST
    set - which CI does - so the shipped bundles cannot silently stop being tried under real Frida."""
    def get(name):
        path = DIST_DIR / name
        if not path.is_file():
            what = f"dist/{name} is missing - run `npm ci && npm run build` first"
            if os.environ.get("REQUIRE_DIST"):
                pytest.fail(what)
            pytest.skip(what)
        return load_agent_source(str(path))
    return get


class RealTable(Table):
    """test_canary's record table, with every pointer made real: strings and the class
    word live at REAL_BASE + offset, because that is where the target maps the image."""

    def string(self, text):
        return REAL_BASE + super().string(text)

    def add(self, id, *args, klass=None, **kwargs):
        return super().add(id, *args, klass=REAL_BASE + CLASS_WORD if klass is None else klass, **kwargs)


def break_string_length(table, index, length=-1):
    """Record `index`'s `name` string now claims an absurd length."""
    pointer = struct.unpack_from("<Q", table.mem, table.bases[index] + A_OFFSETS["name"])[0] - REAL_BASE
    struct.pack_into("<i", table.mem, pointer + STRING_AT["length_offset"], length)


# ---------------------------------------------------------------------------
# running an agent against the target
# ---------------------------------------------------------------------------

class Live:
    """A running target with an agent attached."""

    def __init__(self, run, logs):
        self.run = run
        self.logs = logs

    @property
    def exports(self):
        return self.run.script.exports_sync

    @property
    def skips(self):
        return [line for line in self.logs if "[skip]" in line]

    def wait_for(self, predicate, what):
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.05)
        tail = "\n".join(self.logs[-15:]) or "(nothing)"
        raise AssertionError(f"timed out after {TIMEOUT:g}s waiting for {what}. Agent log, last lines:\n{tail}")


@contextmanager
def live(native, source, tmp_path, table=None, calls=(), dlopen=False, init=True, extra_params=None,
         lib=None, params=None):
    """Spawn the target through spawn_agent(), load `source`, call init() (unless init=False),
    resume, and yield a Live; the target is killed on the way out.

    `calls` is [(record base, unpack_a mode)], made in that order a moment after the start; an entry
    ("wait", MS) sleeps MS milliseconds there instead (so an agent can attach in between), and
    ("raw", LINE) is a config line of target.c's own (the snapshot tests' klass:/publish: lines).
    `extra_params` are added to what init() receives (the verification agent's `verify` section).
    `lib` is the library to ship as libtarget.so (default: the plain one, no IL2CPP); `params` replaces
    what init() receives (the default hooks table_a at the plain library's RVA)."""
    app = tmp_path / "app"
    app.mkdir(parents=True)
    shutil.copy(lib or native.lib, app / "libtarget.so")
    shutil.copy(native.dlopened if dlopen else native.linked, app / "target")
    image = table if table is not None else RealTable()
    (app / "blob.bin").write_bytes(bytes(image.mem))
    config = [str(app / "blob.bin"), f"{REAL_BASE:x}", str(app / "libtarget.so") if dlopen else "-"]
    config += [mode if base == "raw" else f"wait:{mode}" if base == "wait" else f"{base:x}:{mode}" for base, mode in calls]
    (app / "target.cfg").write_text("\n".join(config) + "\n", encoding="utf-8")

    if params is None and init:
        params = profiles.agent_params(PROFILE, module="libtarget.so", offsets={"table_a": native.rva})
    elif not init:
        params = None
    if params is not None and extra_params:
        params = {**params, **extra_params}
    logs = []

    def on_message(message, data):                  # frida < 17 delivers console.log here
        if message.get("type") == "log":
            logs.append(str(message.get("payload")))

    device = frida.get_local_device()
    refused = tuple(getattr(frida, n) for n in ("PermissionDeniedError", "ServerNotRunningError")
                    if hasattr(frida, n))
    with ExitStack() as stack:
        try:
            run = stack.enter_context(spawn_agent(device, str(app / "target"), source, on_message, None,
                                                  params=params))
        except refused as e:
            if os.environ.get("REQUIRE_REAL_FRIDA"):      # CI sets it: a runner that cannot ptrace must not pass this file by skipping it
                pytest.fail(f"REQUIRE_REAL_FRIDA is set, but this environment does not let Frida spawn and attach: {e}")
            pytest.skip(f"this environment does not let Frida spawn and attach: {e}")

        def kill():
            try:
                device.kill(run.pid)
            except Exception:                       # already gone, or never resumed and already killed
                pass
        stack.callback(kill)                        # runs before spawn_agent's own cleanup
        if hasattr(run.script, "set_log_handler"):  # frida >= 17: console.log goes through here
            run.script.set_log_handler(lambda level, text: logs.append(str(text)))
        if init:
            run.resume()
        yield Live(run, logs)


def good_records(n):
    return [{"id": i, "weight": -5 * i, "enabled": i % 2, "name": f"name-{i}"} for i in range(1, n + 1)]


def success_calls(table):
    return [(base, 0) for base in table.bases]


# ---------------------------------------------------------------------------
# the tests
# ---------------------------------------------------------------------------

def test_the_real_hook_exports_exactly_what_the_layout_says(native, bundle, tmp_path):
    table = RealTable().add_good(6)
    with live(native, bundle("dump_table_a.js"), tmp_path, table, success_calls(table)) as app:
        app.wait_for(lambda: app.exports.get_count() == 6, "6 records")
        # every field decoded from real memory, strings and signs and 32-bit values included
        assert app.exports.get_records() == good_records(6)
        assert app.exports.get_unreadable() == []
        verdict = layout_check.judge(app.exports.get_health())
        assert verdict.status == layout_check.OK, (verdict.problems, verdict.notes)
        [health] = app.exports.get_health()["records"]
        assert (health["calls"], health["read_errors"], health["key_conflicts"]) == (6, 0, 0)
        assert health["klass"]["bad_pointer"] == 0


def test_the_return_value_is_judged_by_its_low_32_bits_in_the_real_register(native, bundle, tmp_path):
    table = RealTable().add_good(5)
    # 1: success. 2: success with garbage in the upper half. 3, 4, 5: failures -
    # one with garbage up top, one that is -1 as an int, one that is just 1.
    calls = [(base, mode) for base, mode in zip(table.bases, (0, 2, 3, 4, 1))]
    with live(native, bundle("dump_table_a.js"), tmp_path, table, calls) as app:
        app.wait_for(lambda: len(app.skips) == 3 and app.exports.get_count() == 2,
                     "3 skipped calls and 2 kept records")
        assert [r["id"] for r in app.exports.get_records()] == [1, 2]
        text = "\n".join(app.skips)
        assert "0xdeadbeef00000001" in text            # the agent really sees all 64 bits
        assert "0xffffffff" in text
        assert "expected 0 in the low 32 bits" in text


def build_of(lib):
    """The BuildId of `lib` as the driver side computes it, from the FILE."""
    found = buildid.from_file(lib)
    assert found is not None, f"{lib} has no GNU build-id: the target library is built with --build-id"
    return found


def test_the_agent_names_the_build_it_runs_in_by_the_librarys_own_build_id(native, bundle, tmp_path):
    # the id read out of the module's headers IN THE RUNNING PROCESS is the one retk/buildid.py reads from the file
    table = RealTable().add_good(2)
    with live(native, bundle("dump_table_a.js"), tmp_path, table, success_calls(table)) as app:
        app.wait_for(lambda: app.exports.get_count() == 2, "2 records")
        expected = build_of(native.lib)
        assert app.exports.get_resolution()["build"] == {"kind": expected.kind, "id": expected.id}


def test_an_rva_cached_for_this_build_is_what_gets_hooked_whatever_the_profile_says(native, bundle, tmp_path):
    # the profile's own RVA points at data, where nothing can be hooked: only the cache's address can work
    key = build_of(native.lib).text
    table = RealTable().add_good(3)
    extra = {"offsets": {"table_a": native.data_rva}, "cache": {"builds": {key: {"table_a": native.rva}}}}
    with live(native, bundle("dump_table_a.js"), tmp_path, table, success_calls(table), extra_params=extra) as app:
        app.wait_for(lambda: app.exports.get_count() == 3, "3 records")
        assert app.exports.get_records() == good_records(3)
        [entry] = app.exports.get_resolution()["methods"]
        assert (entry["source"], entry["rva"]) == ("cache", native.rva)


def test_a_cache_for_another_build_is_not_used_and_the_profiles_rva_hooks_as_before(native, bundle, tmp_path):
    table = RealTable().add_good(3)
    elsewhere = {"builds": {"gnu-build-id:" + "ab" * 20: {"table_a": native.data_rva}}}
    with live(native, bundle("dump_table_a.js"), tmp_path, table, success_calls(table),
              extra_params={"cache": elsewhere}) as app:
        app.wait_for(lambda: app.exports.get_count() == 3, "3 records")
        [entry] = app.exports.get_resolution()["methods"]
        assert (entry["source"], entry["rva"]) == ("rva", native.rva)


def test_the_shipped_bundle_reads_the_build_and_hooks_the_cached_rva(native, shipped, tmp_path):
    # dist/ is built by frida-compile, which has to carry the new _buildid.js import along
    expected = build_of(native.lib)
    table = RealTable().add_good(3)
    extra = {"offsets": {"table_a": native.data_rva}, "cache": {"builds": {expected.text: {"table_a": native.rva}}}}
    with live(native, shipped("dump_table_a.js"), tmp_path, table, success_calls(table), extra_params=extra) as app:
        app.wait_for(lambda: app.exports.get_count() == 3, "3 records")
        report = app.exports.get_resolution()
        assert report["build"] == {"kind": expected.kind, "id": expected.id}
        assert report["methods"][0]["source"] == "cache"


def test_the_shipped_bundle_hooks_and_exports_what_the_layout_says(native, shipped, tmp_path):
    # the same checks as above, on the file the drivers load rather than on frida.Compiler's output
    table = RealTable().add_good(6)
    with live(native, shipped("dump_table_a.js"), tmp_path, table, success_calls(table)) as app:
        app.wait_for(lambda: app.exports.get_count() == 6, "6 records")
        assert app.exports.get_records() == good_records(6)
        assert app.exports.get_unreadable() == []
        assert layout_check.judge(app.exports.get_health()).status == layout_check.OK


def test_the_shipped_bundle_judges_the_return_value_by_the_real_register(native, shipped, tmp_path):
    # the hook that must keep returning the right verdict across a Frida upgrade: 64-bit retval in
    # onLeave, judged by its low 32 bits, garbage in the upper half included
    table = RealTable().add_good(5)
    calls = [(base, mode) for base, mode in zip(table.bases, (0, 2, 3, 4, 1))]
    with live(native, shipped("dump_table_a.js"), tmp_path, table, calls) as app:
        app.wait_for(lambda: len(app.skips) == 3 and app.exports.get_count() == 2,
                     "3 skipped calls and 2 kept records")
        assert [r["id"] for r in app.exports.get_records()] == [1, 2]
        text = "\n".join(app.skips)
        assert "0xdeadbeef00000001" in text and "0xffffffff" in text
        assert "expected 0 in the low 32 bits" in text


def test_the_shipped_verification_bundle_judges_every_return_by_the_whole_register(native, shipped, tmp_path):
    # verify_hook.js has its own onLeave: the same 8 calls as the compiler-built test further down -
    # 3 failures (garbage upstairs, -1, a plain 1), 5 successes - read off the shipped bundle
    table = RealTable().add_good(8)
    calls = list(zip(table.bases, (0, 2, 3, 4, 1, 0, 2, 0)))
    with live(native, shipped("verify_hook.js"), tmp_path, table, calls, extra_params=verify_params(native)) as app:
        c = verify_candidate(app, 8)
        assert (c["enters"], c["leaves"], c["failed_returns"]) == (8, 8, 3)
        assert verification.judge(app.exports.get_verification()).outcome == verification.OUTCOME_VERIFIED


def test_a_library_loaded_after_the_agent_is_waited_for(native, bundle, tmp_path):
    table = RealTable().add_good(3)
    with live(native, bundle("dump_table_a.js"), tmp_path, table, success_calls(table), dlopen=True) as app:
        app.wait_for(lambda: app.exports.get_count() == 3, "3 records from the late-loaded library")
        assert app.exports.get_records() == good_records(3)


def test_a_few_unreadable_strings_are_named_in_the_real_export(native, bundle, tmp_path):
    # The case that motivated `_unreadable`: 2 of 41 strings are bad - under the layout
    # check's tolerance, verdict `ok` - and the export must still say which records.
    table = RealTable().add_good(41)
    break_string_length(table, 6)
    break_string_length(table, 29)
    with live(native, bundle("dump_table_a.js"), tmp_path, table, success_calls(table)) as app:
        app.wait_for(lambda: app.exports.get_count() == 41, "41 records")
        records = app.exports.get_records()
        flagged = [r for r in records if r.get("_unreadable")]
        assert [(r["id"], r["name"], r["_unreadable"]) for r in flagged] == [(7, None, ["name"]),
                                                                              (30, None, ["name"])]
        assert "<unexpected len" not in repr(records)
        assert app.exports.get_unreadable() == [{"key": 7, "fields": ["name"]},
                                                {"key": 30, "fields": ["name"]}]
        assert layout_check.judge(app.exports.get_health()).status == layout_check.OK

        # and the driver's own helpers read the same thing off the real script
        run_dump = _import_run_dump()
        entries = run_dump.collect_unreadable(app.run.script, records)
        assert entries == app.exports.get_unreadable()
        assert any("key 7: name" in line for line in run_dump.render_unreadable(entries, len(records)))


def test_run_dump_tells_a_dump_agent_from_one_that_only_prints(native, bundle, tmp_path):
    run_dump = _import_run_dump()
    # a collecting agent passes (loaded but not resumed: nothing to wait for)
    with live(native, bundle("dump_table_a.js"), tmp_path / "a", init=False) as app:
        run_dump.require_dump_agent(app.run, "dist/dump_table_a.js")
    # one that only prints is refused, with what REAL Frida says about the missing export
    with live(native, bundle("trace_lookup.js"), tmp_path / "b", init=False) as app:
        with pytest.raises(run_dump.NotADumpAgent) as refused:
            run_dump.require_dump_agent(app.run, "dist/trace_lookup.js")
    message = str(refused.value)
    assert "getCount" in message and "frida -P" in message and "retk profile" in message


def verify_params(native):
    return {"verify": {"record": "TableARecord", "candidates": [{"id": "c0", "rva": native.rva}]}}


def test_the_real_hook_is_verified_by_the_records_it_hands_back(native, bundle, tmp_path):
    # Not "the bytes matched": the candidate is hooked in the running process, called six times, and
    # every record it handed back read through the layout is valid.
    table = RealTable().add_good(6)
    with live(native, bundle("verify_hook.js"), tmp_path, table, success_calls(table),
              extra_params=verify_params(native)) as app:
        app.wait_for(lambda: app.exports.get_verification()["candidates"][0]["enters"] >= 6, "6 calls")
        snapshot = app.exports.get_verification()
        [c] = snapshot["candidates"]
        assert snapshot["module_loaded"] is True and c["hooked"] is True and c["error"] is None
        assert (c["enters"], c["failed_returns"], c["health"]["calls"]) == (6, 0, 6)
        result = verification.judge(snapshot)
        assert result.outcome == verification.OUTCOME_VERIFIED, [c.as_json() for c in result.candidates]


def test_a_hook_that_is_handed_something_else_is_rejected_in_the_real_process(native, bundle, tmp_path):
    # The same function, called with a pointer that is not a record of this layout (the 0xEE-filled
    # tail of the image: no class word, no strings) - what a wrong candidate looks like from inside.
    table = RealTable().add_good(6)
    stray = [(0x2000 + 0x80 * i, 0) for i in range(6)]
    with live(native, bundle("verify_hook.js"), tmp_path, table, stray, extra_params=verify_params(native)) as app:
        app.wait_for(lambda: app.exports.get_verification()["candidates"][0]["enters"] >= 6, "6 calls")
        result = verification.judge(app.exports.get_verification())
        assert result.outcome == verification.OUTCOME_REJECTED, [c.as_json() for c in result.candidates]


def verify_candidate(app, returns):
    """The only candidate's counts once it has returned `returns` times."""
    app.wait_for(lambda: app.exports.get_verification()["candidates"][0]["leaves"] >= returns,
                 f"{returns} returns")
    return app.exports.get_verification()["candidates"][0]


def test_the_verification_hook_judges_every_return_by_the_whole_register(native, bundle, tmp_path):
    # verify_hook.js has its own onLeave. unpack_a's modes (tests/native/libtarget.c) put garbage in the
    # upper half of the 64-bit register: 2 succeeds with it, 3 fails with it, 4 is -1 as an int, 1 is a
    # plain failure. Only the low 32 bits may decide - and every enter must have its leave.
    table = RealTable().add_good(8)
    calls = list(zip(table.bases, (0, 2, 3, 4, 1, 0, 2, 0)))
    with live(native, bundle("verify_hook.js"), tmp_path, table, calls, extra_params=verify_params(native)) as app:
        c = verify_candidate(app, 8)
        assert (c["enters"], c["leaves"], c["failed_returns"]) == (8, 8, 3)
        assert c["health"]["calls"] == 5 and c["health"]["read_errors"] == 0   # only the 5 successes were read
        result = verification.judge(app.exports.get_verification())
        assert result.outcome == verification.OUTCOME_VERIFIED, [x.as_json() for x in result.candidates]


def test_a_candidate_whose_every_return_is_a_failure_is_not_exercised_in_the_real_process(native, bundle, tmp_path):
    # Fired, but never succeeded: no record was read, so nothing can be said - and above all it must not be
    # called verified or rejected. (The same thing a hook on the wrong function would look like.)
    table = RealTable().add_good(4)
    calls = list(zip(table.bases, (3, 4, 1, 3)))
    with live(native, bundle("verify_hook.js"), tmp_path, table, calls, extra_params=verify_params(native)) as app:
        c = verify_candidate(app, 4)
        assert (c["enters"], c["leaves"], c["failed_returns"], c["health"]["calls"]) == (4, 4, 4, 0)
        [verdict] = verification.judge(app.exports.get_verification()).candidates
        assert verdict.status == verification.NOT_EXERCISED, verdict.as_json()


def test_a_candidate_that_is_not_code_is_refused_by_the_real_process_and_the_real_one_still_hooks(native, bundle, tmp_path):
    # What the process itself says about an address (Process.findRangeByAddress, the module's size) -
    # not what a stand-in is told to say: a writable data address and one far past the module are
    # refused with the reason, and the candidate beside them, the real function, is hooked and called.
    table = RealTable().add_good(3)
    extra = {"verify": {"record": "TableARecord", "candidates": [
        {"id": "data", "rva": native.data_rva},
        {"id": "far", "rva": 0x4000000},
        {"id": "code", "rva": native.rva},
    ]}}
    with live(native, bundle("verify_hook.js"), tmp_path, table, success_calls(table), extra_params=extra) as app:
        app.wait_for(lambda: {c["id"]: c for c in app.exports.get_verification()["candidates"]}["code"]["enters"] >= 3,
                     "3 calls of the real function")
        snapshot = app.exports.get_verification()
        by_id = {c["id"]: c for c in snapshot["candidates"]}
        assert by_id["data"]["hooked"] is False and "rw-" in by_id["data"]["error"]
        assert "not executable" in by_id["data"]["error"]
        assert by_id["far"]["hooked"] is False and "beyond the end of libtarget.so" in by_id["far"]["error"]
        assert (by_id["code"]["hooked"], by_id["code"]["error"], by_id["code"]["leaves"]) == (True, None, 3)
        verdicts = {v.id: v.status for v in verification.judge(snapshot).candidates}
        assert verdicts == {"data": verification.REJECTED, "far": verification.REJECTED, "code": verification.VERIFIED}


def test_the_verification_agent_is_told_from_a_dump_agent_before_the_app_runs(native, bundle, tmp_path):
    verify_offset = import_detached("verify_offset")
    with live(native, bundle("verify_hook.js"), tmp_path / "a", init=False) as app:
        verify_offset.require_verify_agent(app.run, "dist/verify_hook.js")
    with live(native, bundle("dump_table_a.js"), tmp_path / "b", init=False) as app:
        with pytest.raises(verify_offset.NotAVerifyAgent, match="getVerification"):
            verify_offset.require_verify_agent(app.run, "dist/dump_table_a.js")


def _import_run_dump():
    """retk/run_dump.py bound to the real frida (other test modules import it bound to a stub); no copy is left
    in sys.modules or on the package for those tests to find."""
    return import_detached("run_dump")


# ---------------------------------------------------------------------------
# looking things up by name, against a real IL2CPP-shaped library
# ---------------------------------------------------------------------------

def name_params(rva=None, resolve=None, names=None, exports=None):
    """The example profile's params with its names KEPT (the default live() params give table_a an RVA, which
    drops its name) and `rva` as table_a's RVA - or none, when the name is all there is."""
    params = profiles.agent_params(PROFILE, module="libtarget.so", resolve=resolve)
    params["offsets"]["table_a"] = rva or 0
    if names is not None:
        spec = il2cpp_names.parse_method_spec(names).as_agent()     # what the driver would send for it
        params["names"] = {**params["names"], "methods": {"table_a": spec}}
    if exports:
        params["names"] = {**params["names"], "exports": exports}
    return params


def looked_up(app):
    report = app.exports.get_resolution()
    return bool(report and report["methods"])


def table_a_entry(app):
    [entry] = app.exports.get_resolution()["methods"]
    return entry


def dumped(app, n):
    app.wait_for(lambda: app.exports.get_count() == n, f"{n} records")
    assert app.exports.get_records() == good_records(n)


def test_a_name_finds_the_function_in_the_real_runtime_without_any_rva(native, bundle, tmp_path):
    table = RealTable().add_good(3)
    with live(native, bundle("dump_table_a.js"), tmp_path, table, success_calls(table),
              lib=native.il2cpp_lib, params=name_params()) as app:
        dumped(app, 3)                                    # hooked in il2cpp_init's onLeave, in time for the calls
        entry = table_a_entry(app)
        assert (entry["source"], entry["rva"], entry["profile_rva"]) == ("name", native.il2cpp_rvas["unpack_a"], None)
        assert entry["name"] == "ExampleNamespace.ExampleTableA::Unpack/1"
        # the layout's field offsets were also asked of the runtime, and all four agree
        rows = app.exports.get_health()["field_offsets"]
        assert {r["field"]: r["status"] for r in rows} == {"id": "match", "weight": "match", "enabled": "match", "name": "match"}
        assert {r["field"]: r["runtime_offset"] for r in rows} == {"id": 0x10, "weight": 0x14, "enabled": 0x18, "name": 0x20}
        verdict = layout_check.judge(app.exports.get_health())
        assert verdict.status == layout_check.OK, (verdict.problems, verdict.notes)
        assert any("confirmed directly by the IL2CPP runtime" in n for n in verdict.notes)


def test_a_stale_profile_rva_loses_to_the_name(native, bundle, tmp_path):
    table = RealTable().add_good(2)
    stale = native.il2cpp_rvas["unpack_a2"]               # a real function, just not the one the name means
    with live(native, bundle("dump_table_a.js"), tmp_path, table, success_calls(table),
              lib=native.il2cpp_lib, params=name_params(rva=stale)) as app:
        dumped(app, 2)                                    # records only arrive if unpack_a - the name's - was hooked
        entry = table_a_entry(app)
        assert (entry["source"], entry["agrees"], entry["rva"]) == ("name", False, native.il2cpp_rvas["unpack_a"])
        assert entry["profile_rva"] == stale
        assert any("update the profile's RVA" in line for line in app.logs)


def test_the_overload_is_chosen_by_its_parameter_count_in_the_real_runtime(native, bundle, tmp_path):
    with live(native, bundle("dump_table_a.js"), tmp_path, RealTable().add_good(1), [],
              lib=native.il2cpp_lib, params=name_params(names="ExampleNamespace.ExampleTableA::Unpack/2")) as app:
        app.wait_for(lambda: looked_up(app), "the lookup to finish")
        assert table_a_entry(app)["rva"] == native.il2cpp_rvas["unpack_a2"]


@pytest.mark.parametrize("name, why", [
    ("ExampleNamespace.ExampleTableA::Unpack", "2 overloads answer to it"),       # ambiguous without /N
    ("ExampleNamespace.ExampleTableA::Missing", "no method of that name"),
    ("ExampleNamespace.Missing::Unpack/1", "is not in any loaded assembly"),
    ("ExampleNamespace.Abstract::Abstract", "no code pointer"),
    ("ExampleNamespace.Twin::Go", "exists in Other.dll, Assembly-CSharp.dll"),
])
def test_a_name_the_real_runtime_cannot_settle_falls_back_to_the_rva_and_still_dumps(native, bundle, tmp_path, name, why):
    table = RealTable().add_good(2)
    with live(native, bundle("dump_table_a.js"), tmp_path, table, success_calls(table), lib=native.il2cpp_lib,
              params=name_params(rva=native.il2cpp_rvas["unpack_a"], names=name)) as app:
        dumped(app, 2)
        entry = table_a_entry(app)
        assert entry["source"] == "rva" and entry["rva"] == native.il2cpp_rvas["unpack_a"]
        assert why in entry["reason"]


def test_a_nested_class_is_found_through_the_real_nested_type_api(native, bundle, tmp_path):
    with live(native, bundle("dump_table_a.js"), tmp_path, RealTable().add_good(1), [], lib=native.il2cpp_lib,
              params=name_params(names="ExampleNamespace.Outer/Inner::Run")) as app:
        app.wait_for(lambda: looked_up(app), "the lookup to finish")
        assert table_a_entry(app)["rva"] == native.il2cpp_rvas["inner_run"]


def test_a_named_assembly_settles_the_class_that_exists_twice(native, bundle, tmp_path):
    spec = {"class": "ExampleNamespace.Twin", "method": "Go", "args": 0, "assembly": "Other"}
    with live(native, bundle("dump_table_a.js"), tmp_path, RealTable().add_good(1), [], lib=native.il2cpp_lib,
              params=name_params(names=spec)) as app:
        app.wait_for(lambda: looked_up(app), "the lookup to finish")
        assert table_a_entry(app)["rva"] == native.il2cpp_rvas["reset_fn"]


def test_hidden_exports_fall_back_to_the_rva_and_say_why(native, bundle, tmp_path):
    table = RealTable().add_good(3)
    with live(native, bundle("dump_table_a.js"), tmp_path, table, success_calls(table),
              params=name_params(rva=native.rva)) as app:           # the plain library: no IL2CPP exports at all
        dumped(app, 3)
        entry = table_a_entry(app)
        assert (entry["source"], entry["rva"]) == ("rva", native.rva)
        assert "does not export" in entry["reason"] and "il2cpp_class_from_name" in entry["reason"]
        assert app.exports.get_resolution()["api"]["ready"] is False


def test_resolve_names_with_hidden_exports_hooks_nothing(native, bundle, tmp_path):
    table = RealTable().add_good(2)
    with live(native, bundle("dump_table_a.js"), tmp_path, table, success_calls(table),
              params=name_params(rva=native.rva, resolve="names")) as app:
        app.wait_for(lambda: looked_up(app), "the lookup to finish")
        time.sleep(1.0)                                              # the calls have been made by now
        assert app.exports.get_count() == 0 and table_a_entry(app)["source"] == "none"


def test_resolve_rva_ignores_the_names_even_when_the_runtime_could_answer(native, bundle, tmp_path):
    table = RealTable().add_good(2)
    with live(native, bundle("dump_table_a.js"), tmp_path, table, success_calls(table), lib=native.il2cpp_lib,
              params=name_params(rva=native.il2cpp_rvas["unpack_a"], resolve="rva")) as app:
        dumped(app, 2)
        entry = table_a_entry(app)
        assert (entry["source"], entry["name"]) == ("rva", None)


def test_renamed_exports_are_found_through_names_exports(native, bundle, tmp_path):
    from retk.il2cpp_names import API_FUNCTIONS
    table = RealTable().add_good(2)
    # without the alias map the lookup is unavailable and the RVA carries the run...
    with live(native, bundle("dump_table_a.js"), tmp_path / "a", table, success_calls(table), dlopen=True,
              lib=native.renamed_lib, params=name_params(rva=native.renamed_rvas["unpack_a"])) as app:
        dumped(app, 2)
        assert table_a_entry(app)["source"] == "rva" and "does not export" in table_a_entry(app)["reason"]
    # ...with it the runtime answers, and no RVA is needed at all
    aliases = {name: f"renamed_{name}" for name in API_FUNCTIONS}
    with live(native, bundle("dump_table_a.js"), tmp_path / "b", table, success_calls(table), dlopen=True,
              lib=native.renamed_lib, params=name_params(exports=aliases)) as app:
        dumped(app, 2)
        assert (table_a_entry(app)["source"], table_a_entry(app)["rva"]) == ("name", native.renamed_rvas["unpack_a"])


def test_attaching_after_init_asks_the_running_runtime_at_once(native, bundle, tmp_path):
    table = RealTable().add_good(2)
    calls = [("wait", 2500)] + success_calls(table)                  # the app inits, then idles, then calls
    with live(native, bundle("dump_table_a.js"), tmp_path, table, calls, lib=native.il2cpp_lib, init=False) as app:
        app.run.resume()
        time.sleep(1.0)                                              # il2cpp_init has long since returned
        app.exports.init("late", name_params())
        dumped(app, 2)
        assert table_a_entry(app)["source"] == "name"


def test_a_layout_field_the_runtime_places_elsewhere_fails_the_layout_check(native, bundle, tmp_path):
    table = RealTable().add_good(3)
    params = name_params()
    params["names"]["fields"]["TableARecord"]["map"]["weight"] = "enabled"   # the runtime says 0x18, the layout 0x14
    with live(native, bundle("dump_table_a.js"), tmp_path, table, success_calls(table), lib=native.il2cpp_lib,
              params=params) as app:
        dumped(app, 3)                                                     # the data itself reads fine...
        verdict = layout_check.judge(app.exports.get_health())
        assert verdict.status == layout_check.FAIL                         # ...but the layout is contradicted outright
        assert any("TableARecord.weight is at 0x14 in the profile, but the IL2CPP runtime puts enabled at 0x18" in p
                   for p in verdict.problems)


# ---------------------------------------------------------------------------
# snapshot: the table read out of a running app
# ---------------------------------------------------------------------------

def snap_lines(table, klass=True, publish=True, wait_ms=0):
    """target.c config lines that make the fake IL2CPP's heap hold `table`: its class pointer in every record
    (so the records are live instances of ExampleTableA) and ExampleTableB's static fields pointing at them."""
    lines = []
    if klass:
        lines += [("raw", f"klass:{base:x}") for base in table.bases]
    if wait_ms:
        lines.append(("wait", wait_ms))
    if publish:
        lines += [("raw", f"publish:{base:x}") for base in table.bases] + [("raw", "publish!")]
    return lines


def snap_params(static=None, heap=True, record="TableARecord"):
    """The example profile's snapshot params: `static` is a dict of changes to its static spec (False removes the
    source), `heap=False` removes the heap source."""
    params = profiles.agent_params(PROFILE, module="libtarget.so", snapshot=record)
    if static is False:
        params["snapshot"].pop("static", None)
    elif static is not None:
        params["snapshot"]["static"] = {**params["snapshot"]["static"], **static}
    if heap is False:
        params["snapshot"].pop("heap", None)
    return params


def take(app, params, stage="late", timeout=20):
    """init the snapshot agent, take the snapshot and return its final status."""
    app.exports.init(stage, params)
    assert app.exports.snapshot()["started"] is True
    app.wait_for(lambda: app.exports.get_snapshot()["state"] in ("done", "failed"), "the snapshot to finish")
    return app.exports.get_snapshot()


def snapshot_app(native, bundle, tmp_path, table, lines, lib=None, settle=1.0):
    """A running app (the il2cpp library by default) that has already built its table, with the snapshot agent
    loaded but not initialised - an attach that comes late."""
    return live(native, bundle("snapshot_records.js"), tmp_path, table, lines, lib=lib or native.il2cpp_lib, init=False)


def start(app, settle=1.0):
    app.run.resume()
    time.sleep(settle)           # il2cpp_init has returned and the table is published


def test_a_static_list_is_read_without_hooking_anything(native, bundle, tmp_path):
    table = RealTable().add_good(5)
    with snapshot_app(native, bundle, tmp_path, table, snap_lines(table)) as app:
        start(app)
        status = take(app, snap_params(heap=False))
        assert status["state"] == "done" and status["count"] == 5
        [src] = status["sources"]
        assert (src["source"], src["status"], src["candidates"], src["accepted"]) == ("static", "ok", 5, 5)   # the stale tail past _size was not read
        assert app.exports.get_records() == good_records(5)
        verdict = layout_check.judge(app.exports.get_health())
        assert verdict.status == layout_check.OK, (verdict.problems, verdict.notes)
        rows = app.exports.get_health()["field_offsets"]
        assert {r["status"] for r in rows} == {"match"}               # the runtime confirmed the layout's offsets too


def test_an_array_a_single_record_and_a_null_field_are_each_read_as_they_are(native, bundle, tmp_path):
    table = RealTable().add_good(4)
    for static, count, note in (({"field": "rows", "container": "array"}, 4, "1 of 5 array slots are null"),
                                ({"field": "one", "container": "object"}, 1, None)):
        with snapshot_app(native, bundle, tmp_path / static["field"], table, snap_lines(table)) as app:
            start(app)
            status = take(app, snap_params(static=static, heap=False))
            [src] = status["sources"]
            assert (status["state"], status["count"]) == ("done", count)
            assert src.get("note") == note
            assert app.exports.get_records() == good_records(count)
    with snapshot_app(native, bundle, tmp_path / "empty", table, snap_lines(table)) as app:
        start(app)
        status = take(app, snap_params(static={"field": "empty", "container": "list"}, heap=False))
        assert status["state"] == "failed" and "is null: the table has not been built yet" in status["why"]
        assert app.exports.get_count() == 0


def test_a_static_field_that_is_not_what_the_container_says_is_an_error_not_garbage(native, bundle, tmp_path):
    table = RealTable().add_good(3)
    with snapshot_app(native, bundle, tmp_path, table, snap_lines(table)) as app:
        start(app)
        status = take(app, snap_params(static={"field": "one", "container": "list"}, heap=False))   # a record, read as a List
        assert status["state"] == "failed" and app.exports.get_count() == 0
        assert "not a List" in status["why"] or "is not a table" in status["why"]
    with snapshot_app(native, bundle, tmp_path / "b", table, snap_lines(table)) as app:
        start(app)
        status = take(app, snap_params(static={"field": "missing", "container": "list"}, heap=False))
        assert status["state"] == "failed" and "has no field missing" in status["why"]


def test_live_instances_are_found_by_scanning_the_heap_for_their_class(native, bundle, tmp_path):
    table = RealTable().add_good(6)
    with snapshot_app(native, bundle, tmp_path, table, snap_lines(table, publish=False)) as app:
        start(app)
        status = take(app, snap_params(static=False, heap=True))      # no static source: the heap alone
        assert status["state"] == "done" and status["count"] == 6
        [heap] = status["sources"]
        assert (heap["source"], heap["status"], heap["accepted"]) == ("heap", "ok", 6)
        assert heap["candidates"] >= 6 and heap["scanned_bytes"] > 0
        assert sorted(app.exports.get_records(), key=lambda r: r["id"]) == good_records(6)


def test_the_heap_scan_keeps_only_candidates_that_fit_the_layout(native, bundle, tmp_path):
    table = RealTable().add_good(4)
    table.add(9, weight=1, enabled=5, name="bad-enabled")          # a live instance, but `enabled` breaks oneOf [0, 1]
    break_string_length(table, 1, -1)                              # and one whose name is unreadable
    with snapshot_app(native, bundle, tmp_path, table, snap_lines(table, publish=False)) as app:
        start(app)
        status = take(app, snap_params(static=False, heap=True))
        heap = status["sources"][-1]
        assert heap["accepted"] == 3 and heap["rejected"] >= 2
        assert {r["id"] for r in app.exports.get_records()} == {1, 3, 4}
        assert any("enabled" in " ".join(e["problems"]) for e in heap["examples"]) or heap["rejected"] >= 2
        assert layout_check.judge(app.exports.get_health()).status != layout_check.FAIL   # rejects are not read errors


def test_a_heap_with_no_instance_says_so(native, bundle, tmp_path):
    table = RealTable().add_good(3)
    with snapshot_app(native, bundle, tmp_path, table, snap_lines(table, klass=False, publish=False)) as app:
        start(app)
        status = take(app, snap_params(static=False, heap=True))
        assert status["state"] == "failed" and app.exports.get_count() == 0
        assert "no live object of ExampleNamespace.ExampleTableA found" in status["why"]


def test_the_heap_is_the_fallback_when_the_static_field_is_empty(native, bundle, tmp_path):
    table = RealTable().add_good(3)
    with snapshot_app(native, bundle, tmp_path, table, snap_lines(table)) as app:
        start(app)
        status = take(app, snap_params(static={"field": "empty", "container": "list"}, heap=True))
        assert status["state"] == "done" and status["count"] == 3
        assert [s["source"] for s in status["sources"]] == ["static", "heap"]
        assert [s["status"] for s in status["sources"]] == ["empty", "ok"]


def test_the_heap_is_not_scanned_when_the_static_field_already_gave_the_table(native, bundle, tmp_path):
    table = RealTable().add_good(3)
    with snapshot_app(native, bundle, tmp_path, table, snap_lines(table)) as app:
        start(app)
        status = take(app, snap_params(heap=True))
        assert [s["source"] for s in status["sources"]] == ["static"]


def test_a_layout_the_static_pointers_contradict_fails_the_layout_check_rather_than_being_filtered(native, bundle, tmp_path):
    table = RealTable().add_good(3)
    table.add(7, weight=1, enabled=5, name="bad")                   # published too: static roots are exact, so it is shown to the canary
    with snapshot_app(native, bundle, tmp_path, table, snap_lines(table)) as app:
        start(app)
        status = take(app, snap_params(heap=False))
        assert status["state"] == "done" and status["count"] == 4 and status["sources"][0]["rejected"] == 0
        verdict = layout_check.judge(app.exports.get_health(), tolerance=0.0)
        assert verdict.status == layout_check.FAIL and any("enabled" in p for p in verdict.problems)


def test_without_il2cpp_exports_a_snapshot_cannot_find_the_class_and_says_why(native, bundle, tmp_path):
    table = RealTable().add_good(3)
    with live(native, bundle("snapshot_records.js"), tmp_path, table, snap_lines(table, klass=False, publish=False),
              init=False) as app:                                   # the plain library: no IL2CPP at all
        start(app)
        status = take(app, snap_params())
        assert status["state"] == "failed" and "cannot be asked" in status["why"] and "does not export" in status["why"]


def test_a_snapshot_asked_before_the_runtime_is_up_waits_for_it_and_can_be_asked_again(native, bundle, tmp_path):
    table = RealTable().add_good(3)
    lines = [("wait", 1500)] + snap_lines(table)                      # the app builds its table 1.5 s after il2cpp_init
    with snapshot_app(native, bundle, tmp_path, table, lines) as app:
        app.exports.init("early", snap_params(heap=True))             # spawned: the app has not run yet
        assert app.exports.snapshot()["started"] is True
        assert app.exports.get_snapshot()["state"] == "waiting"       # nothing is looked up before il2cpp_init returns
        app.run.resume()
        app.wait_for(lambda: app.exports.get_snapshot()["state"] in ("done", "failed"), "the first snapshot")
        first = app.exports.get_snapshot()
        assert first["state"] == "failed" and app.exports.get_count() == 0   # ran at il2cpp_init: the table was not built yet
        time.sleep(2.0)                                               # now it is
        assert app.exports.snapshot()["started"] is True
        app.wait_for(lambda: app.exports.get_snapshot()["state"] == "done", "the second snapshot")
        assert app.exports.get_snapshot()["count"] == 3 and app.exports.get_count() == 3


def test_a_second_snapshot_starts_from_a_clean_store(native, bundle, tmp_path):
    table = RealTable().add_good(3)
    with snapshot_app(native, bundle, tmp_path, table, snap_lines(table)) as app:
        start(app)
        first = take(app, snap_params(heap=False))
        assert first["count"] == 3
        assert app.exports.snapshot()["started"] is True
        app.wait_for(lambda: app.exports.get_snapshot()["state"] == "done", "the second snapshot")
        assert app.exports.get_count() == 3                           # not 6, and not a key-conflict log
        assert app.exports.get_snapshot()["count"] == 3


def test_a_snapshot_read_by_the_real_driver_helpers_ends_up_in_a_diffable_export(native, bundle, tmp_path):
    """take_snapshot() / render_snapshot() are what run_dump.py uses; their output is what diff_records compares."""
    from retk import run_dump
    table = RealTable().add_good(4)
    with snapshot_app(native, bundle, tmp_path, table, snap_lines(table)) as app:
        start(app)
        app.exports.init("late", snap_params(heap=False))
        status = run_dump.take_snapshot(app.run.script, 20, say=lambda *_: None)
        assert status["state"] == "done"
        lines = run_dump.render_snapshot(status)
        assert lines[0].startswith("[+] static: ok - 4 record(s)") and lines[-1].startswith("[+] Snapshot: 4 unique record(s)")
        records = app.exports.get_records()
    old = {"meta": {}, "records": records}
    changed = [dict(r) for r in records]
    changed[0]["weight"] += 1
    path_old, path_new = tmp_path / "records_a.json", tmp_path / "records_b.json"
    path_old.write_text(json.dumps(old), encoding="utf-8")
    path_new.write_text(json.dumps({"meta": {}, "records": changed}), encoding="utf-8")
    report = diff_records.diff(diff_records.load_dump(str(path_old)), diff_records.load_dump(str(path_new)))
    assert report["summary"]["changed"] == 1 and report["key"]["fields"] == ["id"]
