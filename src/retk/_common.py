"""
_common.py

Small shared helper for the driver modules in retk/. Not meant to be run
directly.

Three jobs:
  1. add_override_args() / resolve_settings(): every driver takes its target
     from a PROFILE (--profile NAME, see profiles.py) - a JSON file kept
     outside git - and lets the command line override single values:

         --profile NAME     NAME.json in the profiles/ folder of your user data
                            dir (see paths.py; $RE_PROFILES_DIR overrides), or
                            a path
         --target ID        package/bundle id to spawn
         --remote H:P       frida-server address
         --module NAME      the IL2CPP module to hook in (no default: it depends
                            on the platform - see profiles.PLATFORM_MODULES)
         --platform P       ios | android | windows: shorthand for that platform's
                            usual module name; --module beats it. Said, never
                            guessed - with neither there is no module
         --offset KEY=HEX   one RVA, e.g. `--offset table_a=0xab68fc8` - handy
                            while probing offsets, without editing the profile; it
                            also beats the profile's `names` entry for that key
         --resolve MODE     (drivers whose agent looks things up by name) auto: the
                            name first, the RVA as the fallback (default); names:
                            the name only; rva: the RVAs only, names ignored

     The agents receive the result through rpc.exports.init(); no value is
     ever written into an agent's source. RVAs are Ghidra addresses with
     Image Base = 0, not file offsets - see README.md's "RVA vs file offset".
  2. load_agent_source(): read a bundled Frida agent.
  3. wait_for_enter(): the "press Enter" prompt the drivers share, which a driver can
     also end from the agent's side (the layout gate in run_dump.py).
  4. spawn_agent(): the spawn -> attach -> load -> init -> (caller resumes) ->
     detach lifecycle every driver shares, so a failure between spawn and
     resume can't leave the app frozen and a driver can't drift out of step
     with the others.
"""
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

from . import buildcache, profiles, resources
# They live in profiles.py now (`profiles.py params --offset` takes them too); re-exported
# so the drivers and their tests keep importing them from here.
from .profiles import parse_offset, parse_offset_override  # noqa: F401


def add_override_args(parser, offsets=True, resolve=False, build_cache=False):
    """Add --profile / --target / --remote / --module / --platform (and --offset KEY=HEX, unless
    `offsets=False`; and --resolve MODE, if `resolve=True`; and --build-cache MODE, if
    `build_cache=True`) to `parser`.

    Pass offsets=False for drivers whose agent doesn't hook a specific
    address (e.g. list_exports.py). Pass resolve=True for the drivers whose agent
    can find its hook point by name (run_dump.py): --resolve means nothing to one
    that hooks only the RVAs it is handed (verify_offset.py). Pass build_cache=True for the one that
    records what a verified dump learned about the build and reuses it (run_dump.py).
    """
    group = parser.add_argument_group(
        "target",
        "Where the target comes from. Everything but --profile overrides the "
        "matching value in the profile.")
    group.add_argument(
        "--profile", metavar="NAME",
        help=f"profile to use: a name (NAME.json in your data dir's profiles/, or ${profiles.ENV_PROFILES_DIR}) "
             f"or a path to a .json file")
    group.add_argument("--target", metavar="ID", help="app package/bundle id to spawn")
    group.add_argument("--remote", metavar="HOST:PORT", help="frida-server address")
    profiles.add_module_args(group)
    if offsets:
        group.add_argument(
            "--offset", metavar="KEY=HEX", action="append", type=parse_offset_override,
            help="override one RVA, e.g. table_a=0xab68fc8 (repeatable); it is used as given - "
                 "the profile's name for that key is not looked up")
    if resolve:
        group.add_argument(
            "--resolve", choices=profiles.RESOLVE_MODES, default=None,
            help="how the agent finds what to hook: 'auto' (default) asks the IL2CPP runtime for "
                 "the profile's `names` first and falls back to the RVA when it cannot; 'names' "
                 "never falls back; 'rva' ignores the names (docs/NAME_LOOKUP.md)")
    if build_cache:
        group.add_argument(
            "--build-cache", choices=buildcache.MODES, default="auto",
            help="the per-build record outside the repo (docs/PROFILES.md): 'auto' "
                 "(default) hooks the addresses a verified run recorded for this exact build, if any, and records "
                 "this run's once its dump passes the layout check; 'rescan' looks everything up again and "
                 "records the result; 'off' neither reads nor writes it. A name or an RVA you gave "
                 "(--resolve names|rva, --offset) is never replaced by what was recorded")


@dataclass
class Settings:
    target: str
    remote_addr: str
    params: dict                                   # what the agent gets in init()
    profile: "profiles.Profile | None" = field(default=None)
    resolution: "dict | None" = field(default=None)   # the agent's getResolution(), once a driver has asked
    snapshot: "dict | None" = field(default=None)     # the snapshot agent's final status (run_dump.py --snapshot)
    build_cache: "buildcache.BuildCache | None" = field(default=None)   # run_dump.py's per-build cache, or None

    @property
    def offsets(self):
        return self.params["offsets"]


def resolve_settings(args):
    """Combine the profile and the command line into Settings. Prints what was
    resolved and from where - a stale override you forgot about is exactly the
    thing you don't want to discover after an hour of probing."""
    profile = None
    if args.profile:
        try:
            profile = profiles.load(args.profile)
        except profiles.ProfileError as e:
            sys.exit(f"[!] {e}")
        print(f"[i] profile = {profile.path}")

    target = args.target or (profile.target if profile else None) or getattr(args, "attach", None)
    if not target:
        sys.exit("[!] no target: pass --profile NAME (see docs/PROFILES.md) or --target ID")
    remote = args.remote or (profile.remote if profile else profiles.DEFAULT_REMOTE)
    overrides = dict(getattr(args, "offset", None) or [])
    module = getattr(args, "module", None)
    platform = getattr(args, "platform", None)
    resolve = getattr(args, "resolve", None)
    snapshot = getattr(args, "snapshot", None)       # None: no snapshot; "": the profile's only record; else its name
    try:
        record = None
        if snapshot is not None:
            if profile is None:
                sys.exit("[!] --snapshot needs --profile: names.snapshot says where the running app holds the table")
            record = profiles.snapshot_record(profile, snapshot or None)
        params = profiles.agent_params(profile, module=module, platform=platform, offsets=overrides,
                                       resolve=resolve, snapshot=record)
    except profiles.ProfileError as e:
        sys.exit(f"[!] {e}")
    _, module_source = profiles.resolve_module(profile, module, platform)     # only to say where it came from

    print(f"[i] target = {target}  ({'CLI' if args.target else 'profile'})")
    print(f"[i] remote = {remote}  ({'CLI' if args.remote else 'profile' if profile else 'default'})")
    print(f"[i] module = {params['module']}  ({module_source})")
    cache = None
    cache_mode = getattr(args, "build_cache", None)          # None: this driver has no build cache
    if cache_mode is not None:
        # "names" / "rva" and a snapshot say where an address must come from: the cache has no say there
        why_not = (f"--resolve {resolve}" if resolve not in (None, "auto") else "a snapshot" if snapshot is not None
                   else "--build-cache off" if cache_mode == "off" else None)
        if why_not:
            print(f"[i] build cache = off  ({why_not})")
        else:
            cache = buildcache.BuildCache(cache_mode, target, params["module"], overrides=overrides,
                                          profile_name=profile.name if profile else None)
            sent = cache.agent_params()
            if sent:
                params["cache"] = sent
            for line in cache.intro():
                print(line)
    if "snapshot" in params:
        want = params["snapshot"]
        print(f"[i] snapshot of {want['record']}: " + "; ".join(
            f"{kind} {s['namespace'] + '.' if s['namespace'] else ''}{s['class']}"
            + (f".{s['field']} ({s['container']})" if kind == "static" else "")
            for kind, s in (("static", want.get("static")), ("heap", want.get("heap"))) if s))
    named = params.get("names", {}).get("methods", {})
    if "names" in params or resolve:
        print(f"[i] resolve = {resolve or 'auto'}  ({'CLI' if resolve else 'default'})")
    for key, value in sorted(params["offsets"].items()):
        if value:
            role = "fallback when the name does not resolve" if key in named else None
            print(f"[i] offset {key} = {hex(value)}  ({'CLI' if key in overrides else 'profile'}"
                  f"{', ' + role if role else ''})")
    for key, spec in sorted(named.items()):
        shown = f"{spec['namespace'] + '.' if spec.get('namespace') else ''}{spec['class']}::{spec['method']}"
        shown += "" if spec.get("args", -1) < 0 else f"/{spec['args']}"
        print(f"[i] name   {key} = {shown}  (profile; looked up in the running app first)")
    for key in sorted(k for k in named if not params["offsets"].get(k)):
        print(f"[i] note: {key} has a name but no RVA - if the name cannot be resolved there is no fallback")
    return Settings(target=target, remote_addr=remote, params=params, profile=profile, build_cache=cache)


def _stdin_ready(timeout):
    """True when a line is waiting on a terminal stdin, polling for `timeout` seconds."""
    if os.name == "nt":
        import msvcrt
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if msvcrt.kbhit():
                return True
            time.sleep(0.05)
        return False
    import select
    return bool(select.select([sys.stdin], [], [], timeout)[0])


def wait_for_enter(stop=None, poll=0.25, timeout=None):
    """Block until the user presses Enter ("enter"), `stop` - a threading.Event the agent's
    message handler sets - is set ("stop"), or `timeout` seconds pass ("timeout", only when a
    timeout is given). Ctrl+C raises KeyboardInterrupt, as input() does.

    Without `stop` and `timeout`, or when stdin is not a terminal and there is no `timeout`
    (a pipe, a test), this is plain input(): it cannot be interrupted, so a `stop` set
    meanwhile is noticed only after the input arrives. With a `timeout` and no terminal
    nobody can press Enter, so it just waits (for `stop`, at most `timeout` seconds). On a
    terminal it polls, so a driver can end the wait by itself without a thread blocked on
    stdin outliving the program."""
    interactive = sys.stdin.isatty()
    if timeout is None and (stop is None or not interactive):
        input()
        return "stop" if stop is not None and stop.is_set() else "enter"
    if not interactive:
        if stop is not None:
            stop.wait(timeout)
        else:
            time.sleep(timeout)
        return "stop" if stop is not None and stop.is_set() else "timeout"
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        if stop is not None and stop.is_set():
            return "stop"
        remaining = None if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            return "timeout"
        if _stdin_ready(poll if remaining is None else min(poll, remaining)):
            sys.stdin.readline()            # '' at EOF: nothing more will ever be typed, so go on
            return "enter"


def load_agent_source(path):
    """Read a bundled Frida agent's JS source from `path`.

    `path` should point at a *bundled* agent (resources.agent_path("dump_table_a.js"):
    dist/ in a checkout, the package's agents/ folder when installed), not the raw
    source under scripts/ - the scripts/ files import shared helpers from
    scripts/_lib.js via ES module `import`, which only resolves after
    `npm run build` (see docs/INSTALL.md). Loading a raw
    scripts/*.js path here directly will fail with an unresolved import.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Agent not found: {path}. {resources.missing_agent_hint()}") from None


def is_gitignored(path):
    """Ask git whether `path` is covered by .gitignore.

    True / False when git can tell, None when it can't (git isn't installed,
    or `path` isn't inside a git work tree). Uses `git check-ignore`, so it
    reflects the repo's real .gitignore rules rather than a guess at them.
    """
    path = os.path.abspath(path)
    cwd = os.path.dirname(path)
    while cwd and not os.path.isdir(cwd):  # the output dir may not exist yet
        parent = os.path.dirname(cwd)
        if parent == cwd:
            return None
        cwd = parent
    try:
        result = subprocess.run(
            ["git", "check-ignore", "-q", "--", path],
            cwd=cwd, capture_output=True, text=True,
        )
    except OSError:  # no git on PATH
        return None
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None  # 128: not a repository / path outside it


class AgentInitError(RuntimeError):
    """The agent's rpc.exports.init() threw - almost always a profile problem
    (a missing offset or record layout); the message says which."""


class AgentRun:
    """Handle yielded by spawn_agent(): the spawned pid, the attached session
    and the loaded script, plus resume() for the one step the caller times."""

    def __init__(self, device, pid):
        self.device = device
        self.pid = pid
        self.session = None
        self.script = None
        self.resumed = False

    def resume(self):
        """Let the spawned process run. Until this succeeds, leaving the
        `with` block (normally or by exception) kills the process."""
        self.device.resume(self.pid)
        self.resumed = True


class ProcessNotFound(RuntimeError):
    """No running process answers to the name or pid given to attach_agent()."""


def find_process(device, process):
    """The pid of `process` - digits are a pid, anything else a process name the device knows."""
    text = str(process).strip()
    if text.isdigit():
        return int(text)
    try:
        return device.get_process(text).pid
    except Exception as e:
        raise ProcessNotFound(f"no running process named {text!r} on the device ({e}) - pass its pid, or start the app first") from e


@contextmanager
def attach_agent(device, process, source, on_message, on_detached=None, params=None):
    """Attach to a process that is ALREADY running, load the agent `source`, hand it `params` through
    rpc.exports.init with the stage "late" (the app's runtime is up; scripts/_resolve.js needs to know), and
    yield an AgentRun - the counterpart of spawn_agent() for an attach that comes after the app has done its
    work (docs/SNAPSHOT.md).

    The process is never killed and never resumed: it was not spawned here, so on the way out - however the
    block ends - the session is detached and nothing else touched. Cleanup errors are swallowed so they
    can't mask the original exception."""
    pid = find_process(device, process)
    run = AgentRun(device, pid)
    run.resumed = True          # nothing to resume, and nothing to kill: this process was not ours to start
    try:
        run.session = device.attach(pid)
        if on_detached is not None:
            run.session.on("detached", on_detached)
        run.script = run.session.create_script(source)
        run.script.on("message", on_message)
        run.script.load()
        if params is not None:
            try:
                run.script.exports_sync.init("late", params)
            except Exception as e:
                raise AgentInitError(f"the agent refused its parameters: {e}") from e
        yield run
    finally:
        if run.session is not None:
            try:
                run.session.detach()
                print("[*] Detached.")
            except Exception:
                pass


@contextmanager
def spawn_agent(device, target, source, on_message, on_detached=None, params=None):
    """Spawn `target` suspended, attach, load the agent `source`, hand it
    `params` through rpc.exports.init (when given), and yield an AgentRun. The
    caller decides when to `run.resume()`.

    Guarantees on the way out, however the block ends (normal return, an
    exception, Ctrl+C):
      - if the process was never resumed - i.e. attach, script creation,
        script load, init (e.g. an offset the profile doesn't set) or resume
        itself failed - it is killed rather than left frozen at spawn;
      - the session, if one was attached, is detached.
    Cleanup errors are swallowed so they can't mask the original exception;
    that exception still propagates.
    """
    pid = device.spawn([target])
    run = AgentRun(device, pid)
    try:
        run.session = device.attach(pid)
        if on_detached is not None:
            run.session.on("detached", on_detached)

        run.script = run.session.create_script(source)
        run.script.on("message", on_message)
        run.script.load()
        if params is not None:
            try:
                run.script.exports_sync.init("early", params)
            except Exception as e:
                raise AgentInitError(f"the agent refused its parameters: {e}") from e

        yield run
    finally:
        if not run.resumed:
            try:
                device.kill(pid)
            except Exception:
                pass
        if run.session is not None:
            try:
                run.session.detach()
                print("[*] Detached.")
            except Exception:
                pass
