"""
What verified runs learned about each BUILD of the target's IL2CPP module, kept outside the repo.

A build is named by the module's own identity - the Mach-O UUID or the ELF build-id (retk/buildid.py reads
it from a file, scripts/_buildid.js from the loaded module). The same build is the same code, so a hook
address that a run proved right for it is right the next time too:

    run 1, a build the cache has not seen   the agent finds the addresses the way it always did (the
                                            profile's names asked of the IL2CPP runtime, else the
                                            profile's RVA); if the dump then passes its layout check,
                                            the addresses are recorded under that build
    run 2, the same build                   the agent is given them and hooks them as they are - no
                                            lookup, and it need not wait for the runtime to come up
    a rebuilt app                           a different id: nothing is cached for it, so it is looked
                                            up afresh (and recorded, once it passes)

One JSON file per build, in <data dir>/builds/<target>/<kind>_<id>.json (retk/paths.py says where that
is on this machine; `retk builds where`):

    {
      "schema_version": 1,
      "build":   {"kind": "gnu-build-id", "id": "8e9fd827446c..."},
      "target":  "com.example.game",
      "module":  "libil2cpp.so",
      "offsets": {"table_a": "0x1c2a4f0"},                 # RVAs, hex like a profile's
      "sources": {"table_a": "name"},                      # how each one was found: name | rva | override | cache
      "recorded": {"at": "2026-11-02T10:11:12+00:00", "tool": "run_dump.py", "profile": "game",
                   "records": 41, "layout_check": "ok"}    # when, by what, and the evidence it passed
    }

`schema_version` is how the layout of this file can change without breaking the files already written:
a file of an older version is migrated when it is read (MIGRATIONS); one written by a NEWER toolkit is
left alone - not read, never overwritten - and the run simply behaves as if the build were unknown.
A file that is damaged, or does not describe the build its name says, is ignored with a note.

Everything here is a convenience, never a precondition: with `--build-cache off`, or when a file cannot be
read or written, the run is what it was before the cache existed.

    retk builds where                 # where this machine keeps everything
    retk builds key libil2cpp.so      # the build id of a binary
    retk builds list [--target ID]    # what is recorded
"""
import argparse
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import buildid
from . import paths
SCHEMA_VERSION = 1

# {version: function(raw dict) -> raw dict of version + 1}. Empty: version 1 is the first. When the layout
# changes, bump SCHEMA_VERSION and add the step from the old version here - old files then keep working.
MIGRATIONS = {}

MODES = ("auto", "rescan", "off")      # --build-cache: use and record / look up again but record / neither
SOURCES = ("name", "rva", "override", "cache")
_HEX = re.compile(r"0x[0-9a-fA-F]+")


class CacheError(Exception):
    """A cache file that cannot be used; the message says why."""


class NewerSchema(CacheError):
    """A file written by a newer toolkit than this one."""


@dataclass
class Entry:
    build: buildid.BuildId
    target: str
    module: str
    offsets: dict                                   # {key: RVA int}
    sources: dict = field(default_factory=dict)     # {key: how it was found}
    recorded: dict = field(default_factory=dict)
    path: "Path | None" = None


def slug(target):
    """A directory name for a target id: letters, digits and . _ - (nothing that is a path)."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip(".") or "_"


def entry_path(target, build):
    return paths.builds_dir() / slug(target) / f"{build.filename}.json"


def _int(text, where):
    if not isinstance(text, str) or not _HEX.fullmatch(text):
        raise CacheError(f"{where}: an RVA must be a 0x... string, got {text!r}")
    value = int(text, 16)
    if value <= 0:
        raise CacheError(f"{where}: an RVA of 0 is not an address")
    return value


def migrate(raw):
    """`raw` brought up to SCHEMA_VERSION. Raises NewerSchema / CacheError."""
    if not isinstance(raw, dict):
        raise CacheError("not a JSON object")
    version = raw.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise CacheError(f"no usable schema_version (got {version!r})")
    if version > SCHEMA_VERSION:
        raise NewerSchema(f"schema_version {version} was written by a newer re-toolkit "
                          f"(this one reads up to {SCHEMA_VERSION})")
    while version < SCHEMA_VERSION:
        step = MIGRATIONS.get(version)
        if step is None:
            raise CacheError(f"schema_version {version} cannot be migrated: no step to {version + 1}")
        raw = step(dict(raw))
        if not isinstance(raw, dict) or raw.get("schema_version") != version + 1:
            raise CacheError(f"the migration from schema_version {version} did not produce version {version + 1}")
        version += 1
    return raw


def parse_entry(raw, path=None):
    """An Entry from the JSON read from `path`. Raises CacheError (NewerSchema) for anything unusable."""
    raw = migrate(raw)
    where = str(path) if path else "cache entry"
    b = raw.get("build")
    if not (isinstance(b, dict) and isinstance(b.get("kind"), str) and isinstance(b.get("id"), str)
            and buildid.valid_id(b["kind"], b["id"])):
        raise CacheError(f"{where}: `build` must be {{kind: one of {', '.join(buildid.KINDS)}, id: ...}}")
    build = buildid.BuildId(b["kind"], b["id"])
    for key in ("target", "module"):
        if not (isinstance(raw.get(key), str) and raw[key]):
            raise CacheError(f"{where}: `{key}` must be a non-empty string")
    offsets = raw.get("offsets")
    if not isinstance(offsets, dict) or not offsets:
        raise CacheError(f"{where}: `offsets` must be a non-empty object")
    parsed = {k: _int(v, f"{where}: offsets.{k}") for k, v in offsets.items()}
    sources = raw.get("sources") if isinstance(raw.get("sources"), dict) else {}
    recorded = raw.get("recorded") if isinstance(raw.get("recorded"), dict) else {}
    if path is not None and Path(path).name != f"{build.filename}.json":
        raise CacheError(f"{where}: the file is named for a different build than it describes")
    return Entry(build, raw["target"], raw["module"], parsed,
                 {k: v for k, v in sources.items() if k in parsed and v in SOURCES}, dict(recorded), path)


def load_entry(path):
    """The Entry in the file at `path`. Raises CacheError / NewerSchema; OSError if it cannot be read."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except ValueError as e:
        raise CacheError(f"{path}: not valid JSON ({e})") from None
    return parse_entry(raw, path)


def load_target(target):
    """({"kind:id": Entry}, [problem text, ...]) for every build recorded for `target`. A file that cannot
    be used is a problem to mention, never a reason to stop."""
    folder = paths.builds_dir() / slug(target)
    entries, problems = {}, []
    try:
        files = sorted(folder.glob("*.json"))
    except OSError as e:
        return {}, [f"{folder}: {e}"]
    for path in files:
        try:
            entry = load_entry(path)
        except (CacheError, OSError) as e:
            problems.append(f"{path.name}: {e} - ignored")
            continue
        if entry.target != target:
            continue                                  # another target whose id slugs to the same folder
        entries[entry.build.text] = entry
    return entries, problems


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_atomically(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def to_json(entry):
    return json.dumps({
        "schema_version": SCHEMA_VERSION,
        "build": {"kind": entry.build.kind, "id": entry.build.id},
        "target": entry.target,
        "module": entry.module,
        "offsets": {k: hex(v) for k, v in sorted(entry.offsets.items())},
        "sources": dict(sorted(entry.sources.items())),
        "recorded": entry.recorded,
    }, indent=2, ensure_ascii=False) + "\n"


def remember(target, module, build, offsets, sources, recorded):
    """Record `offsets` ({key: RVA}) for `build` of `module` in `target`, merged into what is already
    recorded for that build (another agent hooks other keys). Returns (path, "new" | "updated" | "same").
    Raises CacheError (a newer-schema file is never overwritten) or OSError."""
    path = entry_path(target, build)
    old = None
    if path.exists():
        try:
            old = load_entry(path)
        except NewerSchema:
            raise
        except CacheError:
            old = None                                 # damaged: replaced by this verified one
    if old is not None and old.module != module:
        old = None                                     # the same build under another module name: start over
    merged = {**(old.offsets if old else {}), **offsets}
    merged_sources = {**(old.sources if old else {}), **sources}
    if old is not None and merged == old.offsets and {k: merged_sources.get(k) for k in merged} == \
            {k: old.sources.get(k) for k in merged}:
        return path, "same"
    entry = Entry(build, target, module, merged, merged_sources, dict(recorded), path)
    _write_atomically(path, to_json(entry))
    return path, "new" if old is None else "updated"


def agent_cache(entries, module, skip=()):
    """`params["cache"]` for the agent from `entries` (load_target): {"builds": {"kind:id": {key: RVA}}} for the
    builds recorded under `module`, without the keys in `skip` (an explicit --offset is not second-guessed).
    None when there is nothing to send."""
    builds = {}
    for text, entry in entries.items():
        if entry.module != module:
            continue
        offsets = {k: v for k, v in entry.offsets.items() if k not in skip}
        if offsets:
            builds[text] = offsets
    return {"builds": builds} if builds else None


class BuildCache:
    """One run's use of the build cache: what is known for (target, module), what to tell the agent, and what
    to record afterwards. `mode`: "auto" use and record, "rescan" ignore what is known but record, "off" neither."""

    def __init__(self, mode, target, module, overrides=(), profile_name=None):
        if mode not in MODES:
            raise ValueError(f"build cache mode must be one of {', '.join(MODES)}, got {mode!r}")
        self.mode, self.target, self.module = mode, target, module
        self.overrides = set(overrides)
        self.profile_name = profile_name
        self.entries, self.problems = ({}, []) if mode == "off" else load_target(target)

    def agent_params(self):
        """The `cache` params for the agent: only in "auto" (a rescan is told nothing)."""
        if self.mode != "auto":
            return None
        return agent_cache(self.entries, self.module, skip=self.overrides)

    def known(self, build_text):
        entry = self.entries.get(build_text)
        return entry if entry is not None and entry.module == self.module else None

    def intro(self):
        """Console lines for the start of a run."""
        if self.mode == "off":
            return ["[i] build cache = off"]
        mine = [e for e in self.entries.values() if e.module == self.module]
        lines = [f"[i] build cache = {paths.builds_dir() / slug(self.target)}  "
                 f"({len(mine)} build(s) recorded for {self.module}; mode {self.mode})"]
        lines += [f"[!] build cache: {p}" for p in self.problems]
        return lines

    def render(self, report):
        """Console lines saying which build the agent ran in and where its addresses came from."""
        if self.mode == "off" or not report:
            return []
        build = report.get("build")
        methods = report.get("methods", [])
        if not build:
            return ["[i] build cache: no Mach-O UUID or GNU build-id could be read from the loaded module - "
                    "this run is not keyed by build"]
        text = f"{build['kind']}:{build['id']}"
        cached = [m["key"] for m in methods if m.get("source") == "cache"]
        known = self.known(text)
        if cached:
            when = (known.recorded.get("at") if known else None) or "an earlier run"
            return [f"[i] build {text}: seen before - {', '.join(cached)} taken from the build cache (recorded {when})"]
        if known and self.mode == "rescan":
            return [f"[i] build {text}: seen before, but --build-cache rescan looked everything up again"]
        if any(m.get("source") == "name" for m in methods):
            return [f"[i] build {text}: not seen before - looked up by name"]
        return [f"[i] build {text}: not seen before, and nothing here has a name to look up: the profile's RVAs "
                "were used, which belong to whichever build they were written for"]

    def remember(self, report, verified, records):
        """Record what this run hooked for its build, when it is verified. Returns console lines.
        `verified`: the dump passed its layout check and was not stopped; `records`: how many it holds."""
        if self.mode == "off" or not report:
            return []
        build = report.get("build")
        methods = report.get("methods", [])
        if not build or not methods or report.get("mode") not in (None, "auto"):
            return []
        if not verified:
            return ["[i] build cache: not recorded - the dump did not pass its layout check"]
        if any(m.get("rva") in (None, 0) or m.get("source") == "none" for m in methods):
            return []
        offsets = {m["key"]: m["rva"] for m in methods}
        bid = buildid.BuildId(build["kind"], build["id"])
        prior = self.known(bid.text)
        sources = {}
        for m in methods:
            if m["key"] in self.overrides:
                sources[m["key"]] = "override"
            elif m["source"] == "cache":
                sources[m["key"]] = (prior.sources.get(m["key"]) if prior else None) or "cache"     # how it was FOUND stays
            else:
                sources[m["key"]] = m["source"]
        recorded = {"at": _now(), "tool": "run_dump.py", "profile": self.profile_name,
                    "records": records, "layout_check": "ok"}
        try:
            path, how = remember(self.target, self.module, bid, offsets, sources, recorded)
        except (CacheError, OSError) as e:
            return [f"[!] build cache: could not record {bid.text}: {e}"]
        if how == "same":
            return [f"[i] build cache: {bid.text} already holds exactly these addresses"]
        shown = ", ".join(f"{k}={hex(v)}" for k, v in sorted(offsets.items()))
        return [f"[+] build cache: recorded {shown} for {bid.text} -> {path}"]


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------

def cmd_where(_args):
    print(f"data dir      {paths.data_dir()}")
    print(f"profiles      {paths.profiles_dir()}")
    print(f"builds        {paths.builds_dir()}")
    legacy = paths.LEGACY_PROFILES_DIR
    if legacy is not None and legacy.is_dir() and any(legacy.glob("*.json")):
        print(f"legacy        {legacy}  (profiles still here are read, with a warning; move them to the profiles dir)")
    return 0


def cmd_key(args):
    try:
        build = buildid.from_file(args.binary)
    except OSError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    if build is None:
        print(f"[!] {args.binary}: no Mach-O UUID or GNU build-id (a 64-bit Mach-O or ELF64 that has one)", file=sys.stderr)
        return 1
    print(build.text)
    return 0


def cmd_list(args):
    root = paths.builds_dir()
    targets = [slug(args.target)] if args.target else sorted(p.name for p in root.glob("*") if p.is_dir())
    shown = 0
    for folder in targets:
        for path in sorted((root / folder).glob("*.json")):
            try:
                e = load_entry(path)
            except (CacheError, OSError) as err:
                print(f"[!] {path}: {err}")
                continue
            shown += 1
            print(f"{e.target}  {e.module}  {e.build.text}")
            print("    " + ", ".join(f"{k}={hex(v)} ({e.sources.get(k, '?')})" for k, v in sorted(e.offsets.items())))
            print(f"    recorded {e.recorded.get('at', '?')}  {path}")
    if not shown:
        print(f"nothing recorded in {root}")
    return 0


def main(argv=None, prog=None):
    ap = argparse.ArgumentParser(prog=prog, description="The per-build cache and where retk keeps things (docs/PROFILES.md).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("where", help="print where this machine keeps profiles and builds").set_defaults(fn=cmd_where)
    p = sub.add_parser("key", help="print the build id of a binary (64-bit Mach-O or ELF64)")
    p.add_argument("binary")
    p.set_defaults(fn=cmd_key)
    p = sub.add_parser("list", help="list the builds recorded")
    p.add_argument("--target", metavar="ID", help="only this target")
    p.set_defaults(fn=cmd_list)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
