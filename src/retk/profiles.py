"""
profiles.py

A profile is ONE JSON file that holds everything specific to a real target:
its package id, where its code lives (RVAs), and how its records are laid out.
Nothing in this repo is ever configured with a real value - not an offset, not
a package id, not a field name. The profile lives outside git, in the profiles/
folder of your user data directory (retk/paths.py; $RE_PROFILES_DIR moves it),
the drivers read it, and the agents receive what they need at runtime through
rpc.exports.init(stage, params). Because the tree never holds a real value,
there is nothing to guard against committing one.

profile.example.json is the template (made-up names, every offset 0x0, which
the agents refuse to hook).

    {
      "target":  "com.example.unitygame",        # package/bundle id to spawn
      "remote":  "127.0.0.1:27042",              # frida-server address (optional)
      "module":  "UnityFramework",               # the IL2CPP module to hook in: this, or "platform"
                                                 # below, or --module / --platform on the command
                                                 # line (one of them is required: nothing is assumed)
      "platform": "ios",                         # optional: ios | android | windows - stands for
                                                 # that platform's usual module name (see
                                                 # PLATFORM_MODULES); `module` beats it
      "offsets": {"table_a": "0x0", ...},        # RVAs: Ghidra address, Image Base = 0
      "layouts": { ... }                         # see layouts.py
    }

`offsets` are RVAs (not file offsets - see README.md's "RVA vs file offset").
Each agent asks for the keys it needs by name (dump_table_a.js: `table_a`, ...)
and refuses to hook at 0. A profile may hold offsets for several agents; unused
ones are ignored.

A profile may also say WHERE the same functions are by name - the optional `names`
section. With it the agent asks the IL2CPP runtime for the address first and uses the
RVA only as the fallback (docs/NAME_LOOKUP.md):

    "names": {
      "methods": {"table_a": "ExampleNamespace.ExampleTableA::Unpack/1"},   # an offsets key -> Class::Method
      "fields":  {"TableARecord": {"class": "ExampleNamespace.ExampleTableA",
                                   "map": {"id": "id", "name": "label"}}},  # layout field -> IL2CPP field
      "exports": {"il2cpp_class_from_name": "renamed_export"},              # if the build renamed an export
      "snapshot": {"TableARecord": {                                        # where a RUNNING app holds the table
          "static": {"class": "ExampleNamespace.ExampleTableB", "field": "all", "container": "list"},
          "heap": {"class": "ExampleNamespace.ExampleTableA"}}}
    }

`methods` values are `Namespace.Class::Method[/N]` or an object (il2cpp_names.py has the
grammar); `fields` makes the agent read each field's offset from the runtime and compare it
with the layout; `exports` maps an IL2CPP API function to the name the module really
exports it under. An `--offset KEY=HEX` on the command line beats the name for that key.

Finding a profile: `--profile NAME` means NAME.json in the profiles/ folder of the
user's data directory ($RE_PROFILES_DIR/NAME.json when that is set; `python
retk builds where` prints the place). A profile still in this repo's old,
git-ignored profiles/ is read with a warning. Anything with a path separator or
ending in .json is used as a path.

    retk profile init NAME                      # start a profile: the example, copied into the profiles folder
    retk profile layout NAME        # print each record's layout
    retk profile params NAME        # the JSON an agent receives, for
                                               # `frida ... -P "$(retk profile params NAME)"`
    retk profile params NAME --offset probe=0xab68fc8 [--offset KEY=HEX ...] [--module NAME | --platform P]
                                               # the same overrides the drivers take, for the agents
                                               # that have no driver (probe_record.js, trace_lookup.js)
    retk profile params NAME --resolve rva
                                               # ignore the profile's `names`: hook the RVAs only
"""
import argparse
import copy
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import il2cpp_names, layouts, paths, resources
ENV_PROFILES_DIR = paths.ENV_PROFILES_DIR
DEFAULT_REMOTE = "127.0.0.1:27042"

# The library that holds the IL2CPP runtime, by platform. THIS TABLE IS THE ONLY PLACE THESE
# NAMES ARE TYPED IN CODE (the docs and docstrings quote them for people; the agents' hints
# keep a copy in scripts/_lib.js, RUNTIME_MODULES; tests/test_module_lookup.py fails when a
# code string elsewhere repeats one, or when the two tables differ).
PLATFORM_MODULES = {
    "ios": "UnityFramework",
    "android": "libil2cpp.so",
    "windows": "GameAssembly.dll",
}
PLATFORM_LABELS = {"ios": "iOS", "android": "Android", "windows": "Windows"}

# There is deliberately no default module: which library holds the IL2CPP runtime depends on
# the platform, and a default would quietly pick one platform for everybody - an agent waiting
# on a module that never loads looks exactly like an agent that has nothing to report. A
# platform is therefore something you SAY (--platform, or `platform` in the profile); it is
# never guessed, and with neither a module nor a platform given there is an error, not a
# fallback.
NO_MODULE_HELP = ("no module name - set `module` in your profile or pass --module NAME (or name the "
                  "platform: --platform {" + "|".join(PLATFORM_MODULES) + "}, or `platform` in the "
                  "profile): the library that holds the IL2CPP runtime in the target ("
                  + ", ".join(f"{PLATFORM_MODULES[p]} on {PLATFORM_LABELS[p]}" for p in PLATFORM_MODULES)
                  + ")")


# How an agent finds the address to hook (docs/NAME_LOOKUP.md):
#   auto   the name first, the profile's RVA when the name cannot be resolved (the default);
#   names  the name only - an agent that cannot resolve it refuses instead of falling back;
#   rva    the profile's RVA only, names ignored (what the toolkit did before names existed).
RESOLVE_MODES = ("auto", "names", "rva")

# What a `names.snapshot.<Record>.static` field may hold. Keep equal to CONTAINERS in scripts/_snapshot.js (tested).
SNAPSHOT_CONTAINERS = ("object", "array", "list")


class ProfileError(ValueError):
    pass


@dataclass
class Profile:
    name: str
    path: Path
    target: str
    remote: str = DEFAULT_REMOTE
    module: "str | None" = None                       # None: --module / --platform must say
    platform: "str | None" = None                     # a PLATFORM_MODULES key; `module` beats it
    offsets: dict = field(default_factory=dict)       # {key: int RVA}
    layouts: "dict | None" = None                     # validated, see layouts.validate()
    names: dict = field(default_factory=dict)         # {"methods": {key: MethodSpec}, "fields": {...}, "exports": {...}}


def profiles_dir():
    """Where a bare profile name is looked up: <data dir>/profiles in the user's own data directory
    (retk/paths.py), not in the repo - $RE_PROFILES_DIR moves it."""
    return paths.profiles_dir()


def find(ref):
    """The profile file `ref` names: a path, or a bare name looked up in profiles_dir()."""
    ref = str(ref)
    as_path = Path(ref).expanduser()
    if os.sep in ref or "/" in ref or ref.endswith(".json"):
        if not as_path.is_file():
            raise ProfileError(f"profile {ref}: no such file")
        return as_path
    candidate = profiles_dir() / f"{ref}.json"
    if not candidate.is_file():
        # Profiles used to live in the repo's profiles/ (git-ignored). Still read from there when it is
        # where yours is - unless you pointed $RE_PROFILES_DIR somewhere, which is then the only place.
        legacy = paths.LEGACY_PROFILES_DIR / f"{ref}.json" if paths.LEGACY_PROFILES_DIR is not None else None
        if not os.environ.get(ENV_PROFILES_DIR) and legacy is not None and legacy.is_file():
            print(f"[!] profile {ref!r} was read from the repo's own profiles/ ({legacy}): profiles belong outside "
                  f"the repo now - move it to {candidate}", file=sys.stderr)
            return legacy
        raise ProfileError(f"profile {ref!r} not found - expected {candidate} "
                           f"(or pass a path, or set ${ENV_PROFILES_DIR})")
    return candidate


def init_profile(name, force=False):
    """Copy the example profile into the profiles folder as NAME.json and return where it went.

    The way to start a profile on an install that has no repo to copy profile.example.json from. Refuses a
    path (a name is what `--profile NAME` takes), the template being absent, and an existing file unless
    `force`: a profile holds hand-found offsets and layouts, which must not be overwritten by accident."""
    if not name or "/" in name or "\\" in name or name.endswith(".json") or name in (".", ".."):
        raise ProfileError(f"profile init takes a NAME ({name!r} is a path or a file name): it creates "
                           f"NAME.json in {profiles_dir()}")
    template = resources.example_profile_path()
    if template is None:
        raise ProfileError("the example profile is not part of this install - get profile.example.json from "
                           "the repository")
    target = profiles_dir() / f"{name}.json"
    if target.exists() and not force:
        raise ProfileError(f"{target} already exists (--force replaces it)")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(template.read_bytes())
    return target


def parse_hex(value, where):
    """An RVA from JSON: a 0x-prefixed hex string (or a plain int)."""
    if isinstance(value, str) and re.fullmatch(r"0[xX][0-9a-fA-F]+", value.strip()):
        return int(value.strip(), 16)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    raise ProfileError(f"{where}: expected a 0x-prefixed hex string, got {value!r}")


def parse_offset(text):
    """Parse a hex offset, with or without a 0x prefix ('0xab68fc8' / 'ab68fc8')."""
    try:
        value = int(str(text).strip(), 16)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"not a hex offset: {text!r} (expected e.g. 0xab68fc8)") from None
    if value < 0:
        raise argparse.ArgumentTypeError(f"offset must not be negative: {text!r}")
    return value


def parse_offset_override(text):
    """`KEY=HEX` -> (KEY, int), for --offset."""
    key, sep, value = str(text).partition("=")
    if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        raise argparse.ArgumentTypeError(
            f"expected KEY=HEX (e.g. table_a=0xab68fc8), got {text!r}")
    return key, parse_offset(value)


def parse_names(raw, schema, where):
    """The profile's `names` section, validated: {"methods": {key: MethodSpec}, "fields":
    {record: {"class": MethodSpec-like, "map": {layout field: IL2CPP field}}}, "exports":
    {api function: exported name}}. `schema` is the validated layouts (or None) - a `fields`
    entry must name a record and layout fields that exist there."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ProfileError(f"{where}: names must be an object")
    unknown = sorted(set(raw) - {"methods", "fields", "exports", "snapshot"})
    if unknown:
        raise ProfileError(f"{where}: unknown key(s) {', '.join(unknown)} (allowed: methods, fields, exports, snapshot)")
    out = {"methods": {}, "fields": {}, "exports": {}, "snapshot": {}}

    for key, value in (raw.get("methods") or {}).items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ProfileError(f"{where}.methods: {key!r} is not an offsets key")
        try:
            out["methods"][key] = il2cpp_names.parse_method_spec(value, f"{where}.methods.{key}")
        except il2cpp_names.SpecError as e:
            raise ProfileError(str(e)) from e

    for record, entry in (raw.get("fields") or {}).items():
        at = f"{where}.fields.{record}"
        if not isinstance(entry, dict) or set(entry) - {"class", "assembly", "map"}:
            raise ProfileError(f"{at}: expected {{\"class\": ..., \"map\": {{layout field: IL2CPP field}}}} "
                               f"(and optionally \"assembly\")")
        if not isinstance(entry.get("map"), dict) or not entry["map"]:
            raise ProfileError(f"{at}.map: needs at least one `layout field: IL2CPP field name` pair")
        try:
            # a class is named like a method's class: reuse the grammar with a placeholder method
            cls = il2cpp_names.parse_method_spec({"class": entry.get("class"), "method": "_",
                                                  "assembly": entry.get("assembly")}, at)
        except il2cpp_names.SpecError as e:
            raise ProfileError(str(e)) from e
        known = None
        if schema is not None:
            if record not in schema["records"]:
                raise ProfileError(f"{at}: the profile's layouts define no record {record!r}")
            known = {f["name"] for f in schema["records"][record]["fields"]}
        for layout_field, il2cpp_field in entry["map"].items():
            if not isinstance(il2cpp_field, str) or not il2cpp_field.strip():
                raise ProfileError(f"{at}.map.{layout_field}: the IL2CPP field name must be a non-empty string")
            if known is not None and layout_field not in known:
                raise ProfileError(f"{at}.map: {layout_field!r} is not a field of the layout's {record}")
        out["fields"][record] = {"namespace": cls.namespace, "class": cls.cls, "assembly": cls.assembly,
                                 "map": {k: v.strip() for k, v in entry["map"].items()}}

    for api, exported in (raw.get("exports") or {}).items():
        if api not in il2cpp_names.API_FUNCTIONS:
            raise ProfileError(f"{where}.exports: {api!r} is not an IL2CPP function this toolkit calls "
                               f"(known: {', '.join(il2cpp_names.API_FUNCTIONS)})")
        if not isinstance(exported, str) or not exported.strip():
            raise ProfileError(f"{where}.exports.{api}: the exported name must be a non-empty string")
        out["exports"][api] = exported.strip()

    for record, entry in (raw.get("snapshot") or {}).items():
        out["snapshot"][record] = _parse_snapshot(record, entry, f"{where}.snapshot.{record}", schema, out["fields"])
    return out


def _class_of(entry, at):
    """(namespace, class, assembly) of an object with `class` and optional `assembly`."""
    try:
        spec = il2cpp_names.parse_method_spec({"class": entry.get("class"), "method": "_",
                                               "assembly": entry.get("assembly")}, at)
    except il2cpp_names.SpecError as e:
        raise ProfileError(str(e)) from e
    return spec.namespace, spec.cls, spec.assembly


def _parse_snapshot(record, entry, at, schema, fields):
    """One `names.snapshot.<Record>`: {"static": {...}, "heap": {...}} validated and normalised for the agent."""
    if schema is not None and record not in schema["records"]:
        raise ProfileError(f"{at}: the profile's layouts define no record {record!r}")
    if not isinstance(entry, dict) or not entry or set(entry) - {"static", "heap"}:
        raise ProfileError(f"{at}: expected {{\"static\": {{...}}, \"heap\": ...}} with at least one of them")
    out = {}
    if "static" in entry:
        st = entry["static"]
        if not isinstance(st, dict) or set(st) - {"class", "assembly", "field", "container"}:
            raise ProfileError(f"{at}.static: expected {{\"class\", \"field\", \"container\"}} (and optionally \"assembly\")")
        if not isinstance(st.get("field"), str) or not st["field"].strip() or len(st["field"].split()) != 1:
            raise ProfileError(f"{at}.static.field: the name of the static field, one word")
        if st.get("container") not in SNAPSHOT_CONTAINERS:
            raise ProfileError(f"{at}.static.container: one of {', '.join(SNAPSHOT_CONTAINERS)} - what the field holds "
                               f"(a single record, an array of them, a List<T>), got {st.get('container')!r}")
        namespace, cls, assembly = _class_of(st, f"{at}.static")
        out["static"] = {"namespace": namespace, "class": cls, "assembly": assembly, "field": st["field"].strip(),
                         "container": st["container"]}
    if "heap" in entry:
        heap = entry["heap"]
        if heap is True:
            heap = {}
        if not isinstance(heap, dict) or set(heap) - {"class", "assembly", "max", "budget_ms"}:
            raise ProfileError(f"{at}.heap: true, or an object with \"class\" (and optionally \"assembly\", \"max\", \"budget_ms\")")
        for key in ("max", "budget_ms"):
            if key in heap and (isinstance(heap[key], bool) or not isinstance(heap[key], int) or heap[key] <= 0):
                raise ProfileError(f"{at}.heap.{key}: a positive whole number, got {heap[key]!r}")
        if "class" not in heap:
            known = fields.get(record)
            if known is None:
                raise ProfileError(f"{at}.heap: no \"class\" given and names.fields has no entry for {record} to take it from")
            heap = {**heap, "class": ((known["namespace"] + ".") if known["namespace"] else "") + known["class"],
                    "assembly": heap.get("assembly", known["assembly"])}
        namespace, cls, assembly = _class_of(heap, f"{at}.heap")
        out["heap"] = {"namespace": namespace, "class": cls, "assembly": assembly,
                       **{k: heap[k] for k in ("max", "budget_ms") if k in heap}}
    return out


def snapshot_record(profile, name=None):
    """Which `names.snapshot` record a snapshot is of: `name`, or the only one the profile has."""
    entries = (profile.names or {}).get("snapshot") or {}
    if not entries:
        raise ProfileError("the profile has no names.snapshot: nothing says where the table lives in a running app")
    if name:
        if name not in entries:
            raise ProfileError(f"names.snapshot has no record {name!r} (has: {', '.join(entries)})")
        return name
    if len(entries) == 1:
        return next(iter(entries))
    raise ProfileError(f"names.snapshot has several records ({', '.join(entries)}): say which with --snapshot RECORD")


def load(ref):
    path = find(ref)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ProfileError(f"{path}: {e}") from e
    if not isinstance(raw, dict):
        raise ProfileError(f"{path}: a profile is a JSON object")

    for key in ("target", "remote", "module", "platform"):
        if key in raw and not (isinstance(raw[key], str) and raw[key].strip()):
            raise ProfileError(f"{path}: {key} must be a non-empty string")
    if "platform" in raw and raw["platform"] not in PLATFORM_MODULES:
        raise ProfileError(f"{path}: platform must be one of {', '.join(PLATFORM_MODULES)}, "
                           f"got {raw['platform']!r}")
    if not raw.get("target"):
        raise ProfileError(f"{path}: target (the package/bundle id) is required")

    offsets = {}
    for key, value in (raw.get("offsets") or {}).items():
        offsets[key] = parse_hex(value, f"{path}: offsets.{key}")

    schema = None
    if raw.get("layouts") is not None:
        try:
            schema = layouts.validate(raw["layouts"])
        except layouts.SchemaError as e:
            raise ProfileError(f"{path}: layouts: {e}") from e

    names = parse_names(raw.get("names"), schema, f"{path}: names")

    return Profile(name=path.stem, path=path, target=raw["target"],
                   remote=raw.get("remote", DEFAULT_REMOTE), module=raw.get("module"),
                   platform=raw.get("platform"), offsets=offsets, layouts=schema, names=names)


def platform_module(platform):
    """The usual IL2CPP module name on `platform` (a PLATFORM_MODULES key)."""
    try:
        return PLATFORM_MODULES[platform]
    except KeyError:
        raise ProfileError(f"platform must be one of {', '.join(PLATFORM_MODULES)}, got {platform!r}") from None


def resolve_module(profile=None, module=None, platform=None):
    """(module name, where it came from): THE place a module name is decided - every driver,
    `profiles.py params` and the tests come through here, and the agents then receive the result
    as `params["module"]` (scripts/_lib.js's waitForModule is the one place that looks it up).

    Command line beats profile, and a name beats a platform at each level:
    --module, --platform, the profile's `module`, the profile's `platform`. Raises ProfileError
    when none of them is set - there is no default (see NO_MODULE_HELP)."""
    if module:
        return module, "CLI"
    if platform:
        return platform_module(platform), f"CLI --platform {platform}"
    if profile and profile.module:
        return profile.module, "profile"
    if profile and profile.platform:
        return platform_module(profile.platform), f"profile platform {profile.platform}"
    raise ProfileError(NO_MODULE_HELP)


def add_module_args(parser):
    """--module and --platform, defined once for every command line that takes them (the
    drivers through _common.add_override_args, and `profiles.py params`)."""
    parser.add_argument(
        "--module", metavar="NAME",
        help="name of the IL2CPP module to hook in, e.g. "
             + " or ".join(f"{PLATFORM_MODULES[p]} ({PLATFORM_LABELS[p]})" for p in PLATFORM_MODULES)
             + "; required unless the profile sets `module` or `platform`, or --platform is given")
    parser.add_argument(
        "--platform", choices=tuple(PLATFORM_MODULES),
        help="the target's platform, as a shorthand for that platform's usual module name ("
             + ", ".join(f"{p} = {m}" for p, m in PLATFORM_MODULES.items())
             + "); --module beats it. Never guessed: without --module, --platform or a profile "
               "that names one, there is no module")


def agent_params(profile, module=None, offsets=None, resolve=None, snapshot=None, platform=None):
    """What an agent receives in rpc.exports.init(stage, params). `module`, `offsets` (a
    {key: int} dict) and `resolve` (one of RESOLVE_MODES) override the profile's, e.g. from
    the CLI; so does `platform` (see resolve_module(), which picks the module). Raises
    ProfileError when nothing says which module to hook in, or `resolve` is not a mode.

    An RVA given in `offsets` is an explicit choice for that key, so the name the profile
    holds for it is left out: probing `--offset table_a=0x...` must hook exactly that address.

    `snapshot` is the record of `names.snapshot` that scripts/snapshot_records.js is to read (see
    snapshot_record()): its `static` / `heap` spec goes to the agent as `params["snapshot"]`. A snapshot
    is made of names, so `resolve="rva"` contradicts it."""
    if resolve is not None and resolve not in RESOLVE_MODES:
        raise ProfileError(f"resolve must be one of {', '.join(RESOLVE_MODES)}, got {resolve!r}")
    merged = dict(profile.offsets) if profile else {}
    merged.update(offsets or {})
    module, _source = resolve_module(profile, module, platform)
    params = {"module": module, "offsets": merged}
    if profile and profile.layouts is not None:
        params["layouts"] = layouts.for_agent(profile.layouts)
    names = profile.names if profile else {}
    if names and resolve != "rva":
        methods = {k: spec.as_agent() for k, spec in names.get("methods", {}).items()
                   if k not in (offsets or {})}
        sent = {}
        if methods:
            sent["methods"] = methods
        if names.get("fields"):
            sent["fields"] = copy.deepcopy(names["fields"])
        if names.get("exports"):
            sent["exports"] = dict(names["exports"])
        if sent:
            params["names"] = sent
    if resolve is not None:
        params["resolve"] = resolve
    if snapshot is not None:
        if resolve == "rva":
            raise ProfileError("--resolve rva contradicts a snapshot: it finds the table through the IL2CPP names")
        entry = ((profile.names if profile else {}) or {}).get("snapshot", {}).get(snapshot)
        if entry is None:
            raise ProfileError(f"names.snapshot has no record {snapshot!r}")
        params["snapshot"] = {"record": snapshot, **copy.deepcopy(entry)}
        sent = dict(params.get("names", {}))
        if names.get("fields"):
            sent["fields"] = copy.deepcopy(names["fields"])
        if names.get("exports"):
            sent["exports"] = dict(names["exports"])
        if sent:
            params["names"] = sent
    if resolve == "names" and not params.get("names", {}).get("methods"):
        raise ProfileError("--resolve names needs `names.methods` in the profile (and no --offset for "
                           "the same key): there is nothing to look up by name")
    return params


def main(argv=None, prog=None):
    ap = argparse.ArgumentParser(prog=prog, description="Inspect a profile, or start one (docs/PROFILES.md).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="create NAME.json in the profiles folder from the example profile")
    p.add_argument("name", metavar="NAME", help="the profile's name (what --profile NAME takes)")
    p.add_argument("--force", action="store_true", help="replace NAME.json if it already exists")
    for name, help_ in (("layout", "print each record's layout"),
                        ("params", "print the JSON parameters an agent receives")):
        p = sub.add_parser(name, help=help_)
        p.add_argument("profile", metavar="PROFILE", help="a profile name or path")
        if name == "params":
            add_module_args(p)
            p.add_argument("--offset", metavar="KEY=HEX", action="append", type=parse_offset_override,
                           help="override one RVA, e.g. probe=0xab68fc8 (repeatable)")
            p.add_argument("--resolve", choices=RESOLVE_MODES,
                           help="how the agent finds what to hook: auto (name, then RVA), names, rva")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "init":
            target = init_profile(args.name, force=args.force)
            print(f"created {target}\nedit it (target, module or platform, offsets, layouts), then "
                  f"`{ap.prog} layout {args.name}` checks it")
            return 0
        profile = load(args.profile)
        if args.cmd == "params":
            print(json.dumps(agent_params(profile, module=args.module, platform=args.platform,
                                          offsets=dict(args.offset or []), resolve=args.resolve)))
        else:
            if profile.layouts is None:
                raise ProfileError(f"{profile.path}: no layouts defined")
            print("\n\n".join(layouts.describe(profile.layouts, r) for r in profile.layouts["records"]))
    except ProfileError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
