"""
The `retk` command: one entry point, one subcommand per tool.

    retk dump        run_dump.py        spawn (or attach to) the app, run an agent, export the records
    retk verify      verify_offset.py   trial-hook candidate offsets in the running app, say which are VERIFIED
    retk relocate    relocate_offset.py find a hook point again in a new build (AArch64)
    retk exports     list_exports.py    list the IL2CPP module's exports/symbols
    retk diff        diff_records.py    semantic diff of two dumps, with schema-drift detection
    retk profile     profiles.py        layout | params | init - inspect a profile, or start one
    retk builds      buildcache.py      where | key | list - where retk keeps things, build ids, recorded builds

This file only chooses and forwards: `retk NAME ARGS...` imports the tool's module and calls its
`main(ARGS, prog="retk NAME")`, so every tool keeps its own options, its own --help and its own exit
status. The import is lazy - `retk --help` (and a typo) never loads frida or capstone.

tools/check_identifiers.py is not here on purpose: it guards a git repository's tree (and its denylist
is committed in that repo), which an installed copy of retk does not have. It stays a script of the
repo - `python3 tools/check_identifiers.py`, the pre-commit hook and CI call it.

Exit status: the tool's own; 2 for a command line retk itself cannot make sense of.
"""
import argparse
import importlib
import sys
from collections import namedtuple

from . import __version__

Command = namedtuple("Command", "name module help")

# Order = the order `retk --help` lists them in: the workflow, then the helpers.
COMMANDS = (
    Command("dump", "run_dump",
            "spawn or attach to the app, run a bundled agent, export its records to JSON (--snapshot: read a "
            "running app)"),
    Command("relocate", "relocate_offset",
            "find a hook point again in a new build of the binary (AArch64), by bytes or by Class::Method name"),
    Command("verify", "verify_offset",
            "trial-hook candidate offsets in the running app and say which are VERIFIED"),
    Command("diff", "diff_records",
            "semantic diff of two dumps: added / removed / changed records, schema drift"),
    Command("exports", "list_exports",
            "list the IL2CPP module's exports/symbols (find il2cpp_init in a stripped build)"),
    Command("profile", "profiles",
            "layout | params | init: validate and print a profile, the JSON an agent gets, or start one"),
    Command("builds", "buildcache",
            "where | key | list: where retk keeps profiles and builds, a binary's build id, recorded builds"),
)
BY_NAME = {c.name: c for c in COMMANDS}

EPILOG = """\
after an app update:
  retk relocate OLD_BINARY 0x... NEW_BINARY --json relocate_new.json
  retk verify --profile myapp --from-relocate relocate_new.json
  retk dump --profile myapp --out records_new.json
  retk diff records_old.json records_new.json

`retk COMMAND --help` shows a command's own options. Profiles and per-build records live in your
user data directory (`retk builds where`), never in a repository."""

# The third-party packages the tools need (pinned in requirements.txt - the one place the versions are
# written), named for a clearer message than a bare ImportError.
NEEDS = ("frida", "capstone", "platformdirs")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="retk", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG,
        description="Frida-based inspection of how a Unity + IL2CPP app loads its configuration tables: dump "
                    "the records, carry a hook point across a rebuild, verify it, diff the result.")
    ap.add_argument("--version", action="version", version=f"retk {__version__}")
    sub = ap.add_subparsers(dest="command", metavar="COMMAND", title="commands")
    sub.required = True
    for c in COMMANDS:
        sub.add_parser(c.name, help=c.help)
    return ap


def run(name, args):
    """Run subcommand `name` with the rest of the command line; returns the tool's exit status."""
    command = BY_NAME[name]
    try:
        module = importlib.import_module(f"{__package__}.{command.module}")
    except ModuleNotFoundError as e:
        wanted = (e.name or "").split(".")[0]
        if wanted in NEEDS:
            print(f"retk {name} needs the Python package {wanted!r}, which is not installed here. It is one of "
                  f"re-toolkit's dependencies (pinned in requirements.txt): reinstall retk so pip brings it.",
                  file=sys.stderr)
            return 1
        raise
    status = module.main(list(args), prog=f"retk {name}")
    return 0 if status is None else status


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in BY_NAME:
        return run(argv[0], argv[1:])
    # No command, -h, --version or something that is no command: argparse prints help / the version / the
    # error ("invalid choice", with the commands) and exits (0, 0, 2).
    build_parser().parse_args(argv)
    return 2                                    # unreachable: parse_args exits above
