"""
_common.py

Small shared helper for the driver scripts in tools/. Not meant to be run
directly.

Two jobs:
  1. load_agent_source(): read a bundled Frida agent and (optionally) inject
     FRIDA_OFFSET into it.
  2. add_override_args() / resolve_settings(): let every driver take TARGET,
     REMOTE_ADDR and FRIDA_OFFSET from the command line or from environment
     variables, falling back to the defaults in config.py. Precedence:

         CLI flag  >  environment variable  >  config.py

     Flag           Env var             config.py name
     --target ID    FRIDA_TARGET        TARGET
     --remote H:P   FRIDA_REMOTE_ADDR   REMOTE_ADDR
     --offset HEX   FRIDA_OFFSET        FRIDA_OFFSET

     Offsets are always parsed as hex, with or without a 0x prefix (same
     convention as relocate_offset.py and Ghidra's Symbol Table), so
     `--offset ab68fc8` and `--offset 0xab68fc8` mean the same thing.
"""
import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass

import config

ENV_TARGET = "FRIDA_TARGET"
ENV_REMOTE = "FRIDA_REMOTE_ADDR"
ENV_OFFSET = "FRIDA_OFFSET"


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


def add_override_args(parser, offset=True):
    """Add --target / --remote (and --offset, unless `offset=False`) to `parser`.

    Pass offset=False for drivers whose agent doesn't hook a specific offset
    (e.g. list_exports.py).
    """
    group = parser.add_argument_group(
        "overrides",
        "Each one overrides the matching value in config.py. "
        "Precedence: CLI flag > environment variable > config.py.")
    group.add_argument(
        "--target", metavar="ID",
        help=f"app package/bundle id to spawn (env: {ENV_TARGET})")
    group.add_argument(
        "--remote", metavar="HOST:PORT",
        help=f"frida-server address (env: {ENV_REMOTE})")
    if offset:
        group.add_argument(
            "--offset", metavar="HEX", type=parse_offset,
            help=f"RVA of the function to hook, hex with or without 0x "
                 f"(env: {ENV_OFFSET})")


@dataclass
class Settings:
    target: str
    remote_addr: str
    offset: "int | None"  # None when the driver doesn't use an offset


def _pick(cli_value, env_name, default, parse=None):
    """Return (value, source) following CLI > env > config.py."""
    if cli_value is not None:
        return cli_value, "CLI"
    raw = os.environ.get(env_name)
    if raw:  # an empty string counts as "not set"
        try:
            return (parse(raw) if parse else raw), f"env {env_name}"
        except argparse.ArgumentTypeError as e:
            sys.exit(f"[!] ${env_name}: {e}")
    return default, "config.py"


def resolve_settings(args, offset=True):
    """Combine parsed CLI args, environment variables and config.py defaults.

    Prints where each value came from - an exported FRIDA_OFFSET left over in
    your shell silently beating the value in config.py is exactly the sort of
    thing you don't want to discover after an hour of probing.
    """
    target, t_src = _pick(args.target, ENV_TARGET, config.TARGET)
    remote, r_src = _pick(args.remote, ENV_REMOTE, config.REMOTE_ADDR)
    print(f"[i] target = {target}  ({t_src})")
    print(f"[i] remote = {remote}  ({r_src})")

    off = None
    if offset:
        off, o_src = _pick(args.offset, ENV_OFFSET, config.FRIDA_OFFSET, parse_offset)
        print(f"[i] offset = {hex(off)}  ({o_src})")

    return Settings(target=target, remote_addr=remote, offset=off)


def load_agent_source(path, offset=None):
    """Read a bundled Frida agent's JS source from `path`.

    `path` should point at the *bundled* output under dist/ (e.g.
    "../dist/dump_hd_quality_list.js"), not the raw source under scripts/
    - the scripts/ files import shared helpers from scripts/_lib.js via ES
    module `import`, which only resolves after `npm run build` (see
    README.md's "Building the agents"). Loading a raw scripts/*.js path
    here directly will fail with an unresolved import.

    If `offset` is given, overwrite the agent's own `const FRIDA_OFFSET =
    0x...;` line with it, so you only have to set the offset once (via
    --offset, $FRIDA_OFFSET or config.py) instead of also editing the .js
    file. No-op (with a note) if the agent doesn't declare a FRIDA_OFFSET at
    all — e.g. list_il2cpp_exports.js doesn't need one.
    """
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()

    if offset is not None:
        source, n = re.subn(
            r"const FRIDA_OFFSET = 0x[0-9a-fA-F]+;",
            f"const FRIDA_OFFSET = {hex(offset)};",
            source,
            count=1,
        )
        if n == 0:
            print(f"[i] {path}: no FRIDA_OFFSET constant found — nothing to inject, "
                  "using the agent's own file contents as-is.")

    return source


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
