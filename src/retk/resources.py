"""
Where the files that are not Python live: the bundled Frida agents and the example profile.

Two ways of running retk, and one place to look for each:

    installed (`pip install .`, a wheel)   inside the package: retk/agents/*.js and
                                           retk/data/profile.example.json. The wheel build runs
                                           `npm run build` and copies its dist/ output and the
                                           repo's profile.example.json in (setup.py).
    a source checkout (`pip install -e .`, or  where the repo keeps them: dist/ (what `npm run build`
    PYTHONPATH=src from the repo root)        writes) and profile.example.json at the repo root.

$RETK_AGENTS_DIR beats both for the agents: a folder of already-built bundles (a CI artifact, a
shared drive, a build somebody else made).

Nothing here raises when a file is absent: the functions answer with the path the file WOULD be at,
so a module can name a default at import time (and `--help` works on an install that has no agents).
The failure comes where the file is actually read - `_common.load_agent_source` - with
`missing_agent_hint()` telling the person what to do about it.
"""
import os
from pathlib import Path

ENV_AGENTS_DIR = "RETK_AGENTS_DIR"

PACKAGE_DIR = Path(__file__).resolve().parent
PACKAGED_AGENTS_DIR = PACKAGE_DIR / "agents"
PACKAGED_EXAMPLE_PROFILE = PACKAGE_DIR / "data" / "profile.example.json"

EXAMPLE_PROFILE_NAME = "profile.example.json"


def checkout_root():
    """The repo this package is running from (src/retk/ inside a clone), or None when it is installed.

    Three things have to agree, so a package that merely sits in a folder called `src` is not taken for a
    checkout: the repo's package.json (what `npm run build` reads), its scripts/ (the agent sources) and
    this very package under src/."""
    root = PACKAGE_DIR.parent.parent
    if (root / "package.json").is_file() and (root / "scripts").is_dir() and (root / "src" / "retk") == PACKAGE_DIR:
        return root
    return None


def agent_dirs():
    """Every folder the agent bundles are looked for in, best first."""
    dirs = []
    override = os.environ.get(ENV_AGENTS_DIR)
    if override:
        dirs.append(Path(override).expanduser())
    dirs.append(PACKAGED_AGENTS_DIR)
    root = checkout_root()
    if root is not None:
        dirs.append(root / "dist")
    return dirs


def agent_path(name):
    """The bundle `name` (e.g. "dump_table_a.js"): the first folder in agent_dirs() that has it.

    When none has it, the path in the folder a person would expect to find it in - the override if
    one is set, else dist/ of the checkout, else the package's own agents/ - so an error message
    can say where it looked. Never raises."""
    dirs = agent_dirs()
    for d in dirs:
        if (d / name).is_file():
            return str(d / name)
    expected = dirs[0] if os.environ.get(ENV_AGENTS_DIR) else (dirs[-1] if checkout_root() else PACKAGED_AGENTS_DIR)
    return str(expected / name)


def resolve_agent(value):
    """What `--agent VALUE` means: a path, or just the name of a bundle ("dump_table_b.js", or without the .js).

    An existing file wins as it always did (relative to the current directory, like any CLI path); a bare
    name that is no file there is looked up in agent_dirs() - which is how an installed retk, with no
    repo dist/ to point at, picks dump_table_b.js. Anything else is returned unchanged for
    load_agent_source to report."""
    value = str(value)
    if Path(value).is_file() or os.sep in value or "/" in value:
        return value
    for name in (value, value + ".js"):
        found = agent_path(name)
        if Path(found).is_file():
            return found
    return value


def missing_agent_hint():
    """What to do when a bundle is not where it should be, for the way this copy is running."""
    if os.environ.get(ENV_AGENTS_DIR):
        return f"${ENV_AGENTS_DIR} is set to {os.environ[ENV_AGENTS_DIR]!r}: build the agents there, or unset it."
    if checkout_root() is not None:
        return ("Run `npm run build` from the repo root to bundle scripts/ into dist/ "
                "(see README 'Building the agents').")
    return ("This install carries no agent bundles (it was built without Node.js, or with RETK_SKIP_AGENTS=1). "
            "Reinstall from a checkout with Node.js 20+ and npm on PATH - `pip install .` builds them - "
            f"or point ${ENV_AGENTS_DIR} at a folder of built bundles.")


def example_profile_path():
    """profile.example.json: next to the package when installed, at the repo root in a checkout. None when
    neither is there."""
    root = checkout_root()
    for path in ((root / EXAMPLE_PROFILE_NAME) if root else None, PACKAGED_EXAMPLE_PROFILE):
        if path is not None and path.is_file():
            return path
    return None
