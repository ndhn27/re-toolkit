"""
Where this toolkit keeps what it learns, outside the repo: THE place the locations are decided.

    <data dir>/profiles/NAME.json            your hand-written target profiles (see profiles.py)
    <data dir>/builds/<target>/<build>.json  what verified runs learned about each build (buildcache.py)

<data dir> is the user's own data directory, the standard one for the operating system
(the `platformdirs` package decides, for an app called "re-toolkit"):

    Linux     ~/.local/share/re-toolkit        ($XDG_DATA_HOME/re-toolkit when that is set)
    macOS     ~/Library/Application Support/re-toolkit
    Windows   %LOCALAPPDATA%\\re-toolkit

Two environment variables move things, for CI, a shared machine or a USB stick:

    RE_DATA_DIR       the whole <data dir>
    RE_PROFILES_DIR   only profiles/ (older than the above and kept: it wins for profiles)

Nothing here is ever inside the repository - real names, offsets and layouts of a real target do not
belong in git (the repo's .gitignore only backs that up). `retk builds where` prints
what these resolve to on this machine.
"""
import os
from pathlib import Path

import platformdirs

from . import resources

APP_NAME = "re-toolkit"
ENV_DATA_DIR = "RE_DATA_DIR"
ENV_PROFILES_DIR = "RE_PROFILES_DIR"

# Where profiles lived before they moved out of the repo: the checkout's own profiles/. None when retk is
# installed - there is no repo, so there is no old place to look in.
_CHECKOUT = resources.checkout_root()
LEGACY_PROFILES_DIR = _CHECKOUT / "profiles" if _CHECKOUT is not None else None


def data_dir():
    """The user's data directory for this toolkit (not created here)."""
    override = os.environ.get(ENV_DATA_DIR)
    return Path(override).expanduser() if override else Path(platformdirs.user_data_dir(APP_NAME, appauthor=False))


def profiles_dir():
    """Where `--profile NAME` looks for NAME.json."""
    override = os.environ.get(ENV_PROFILES_DIR)
    return Path(override).expanduser() if override else data_dir() / "profiles"


def builds_dir():
    """Where the per-build records are kept."""
    return data_dir() / "builds"
