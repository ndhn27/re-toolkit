"""
The release number is written in one place, and everything else must agree with it.

`__version__` in src/retk/__init__.py is the source (pyproject.toml reads it). The newest numbered
section of CHANGELOG.md and its compare link at the bottom must name the same release, so a source
tree - or a zip of one - that carries an older number than its changelog (or the reverse) fails here
instead of reaching someone. Nothing else in the tree may claim to be a different current version:
package.json is `private` and carries no version, which is checked as well, so a stray one cannot
start disagreeing.

Run from the repo root:

    pytest tests/test_release_consistency.py
"""
import json
import re
from pathlib import Path

from retk import __version__

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def _newest_release():
    m = re.search(r"^## \[(\d+\.\d+\.\d+)\]", CHANGELOG, re.MULTILINE)
    assert m, "CHANGELOG.md has no '## [x.y.z]' section"
    return m.group(1)


def test_the_package_version_is_a_plain_release_number():
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__), f"{__version__!r} is not MAJOR.MINOR.PATCH"


def test_the_changelog_newest_section_is_the_package_version():
    assert _newest_release() == __version__, (
        f"__version__ is {__version__} but CHANGELOG.md's newest section is {_newest_release()}: "
        "a release bumps both (see CHANGELOG.md's intro)")


def test_the_changelog_links_the_package_version_to_its_tag():
    assert re.search(rf"^\[{re.escape(__version__)}\]: \S+/v{re.escape(__version__)}$", CHANGELOG, re.MULTILINE) \
        or re.search(rf"^\[{re.escape(__version__)}\]: \S+\.\.\.v{re.escape(__version__)}$", CHANGELOG, re.MULTILINE), (
        f"CHANGELOG.md has no link line for [{__version__}] pointing at the v{__version__} tag")


def test_the_changelog_lists_releases_newest_first():
    found = [tuple(int(n) for n in v.split("."))
             for v in re.findall(r"^## \[(\d+\.\d+\.\d+)\]", CHANGELOG, re.MULTILINE)]
    assert found == sorted(found, reverse=True)


def test_package_json_carries_no_version_of_its_own():
    assert "version" not in json.loads((ROOT / "package.json").read_text(encoding="utf-8"))


def test_security_policy_supports_the_current_minor_release():
    major, minor, _patch = __version__.split(".")
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert re.search(rf"^\| {major}\.{minor}\.x \| ", policy, re.MULTILINE), (
        f"SECURITY.md's supported-versions table has no '{major}.{minor}.x' row")
