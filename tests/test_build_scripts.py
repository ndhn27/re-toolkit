"""
package.json lists every agent by hand, so an agent added to scripts/ but not to the build exists only in
the source tree: `npm run build` (and CI) would not bundle it, and retk dump would find no
dist/<agent>.js to load. This pins that every entry point has a build script that writes dist/<its name>, and
that `npm run build` runs them all.

Run from the repo root:

    pytest tests/test_build_scripts.py
"""
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))
ENTRY_POINTS = sorted(p.name for p in (REPO_ROOT / "scripts").glob("*.js") if not p.name.startswith("_"))


def build_scripts():
    """{agent file: script name} for every `frida-compile scripts/X.js -o dist/X.js` (watch variants left out)."""
    out = {}
    for name, command in PACKAGE["scripts"].items():
        m = re.fullmatch(r"frida-compile scripts/(\S+\.js) -o dist/(\S+\.js)", command)
        if m and name.startswith("build:"):
            assert m.group(1) == m.group(2), f"{name} writes dist/{m.group(2)} from scripts/{m.group(1)}"
            out[m.group(1)] = name
    return out


def test_every_agent_has_a_build_script_that_writes_dist_under_its_own_name():
    assert sorted(build_scripts()) == ENTRY_POINTS


def test_npm_run_build_runs_every_build_script():
    ran = re.findall(r"npm run (build:[\w-]+)", PACKAGE["scripts"]["build"])
    assert sorted(ran) == sorted(build_scripts().values())
