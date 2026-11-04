"""
Everything about the package is in pyproject.toml except this: the wheel has to carry two things that are
not Python and not in the source tree.

  retk/agents/*.js              the Frida agents. `npm run build` (frida-compile) bundles scripts/ into dist/;
                                a wheel built from a clone runs it, then copies the bundles in. Without them an
                                installed `retk dump` would have nothing to load.
  retk/data/profile.example.json  the template `retk profile init` copies (the repo keeps it at its root).

What the build does about the agents:
    dist/ is complete and newer than scripts/   used as it is (you just ran `npm run build`)
    otherwise, npm on PATH                      `npm ci` if node_modules/ is missing, then `npm run build`
    no npm, or the build fails                  the install FAILS, saying why - an install that quietly has no
                                                agents is found out an hour later, on a device
    RETK_SKIP_AGENTS=1                          no agents, no Node needed: `retk relocate`, `diff`, `profile` and
                                                `builds` do not use them (`retk dump` says so when asked to)

An editable install (`pip install -e .`) copies nothing: the checkout's dist/ is found where it is
(retk/resources.py), so `npm run build` after an edit to scripts/ is all it takes.

Build into a folder of your own (`python -m build --outdir wheelhouse`): the default, dist/, is where the
bundles are.
"""
import os
import shutil
import subprocess
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py
from setuptools.errors import SetupError

ROOT = Path(__file__).resolve().parent
ENV_SKIP_AGENTS = "RETK_SKIP_AGENTS"


def env_flag(name):
    """A switch in the environment: unset, empty, 0, false, no and off are OFF; anything else is on. (A bare
    `os.environ.get(name)` would read RETK_SKIP_AGENTS=0 as 'skip', and ship a wheel without agents to
    whoever meant the opposite.)"""
    return os.environ.get(name, "").strip().lower() not in ("", "0", "false", "no", "off")


def agent_names():
    """The bundles `npm run build` writes: one per entry point in scripts/ (_*.js are shared helpers)."""
    return sorted(p.name for p in (ROOT / "scripts").glob("*.js") if not p.name.startswith("_"))


def bundles_are_current():
    dist = ROOT / "dist"
    bundles = [dist / n for n in agent_names()]
    if not bundles or not all(b.is_file() for b in bundles):
        return False
    sources = [*(ROOT / "scripts").glob("*.js"), ROOT / "package.json", ROOT / "package-lock.json"]
    return min(b.stat().st_mtime for b in bundles) >= max(s.stat().st_mtime for s in sources if s.exists())


def run_npm(npm, *args):
    print(f"retk build: npm {' '.join(args)}")
    try:
        subprocess.run([npm, *args], cwd=ROOT, check=True)
    except (subprocess.CalledProcessError, OSError) as e:
        raise SetupError(f"`npm {' '.join(args)}` failed ({e}). The agents could not be built; fix that, or "
                         f"install without them: {ENV_SKIP_AGENTS}=1 pip install .") from e


def build_agents():
    """Make dist/ hold every bundle; returns the folder."""
    if not bundles_are_current():
        npm = shutil.which("npm")
        if npm is None:
            raise SetupError("npm was not found on PATH: the Frida agents are bundled with Node.js (20 or newer, "
                             f"see docs/INSTALL.md, 'Requirements'). Install Node, or install without the agents: "
                             f"{ENV_SKIP_AGENTS}=1 pip install .")
        if not (ROOT / "node_modules" / "frida-compile").is_dir():
            run_npm(npm, "ci")
        run_npm(npm, "run", "build")
    missing = [n for n in agent_names() if not (ROOT / "dist" / n).is_file()]
    if missing:
        raise SetupError(f"`npm run build` left no dist/{', dist/'.join(missing)}: package.json must build "
                         "every scripts/*.js entry point (tests/test_build_scripts.py checks it)")
    return ROOT / "dist"


class build_py(_build_py):
    def run(self):
        super().run()
        if self.editable_mode:                  # a checkout is found in place, nothing to copy
            return
        package = Path(self.build_lib) / "retk"
        # build/lib survives between builds (pip builds in the tree): what an earlier build copied in must not
        # ride along into this wheel - least of all agents, when this one is meant to have none.
        shutil.rmtree(package / "agents", ignore_errors=True)
        shutil.rmtree(package / "data", ignore_errors=True)
        example = ROOT / "profile.example.json"
        if example.is_file():
            (package / "data").mkdir(parents=True, exist_ok=True)
            shutil.copyfile(example, package / "data" / example.name)
        if env_flag(ENV_SKIP_AGENTS):
            print(f"retk build: {ENV_SKIP_AGENTS} is set - building without the agents")
            return
        dist = build_agents()
        (package / "agents").mkdir(parents=True, exist_ok=True)
        for name in agent_names():
            shutil.copyfile(dist / name, package / "agents" / name)


setup(cmdclass={"build_py": build_py})
