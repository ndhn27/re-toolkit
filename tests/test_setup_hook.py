"""
setup.py's build hook: what goes into the wheel besides Python - the bundled agents and the example profile.

The hook's functions are exercised against a small fake repo in tmp_path (no npm run, no wheel build; the CI
"package" job builds a real wheel and installs it into a clean environment). What is pinned here:

  * which bundles the build expects (one per entry point in scripts/) and when dist/ counts as current;
  * no npm -> the build fails saying what to do, and RETK_SKIP_AGENTS=1 is the way out;
  * a build that leaves a bundle out fails instead of shipping a wheel with a hole;
  * pyproject.toml reads the version and the dependencies from the one place each lives in.
"""
import importlib.util
import os
import re
import time
from pathlib import Path

import pytest
import setuptools
from setuptools.errors import SetupError

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def hook():
    """setup.py imported without running setup()."""
    real = setuptools.setup
    setuptools.setup = lambda **kw: kw
    try:
        spec = importlib.util.spec_from_file_location("retk_setup", REPO_ROOT / "setup.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        setuptools.setup = real
    return module


@pytest.fixture
def fake_repo(hook, monkeypatch, tmp_path):
    (tmp_path / "scripts").mkdir()
    for name in ("dump_table_a.js", "verify_hook.js", "_lib.js"):
        (tmp_path / "scripts" / name).write_text("// source")
    (tmp_path / "package.json").write_text("{}")
    monkeypatch.setattr(hook, "ROOT", tmp_path)
    monkeypatch.delenv(hook.ENV_SKIP_AGENTS, raising=False)
    return tmp_path


def make_dist(root, names=("dump_table_a.js", "verify_hook.js"), age=0):
    (root / "dist").mkdir(exist_ok=True)
    for name in names:
        path = root / "dist" / name
        path.write_text("// bundle")
        stamp = time.time() + age
        os.utime(path, (stamp, stamp))


def test_the_expected_bundles_are_the_entry_points_not_the_helpers(hook, fake_repo):
    assert hook.agent_names() == ["dump_table_a.js", "verify_hook.js"]


def test_the_real_repos_expected_bundles_are_the_ones_package_json_builds(hook):
    import json
    scripts = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))["scripts"]
    built = set(re.findall(r"-o dist/(\S+\.js)", " ".join(v for k, v in scripts.items() if k.startswith("build:"))))
    assert set(hook.agent_names()) == built


def test_no_dist_is_not_current(hook, fake_repo):
    assert hook.bundles_are_current() is False


def test_a_complete_dist_newer_than_the_sources_is_current(hook, fake_repo):
    make_dist(fake_repo, age=+100)
    assert hook.bundles_are_current() is True


def test_a_source_edited_after_the_build_makes_dist_stale(hook, fake_repo):
    make_dist(fake_repo, age=-100)
    assert hook.bundles_are_current() is False


def test_a_dist_with_a_bundle_missing_is_not_current(hook, fake_repo):
    make_dist(fake_repo, names=("dump_table_a.js",), age=+100)
    assert hook.bundles_are_current() is False


def test_a_current_dist_is_used_without_npm(hook, fake_repo, monkeypatch):
    make_dist(fake_repo, age=+100)
    monkeypatch.setattr(hook.shutil, "which", lambda _name: pytest.fail("npm must not be looked for"))
    assert hook.build_agents() == fake_repo / "dist"


def test_without_npm_the_build_fails_and_names_the_way_out(hook, fake_repo, monkeypatch):
    monkeypatch.setattr(hook.shutil, "which", lambda _name: None)
    with pytest.raises(SetupError) as e:
        hook.build_agents()
    assert "npm was not found" in str(e.value) and hook.ENV_SKIP_AGENTS in str(e.value)


def test_a_stale_dist_is_rebuilt_with_npm_ci_when_node_modules_is_missing(hook, fake_repo, monkeypatch):
    make_dist(fake_repo, age=-100)
    ran = []

    def fake_npm(npm, *args):
        ran.append(args)
        if args == ("run", "build"):
            make_dist(fake_repo, age=+100)

    monkeypatch.setattr(hook.shutil, "which", lambda _name: "/usr/bin/npm")
    monkeypatch.setattr(hook, "run_npm", fake_npm)
    assert hook.build_agents() == fake_repo / "dist"
    assert ran == [("ci",), ("run", "build")]


def test_node_modules_present_skips_npm_ci(hook, fake_repo, monkeypatch):
    (fake_repo / "node_modules" / "frida-compile").mkdir(parents=True)
    ran = []
    monkeypatch.setattr(hook.shutil, "which", lambda _name: "/usr/bin/npm")
    monkeypatch.setattr(hook, "run_npm", lambda npm, *args: (ran.append(args), make_dist(fake_repo, age=+100)))
    hook.build_agents()
    assert ran == [("run", "build")]


def test_a_build_that_leaves_a_bundle_out_fails(hook, fake_repo, monkeypatch):
    monkeypatch.setattr(hook.shutil, "which", lambda _name: "/usr/bin/npm")
    (fake_repo / "node_modules" / "frida-compile").mkdir(parents=True)
    monkeypatch.setattr(hook, "run_npm", lambda npm, *args: make_dist(fake_repo, names=("dump_table_a.js",), age=+100))
    with pytest.raises(SetupError, match="verify_hook.js"):
        hook.build_agents()


def test_a_failing_npm_is_reported_with_the_way_out(hook, fake_repo, monkeypatch):
    monkeypatch.setattr(hook.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(
        hook.subprocess.CalledProcessError(1, "npm")))
    with pytest.raises(SetupError, match=hook.ENV_SKIP_AGENTS):
        hook.run_npm("npm", "ci")


# --- pyproject.toml: one place for the version, one for the dependencies ---

def pyproject():
    return (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_the_version_comes_from_the_package(hook):
    assert re.search(r'^version\s*=\s*\{attr\s*=\s*"retk\.__version__"\}', pyproject(), re.M)
    assert re.search(r'^dynamic\s*=\s*\[[^\]]*"version"', pyproject(), re.M)


def test_the_dependencies_come_from_requirements_txt():
    assert re.search(r'^dependencies\s*=\s*\{file\s*=\s*\["requirements\.txt"\]\}', pyproject(), re.M)
    assert re.search(r'^dynamic\s*=\s*\[[^\]]*"dependencies"', pyproject(), re.M)
    assert not re.search(r"^dependencies\s*=\s*\[", pyproject(), re.M), "a second copy of the pins would drift"


def test_the_sdist_carries_what_the_wheel_build_reads():
    manifest = (REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    for needed in ("requirements.txt", "profile.example.json", "package.json", "package-lock.json", "scripts"):
        assert needed in manifest, needed


def test_the_built_things_stay_out_of_git():
    lines = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for ignored in ("dist/", "build/", "*.egg-info/", "wheelhouse/"):
        assert ignored in lines, ignored


# --- build_py.run: what lands in build/lib ---

def test_agents_left_in_build_lib_by_an_earlier_build_do_not_ride_along(hook, fake_repo, monkeypatch, tmp_path):
    """build/lib survives between builds: a RETK_SKIP_AGENTS=1 wheel must not carry the last build's agents."""
    from setuptools import Distribution
    (fake_repo / "profile.example.json").write_text("{}")
    build_lib = tmp_path / "build_lib"
    (build_lib / "retk" / "agents").mkdir(parents=True)
    (build_lib / "retk" / "agents" / "dump_table_a.js").write_text("// stale")
    monkeypatch.setenv(hook.ENV_SKIP_AGENTS, "1")

    command = hook.build_py(Distribution({"packages": []}))
    command.build_lib = str(build_lib)
    command.editable_mode = False
    monkeypatch.setattr(hook._build_py, "run", lambda self: None)         # the Python modules are not the point here
    command.run()

    assert not (build_lib / "retk" / "agents").exists()
    assert (build_lib / "retk" / "data" / "profile.example.json").is_file()


def test_the_agents_are_copied_from_dist_into_the_package(hook, fake_repo, monkeypatch, tmp_path):
    from setuptools import Distribution
    (fake_repo / "profile.example.json").write_text("{}")
    make_dist(fake_repo, age=+100)
    build_lib = tmp_path / "build_lib"
    command = hook.build_py(Distribution({"packages": []}))
    command.build_lib = str(build_lib)
    command.editable_mode = False
    monkeypatch.setattr(hook._build_py, "run", lambda self: None)
    command.run()
    assert sorted(p.name for p in (build_lib / "retk" / "agents").iterdir()) == ["dump_table_a.js", "verify_hook.js"]


def test_an_editable_install_copies_nothing(hook, fake_repo, monkeypatch, tmp_path):
    from setuptools import Distribution
    command = hook.build_py(Distribution({"packages": []}))
    command.build_lib = str(tmp_path / "build_lib")
    command.editable_mode = True
    monkeypatch.setattr(hook._build_py, "run", lambda self: None)
    monkeypatch.setattr(hook, "build_agents", lambda: pytest.fail("an editable install must not build agents"))
    command.run()
    assert not (tmp_path / "build_lib").exists()


# --- RETK_SKIP_AGENTS is a switch, not "is it set" ---

@pytest.mark.parametrize("value,on", [("1", True), ("true", True), ("YES", True), ("on", True), ("anything", True),
                                      ("0", False), ("false", False), ("False", False), ("no", False),
                                      ("off", False), ("", False), ("  ", False)])
def test_env_flag_reads_zero_and_false_as_off(hook, monkeypatch, value, on):
    monkeypatch.setenv("RETK_TEST_FLAG", value)
    assert hook.env_flag("RETK_TEST_FLAG") is on


def test_env_flag_unset_is_off(hook, monkeypatch):
    monkeypatch.delenv("RETK_TEST_FLAG", raising=False)
    assert hook.env_flag("RETK_TEST_FLAG") is False


@pytest.mark.parametrize("value", ["0", "false", "no", ""])
def test_skip_agents_set_to_zero_still_ships_the_agents(hook, fake_repo, monkeypatch, tmp_path, value):
    from setuptools import Distribution
    (fake_repo / "profile.example.json").write_text("{}")
    make_dist(fake_repo, age=+100)
    monkeypatch.setenv(hook.ENV_SKIP_AGENTS, value)
    build_lib = tmp_path / "build_lib"
    command = hook.build_py(Distribution({"packages": []}))
    command.build_lib = str(build_lib)
    command.editable_mode = False
    monkeypatch.setattr(hook._build_py, "run", lambda self: None)
    command.run()
    assert (build_lib / "retk" / "agents" / "dump_table_a.js").is_file()
