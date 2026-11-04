"""
src/retk/resources.py: where the bundled agents and the example profile are found - in a checkout, inside an
installed package, or in $RETK_AGENTS_DIR - and what is said when one is missing.
"""
import os
import shutil
from pathlib import Path

import pytest

from retk import _common, resources

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def no_override(monkeypatch):
    monkeypatch.delenv(resources.ENV_AGENTS_DIR, raising=False)


@pytest.fixture
def installed(monkeypatch, tmp_path, no_override):
    """retk as a wheel has it: no checkout around the package, agents/ and data/ inside it."""
    package = tmp_path / "site-packages" / "retk"
    (package / "agents").mkdir(parents=True)
    (package / "data").mkdir()
    monkeypatch.setattr(resources, "PACKAGE_DIR", package)
    monkeypatch.setattr(resources, "PACKAGED_AGENTS_DIR", package / "agents")
    monkeypatch.setattr(resources, "PACKAGED_EXAMPLE_PROFILE", package / "data" / "profile.example.json")
    return package


# --- the checkout (what these tests run in) ---

def test_this_tree_is_a_checkout():
    assert resources.checkout_root() == REPO_ROOT


def test_in_a_checkout_the_agents_are_searched_in_dist(no_override):
    assert resources.agent_dirs() == [resources.PACKAGED_AGENTS_DIR, REPO_ROOT / "dist"]
    assert Path(resources.agent_path("dump_table_a.js")) in (REPO_ROOT / "dist" / "dump_table_a.js",
                                                              resources.PACKAGED_AGENTS_DIR / "dump_table_a.js")


def test_a_missing_bundle_gets_the_path_it_should_have_had_and_never_raises(no_override):
    path = Path(resources.agent_path("nothing_like_it.js"))
    assert path == REPO_ROOT / "dist" / "nothing_like_it.js" and not path.exists()


def test_the_env_override_comes_first_and_is_where_a_missing_one_is_expected(monkeypatch, tmp_path):
    monkeypatch.setenv(resources.ENV_AGENTS_DIR, str(tmp_path))
    assert resources.agent_dirs()[0] == tmp_path
    assert resources.agent_path("x.js") == str(tmp_path / "x.js")
    (tmp_path / "x.js").write_text("//")
    assert resources.agent_path("x.js") == str(tmp_path / "x.js")


def test_the_example_profile_is_the_repos_in_a_checkout():
    assert resources.example_profile_path() == REPO_ROOT / "profile.example.json"


def test_a_folder_that_is_only_called_src_is_not_a_checkout(monkeypatch, tmp_path):
    monkeypatch.setattr(resources, "PACKAGE_DIR", tmp_path / "src" / "retk")
    assert resources.checkout_root() is None        # no package.json / scripts/ beside it


# --- an installed package ---

def test_installed_the_agents_are_in_the_package(installed):
    (installed / "agents" / "dump_table_a.js").write_text("//")
    assert resources.checkout_root() is None
    assert resources.agent_path("dump_table_a.js") == str(installed / "agents" / "dump_table_a.js")


def test_installed_a_missing_agent_is_expected_in_the_package(installed):
    assert resources.agent_path("dump_table_a.js") == str(installed / "agents" / "dump_table_a.js")


def test_installed_the_example_profile_is_the_packaged_copy(installed):
    assert resources.example_profile_path() is None
    shutil.copyfile(REPO_ROOT / "profile.example.json", installed / "data" / "profile.example.json")
    assert resources.example_profile_path() == installed / "data" / "profile.example.json"


def test_the_hint_for_an_install_without_agents_says_how_to_get_them(installed):
    hint = resources.missing_agent_hint()
    assert "pip install ." in hint and "Node.js" in hint and resources.ENV_AGENTS_DIR in hint


def test_the_hint_in_a_checkout_is_npm_run_build(no_override):
    assert "npm run build" in resources.missing_agent_hint()


def test_the_hint_with_the_override_set_names_it(monkeypatch, tmp_path):
    monkeypatch.setenv(resources.ENV_AGENTS_DIR, str(tmp_path))
    assert str(tmp_path) in resources.missing_agent_hint()


def test_load_agent_source_says_where_it_looked_and_what_to_do(installed):
    with pytest.raises(FileNotFoundError) as e:
        _common.load_agent_source(resources.agent_path("dump_table_a.js"))
    assert "Agent not found" in str(e.value) and "dump_table_a.js" in str(e.value) and "pip install ." in str(e.value)


# --- --agent takes a path or a name ---

def test_an_existing_file_is_a_path_even_when_it_looks_like_a_name(monkeypatch, tmp_path, no_override):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "dump_table_b.js").write_text("// mine")
    assert resources.resolve_agent("dump_table_b.js") == "dump_table_b.js"


def test_a_bare_name_is_looked_up_with_or_without_js(installed, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (installed / "agents" / "dump_table_b.js").write_text("//")
    expected = str(installed / "agents" / "dump_table_b.js")
    assert resources.resolve_agent("dump_table_b.js") == expected
    assert resources.resolve_agent("dump_table_b") == expected


def test_a_path_or_an_unknown_name_is_returned_unchanged(installed, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert resources.resolve_agent("nope.js") == "nope.js"
    assert resources.resolve_agent(os.path.join("some", "dir", "dump_table_b.js")) == os.path.join("some", "dir", "dump_table_b.js")
    assert resources.resolve_agent("some/dir/dump_table_b.js") == "some/dir/dump_table_b.js"


# --- the commands that load an agent end cleanly when there is none ---

@pytest.mark.parametrize("command,module,agent,extra", [
    ("dump", "run_dump", "dump_table_a.js", ["--offset", "table_a=0x10"]),
    ("verify", "verify_offset", "verify_hook.js", ["--candidate", "0x10"]),
    ("exports", "list_exports", "list_il2cpp_exports.js", []),
])
def test_a_command_without_its_agent_exits_with_the_explanation_not_a_traceback(
        installed, monkeypatch, capsys, command, module, agent, extra):
    from importlib import import_module

    from retk import cli
    # The drivers name their default bundle once, when they are imported - which another test may have done
    # in a checkout. Point it where an installed retk with no agents would look.
    monkeypatch.setattr(import_module(f"retk.{module}"), "AGENT_PATH", resources.agent_path(agent))
    with pytest.raises(SystemExit) as stop:
        cli.main([command, "--profile", str(REPO_ROOT / "profile.example.json"), *extra])
    assert str(stop.value).startswith("[!] Agent not found") and "pip install ." in str(stop.value)
    assert "[i]" not in capsys.readouterr().out, "the missing agent is the answer; settings lines must not come first"
