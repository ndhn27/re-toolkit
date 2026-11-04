"""
The `retk` command (src/retk/cli.py): the dispatcher in front of the tools.

  * `retk --help` lists every command; a typo, no command and `--version` behave like a command line program;
  * `retk NAME ARGS...` imports the tool and calls main(ARGS, prog="retk NAME"), returning its exit status;
  * every command really exists (a module with a main(argv, prog)), and `retk NAME --help` works for each;
  * `retk --help` does not load frida or capstone (a fresh interpreter proves it);
  * pyproject.toml declares the `retk` entry point, and the README documents every command.
"""
import inspect
import re
import subprocess
import sys
from importlib import import_module
from pathlib import Path

import pytest

from retk import __version__, cli

REPO_ROOT = Path(__file__).resolve().parent.parent
NAMES = [c.name for c in cli.COMMANDS]


def run(argv, capsys):
    """(exit status, stdout, stderr) of `retk *argv`, whether it returns or exits."""
    try:
        status = cli.main(argv)
    except SystemExit as e:
        status = e.code
    out = capsys.readouterr()
    return status, out.out, out.err


# --- the top level ---

def test_help_lists_every_command(capsys):
    status, out, _ = run(["--help"], capsys)
    assert status == 0 and out.startswith("usage: retk ")
    for command in cli.COMMANDS:
        assert re.search(rf"^\s+{command.name}\s", out, re.M), command.name


def test_no_command_is_a_usage_error_that_names_the_commands(capsys):
    status, out, err = run([], capsys)
    assert status == 2 and "usage: retk" in err and "COMMAND" in err and out == ""


def test_a_typo_is_refused_with_the_choices(capsys):
    status, _, err = run(["dumpp"], capsys)
    assert status == 2 and "invalid choice" in err
    # Every command is offered. How argparse writes that list is not retk's: it quotes each choice
    # ('dump') in most releases, but some patch releases printed it bare (dump). Don't pin either.
    offered = err.split("choose from", 1)[-1]
    for name in NAMES:
        assert re.search(rf"\b{re.escape(name)}\b", offered), (name, err)


def test_version(capsys):
    status, out, _ = run(["--version"], capsys)
    assert status == 0 and out.strip() == f"retk {__version__}"


def test_the_version_is_a_pep440_release():
    assert re.fullmatch(r"\d+\.\d+\.\d+(\.dev\d+|rc\d+|a\d+|b\d+)?", __version__), __version__


# --- dispatch ---

@pytest.fixture
def fake_tool(monkeypatch):
    """Replace importlib.import_module inside cli with one that hands out a recording tool."""
    calls = []

    class Tool:
        status = None

        @staticmethod
        def main(argv, prog=None):
            calls.append((list(argv), prog))
            return Tool.status

    asked = []

    def fake_import(name):
        asked.append(name)
        return Tool

    monkeypatch.setattr(cli.importlib, "import_module", fake_import)
    return Tool, calls, asked


@pytest.mark.parametrize("command", cli.COMMANDS, ids=NAMES)
def test_a_command_forwards_the_rest_of_the_line_with_its_own_prog(fake_tool, command):
    _tool, calls, asked = fake_tool
    assert cli.main([command.name, "--profile", "x", "--out", "y.json", "-h"]) == 0
    assert asked == [f"retk.{command.module}"]
    assert calls == [(["--profile", "x", "--out", "y.json", "-h"], f"retk {command.name}")]


def test_the_tools_exit_status_is_the_commands(fake_tool):
    tool, _, _ = fake_tool
    for status in (0, 1, 3, 4, 5):
        tool.status = status
        assert cli.main(["dump"]) == status


def test_a_tool_that_exits_exits_the_same_way(monkeypatch):
    class Tool:
        @staticmethod
        def main(argv, prog=None):
            raise SystemExit("[!] no target")
    monkeypatch.setattr(cli.importlib, "import_module", lambda name: Tool)
    with pytest.raises(SystemExit) as stop:
        cli.main(["dump"])
    assert stop.value.code == "[!] no target"


def test_a_missing_third_party_package_is_explained_not_a_traceback(monkeypatch, capsys):
    def fail(name):
        raise ModuleNotFoundError("No module named 'frida'", name="frida")
    monkeypatch.setattr(cli.importlib, "import_module", fail)
    status, _, err = run(["dump"], capsys)
    assert status == 1 and "'frida'" in err and "retk dump" in err and "requirements.txt" in err


def test_another_import_error_is_not_swallowed(monkeypatch):
    def fail(name):
        raise ModuleNotFoundError("No module named 'retk.nonsense'", name="retk.nonsense")
    monkeypatch.setattr(cli.importlib, "import_module", fail)
    with pytest.raises(ModuleNotFoundError):
        cli.main(["dump"])


# --- every command is real ---

@pytest.mark.parametrize("command", cli.COMMANDS, ids=NAMES)
def test_every_command_has_a_tool_with_main_argv_prog(command):
    module = import_module(f"retk.{command.module}")
    assert (REPO_ROOT / "src" / "retk" / f"{command.module}.py").is_file()
    assert list(inspect.signature(module.main).parameters) == ["argv", "prog"], command.name


@pytest.mark.parametrize("command", cli.COMMANDS, ids=NAMES)
def test_every_command_answers_help_under_its_own_name(command, capsys):
    status, out, err = run([command.name, "--help"], capsys)
    assert status == 0 and f"retk {command.name}" in out, (out, err)


@pytest.mark.parametrize("group,subs", [("profile", ["layout", "params", "init"]),
                                        ("builds", ["where", "key", "list"])])
def test_the_grouped_commands_list_their_subcommands(group, subs, capsys):
    status, out, _ = run([group, "--help"], capsys)
    assert status == 0 and all(s in out for s in subs) and f"retk {group}" in out


def test_the_tool_without_a_repo_is_not_a_command():
    assert "check_identifiers" not in {c.module for c in cli.COMMANDS}
    assert (REPO_ROOT / "tools" / "check_identifiers.py").is_file()


def test_pyproject_declares_the_entry_point_and_it_resolves():
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    section = re.search(r"^\[project\.scripts\]\n((?:[^\[\n].*\n|\n|#.*\n)*)", text, re.M).group(1)
    assert re.search(r'^retk\s*=\s*"retk\.cli:main"\s*$', section, re.M)
    assert callable(cli.main)


def test_the_readme_documents_every_command():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    for name in NAMES:
        assert re.search(rf"^\| `retk {name}[` \\]", readme, re.M), f"README.md's command table has no `retk {name}`"


# --- a fresh interpreter ---

def test_help_does_not_load_frida_or_capstone():
    code = ("import sys\nfrom retk.cli import main\n"
            "try:\n    main(['--help'])\nexcept SystemExit:\n    pass\n"
            "bad = [m for m in ('frida', 'capstone') if m in sys.modules]\n"
            "assert not bad, bad\n")
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          env={**__import__("os").environ, "PYTHONPATH": str(REPO_ROOT / "src")})
    assert proc.returncode == 0, proc.stderr


def test_python_dash_m_retk_is_the_same_program():
    proc = subprocess.run([sys.executable, "-m", "retk", "--version"], capture_output=True, text=True,
                          env={**__import__("os").environ, "PYTHONPATH": str(REPO_ROOT / "src")})
    assert proc.returncode == 0 and proc.stdout.strip() == f"retk {__version__}", proc.stderr
