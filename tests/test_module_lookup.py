"""
Where the IL2CPP module's name comes from, and where it is looked up.

Two things are pinned here so they stay true as the code moves:

  * Python: retk profile's PLATFORM_MODULES is the only place a platform's module name
    (UnityFramework, libil2cpp.so, GameAssembly.dll) is typed in code, and resolve_module() is the
    one function that decides which module a run uses - --module, --platform, the profile's
    `module`, the profile's `platform`, in that order, and an error (never a guess) when none says.
  * JavaScript: scripts/_lib.js's fridaModules() is the only code that calls Frida's module APIs
    (Process.getModuleByName / enumerateModules / attachModuleObserver, Module.*), every agent
    reaches it through waitForModule(), and the platform names the agents' hints quote are the same
    ones Python has. A Frida whose module API differs then means editing one function.

No device and no Frida: this reads the source.

Run from the repo root:

    pytest tests/test_module_lookup.py
"""
import argparse
import ast
import json
import re
from pathlib import Path

import pytest

from retk import _common as common
from retk import profiles
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = sorted((REPO_ROOT / "scripts").glob("*.js"))
AGENTS = [p for p in SCRIPTS if not p.name.startswith("_")]
TOOLS = sorted((REPO_ROOT / "src" / "retk").glob("*.py"))
NAMES = sorted(profiles.PLATFORM_MODULES.values())

# What a JS source has besides code: comments and string literals (the guards below look at code).
JS_NOISE = re.compile(r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`", re.S)
JS_COMMENTS = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
FRIDA_MODULE_API = re.compile(
    r"\bProcess\s*\.\s*(?:getModuleByName|findModuleByName|enumerateModules|attachModuleObserver)\b"
    r"|\bModule\s*\.\s*\w+")


def js_code(path):
    """The source with comments and string literals blanked out (what is left is code)."""
    return JS_NOISE.sub('""', path.read_text(encoding="utf-8"))


def function_span(code, name):
    """(start, end) of `function name(...) { ... }` in `code`, by brace matching."""
    start = code.index(f"function {name}(")
    depth, i = 0, code.index("{", start)
    for j in range(i, len(code)):
        depth += {"{": 1, "}": -1}.get(code[j], 0)
        if depth == 0:
            return start, j + 1
    raise AssertionError(f"unbalanced braces in {name}")


# --- resolve_module(): the one place a module name is decided ---

def a_profile(tmp_path, **fields):
    raw = {"target": "com.example.t", **fields}
    path = tmp_path / "p.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return profiles.load(path)


def test_the_table_names_each_platform_once_and_labels_it():
    assert profiles.PLATFORM_MODULES == {"ios": "UnityFramework", "android": "libil2cpp.so",
                                         "windows": "GameAssembly.dll"}
    assert set(profiles.PLATFORM_LABELS) == set(profiles.PLATFORM_MODULES)
    assert len(set(profiles.PLATFORM_MODULES.values())) == len(profiles.PLATFORM_MODULES)


def test_resolution_order_is_cli_name_cli_platform_profile_name_profile_platform(tmp_path):
    both = a_profile(tmp_path, module="FromProfile", platform="windows")
    assert profiles.resolve_module(both, module="FromCli", platform="ios") == ("FromCli", "CLI")
    assert profiles.resolve_module(both, platform="ios") == ("UnityFramework", "CLI --platform ios")
    assert profiles.resolve_module(both) == ("FromProfile", "profile")
    only_platform = a_profile(tmp_path, platform="windows")
    assert profiles.resolve_module(only_platform) == ("GameAssembly.dll", "profile platform windows")
    # a name given on the command line still beats the platform the profile says
    assert profiles.resolve_module(only_platform, module="x") == ("x", "CLI")
    # and a platform given on the command line beats the profile's platform
    assert profiles.resolve_module(only_platform, platform="android") == ("libil2cpp.so", "CLI --platform android")


def test_nothing_naming_a_module_or_a_platform_is_an_error_not_a_default(tmp_path):
    for profile in (None, a_profile(tmp_path)):
        with pytest.raises(profiles.ProfileError, match="--module") as e:
            profiles.resolve_module(profile)
        assert "--platform" in str(e.value)
        with pytest.raises(profiles.ProfileError, match="--module"):
            profiles.agent_params(profile)


def test_the_no_module_message_lists_every_platform_from_the_table():
    for platform, module in profiles.PLATFORM_MODULES.items():
        assert f"{module} on {profiles.PLATFORM_LABELS[platform]}" in profiles.NO_MODULE_HELP
        assert platform in profiles.NO_MODULE_HELP


def test_an_unknown_platform_is_refused_wherever_it_comes_from(tmp_path):
    with pytest.raises(profiles.ProfileError, match="platform must be one of ios, android, windows"):
        profiles.resolve_module(None, platform="linux")
    with pytest.raises(profiles.ProfileError, match="platform must be one of"):
        a_profile(tmp_path, platform="linux")
    with pytest.raises(profiles.ProfileError, match="platform must be a non-empty string"):
        a_profile(tmp_path, platform="")
    with pytest.raises(profiles.ProfileError, match="platform must be one of"):
        a_profile(tmp_path, platform="iOS")         # exact keys: no quiet case folding


def test_agent_params_carries_the_platforms_module_to_the_agent(tmp_path):
    assert profiles.agent_params(None, platform="android") == {"module": "libil2cpp.so", "offsets": {}}
    p = a_profile(tmp_path, platform="windows", offsets={"a": "0x10"})
    assert profiles.agent_params(p) == {"module": "GameAssembly.dll", "offsets": {"a": 0x10}}
    assert profiles.agent_params(p, module="Other")["module"] == "Other"


def test_profiles_params_takes_platform_and_module_like_the_drivers(tmp_path, capsys):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"target": "com.example.t"}), encoding="utf-8")
    assert profiles.main(["params", str(path), "--platform", "android"]) in (None, 0)
    assert json.loads(capsys.readouterr().out)["module"] == "libil2cpp.so"
    profiles.main(["params", str(path), "--platform", "android", "--module", "Custom"])
    assert json.loads(capsys.readouterr().out)["module"] == "Custom"


# --- the command line: one definition of the flags, one place that says where the module came from ---

def parser():
    ap = argparse.ArgumentParser()
    common.add_override_args(ap)
    return ap


def settings(*argv):
    return common.resolve_settings(parser().parse_args(["--target", "com.example.t", *argv]))


def test_every_driver_parser_has_module_and_platform():
    ap = parser()
    assert ap.parse_args(["--platform", "windows"]).platform == "windows"
    assert ap.parse_args([]).module is None and ap.parse_args([]).platform is None
    with pytest.raises(SystemExit):
        ap.parse_args(["--platform", "linux"])


def test_resolve_settings_says_where_the_module_came_from(capsys):
    assert settings("--platform", "ios").params["module"] == "UnityFramework"
    assert "module = UnityFramework  (CLI --platform ios)" in capsys.readouterr().out
    assert settings("--module", "Custom", "--platform", "ios").params["module"] == "Custom"
    assert "module = Custom  (CLI)" in capsys.readouterr().out


def test_resolve_settings_without_a_module_or_platform_still_exits():
    with pytest.raises(SystemExit, match="--platform"):
        settings()


# --- the names live in one place ---

def docstring_nodes(tree):
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                out.add(id(first.value))
    return out


@pytest.mark.parametrize("path", TOOLS, ids=lambda p: p.name)
def test_no_tool_types_a_platforms_module_name_in_code(path):
    """Docstrings and comments may quote them; a string a program USES may not - it reads the table."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    skip = docstring_nodes(tree)
    if path.name == "profiles.py":              # the table itself
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "PLATFORM_MODULES" for t in node.targets):
                skip.update(id(n) for n in ast.walk(node.value))
    found = [(n.lineno, n.value) for n in ast.walk(tree)
             if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in skip
             and any(name in n.value for name in NAMES)]
    assert found == []


def test_the_table_is_still_where_the_guard_expects_it():
    tree = ast.parse((REPO_ROOT / "src" / "retk" / "profiles.py").read_text(encoding="utf-8"))
    assigns = [n for n in tree.body if isinstance(n, ast.Assign)
               and any(getattr(t, "id", "") == "PLATFORM_MODULES" for t in n.targets)]
    assert len(assigns) == 1 and {c.value for c in ast.walk(assigns[0].value) if isinstance(c, ast.Constant)
                                  and c.value in NAMES} == set(NAMES)


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_no_agent_types_a_platforms_module_name_in_code_except_the_hint_table(path):
    code = JS_COMMENTS.sub("", path.read_text(encoding="utf-8"))
    if path.name == "_lib.js":
        code, n = re.subn(r"const RUNTIME_MODULES = \{[^}]*\};", "", code)
        assert n == 1
    assert [name for name in NAMES if name in code] == []


def js_table(source, const):
    block = re.search(rf"const {const} = \{{([^}}]*)\}};", source).group(1)
    return dict(re.findall(r"(\w+):\s*\"([^\"]+)\"", block))


def test_the_agents_hint_table_equals_the_drivers():
    source = (REPO_ROOT / "scripts" / "_lib.js").read_text(encoding="utf-8")
    assert js_table(source, "RUNTIME_MODULES") == profiles.PLATFORM_MODULES
    assert js_table(source, "RUNTIME_LABELS") == profiles.PLATFORM_LABELS


# --- the lookup is one function ---

def test_only_fridaModules_calls_a_frida_module_api():
    lib = js_code(REPO_ROOT / "scripts" / "_lib.js")
    start, end = function_span(lib, "fridaModules")
    inside = set(re.findall(r"Process\s*\.\s*(\w+)", lib[start:end]))
    assert {"getModuleByName", "enumerateModules", "attachModuleObserver"} <= inside     # the guard is live
    for path in SCRIPTS:
        code = js_code(path)
        hits = [m for m in FRIDA_MODULE_API.finditer(code)
                if path.name != "_lib.js" or not start <= m.start() < end]
        assert [code[m.start():m.end()] for m in hits] == [], path.name


@pytest.mark.parametrize("path", AGENTS, ids=lambda p: p.name)
def test_every_agent_waits_for_its_module_through_waitForModule(path):
    code = js_code(path)
    assert re.search(r"\bwaitForModule\(\s*p\.moduleName\b", code)
    assert "moduleMatches" not in code and "fridaModules" not in code     # no side door around it


def test_waitForModule_asks_fridaModules_and_nothing_else():
    lib = js_code(REPO_ROOT / "scripts" / "_lib.js")
    start, end = function_span(lib, "waitForModule")
    body = lib[start:end]
    assert "fridaModules()" in body and not FRIDA_MODULE_API.search(body)
