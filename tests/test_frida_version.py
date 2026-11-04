"""
The Frida version this toolkit is built for (17), and what keeps it there.

  * requirements.txt pins `frida` and `frida-tools` EXACTLY. The `frida-server` on the device has to
    be the same major (and should be the same release) as the Python client, so a range that lets pip
    pick "whatever is newest today" is a way to find out on the phone.
  * The Frida the tests run under is that pin (its major always; the exact release when $CI is set,
    which is what installs from requirements.txt), and the Frida inside `frida-compile` - the node
    package whose bundles the drivers load - is the same major.
  * The agents call none of the APIs Frida 17 removed: static `Module.*` lookups (use
    `Process.getModuleByName(...)` and the Module's own methods - in scripts/_lib.js's
    fridaModules(), see test_module_lookup.py), `Memory.read*` / `Memory.write*` (use
    `NativePointer.read*` / `write*`), the `enumerate*Sync` forms, and the Java / ObjC / Swift
    bridges, which 17 no longer bundles into the runtime (an agent that wanted one would have to
    import it and be bundled with it).

The real-Frida behaviour - the hooks firing and returning the right values - is
tests/test_frida_real.py; this file only pins what can be read from the tree.

Run from the repo root:

    pytest tests/test_frida_version.py
"""
import json
import os
import re
from pathlib import Path

import pytest

from test_module_lookup import SCRIPTS, js_code

try:
    import frida
except ImportError:  # pragma: no cover - depends on the machine
    frida = None

REPO_ROOT = Path(__file__).resolve().parent.parent
FRIDA_MAJOR = 17


def pins():
    """{package: version} for every `name==version` line of requirements.txt."""
    out = {}
    for line in (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.fullmatch(r"([A-Za-z0-9_.-]+)\s*==\s*(\d+(?:\.\d+)*)", line)
        if m:
            out[m.group(1).lower()] = m.group(2)
    return out


def major(version):
    return int(version.split(".")[0])


# --- the pin ---

def test_frida_and_frida_tools_are_pinned_exactly_to_the_17_line():
    found = pins()
    assert set(found) >= {"frida", "frida-tools"}, "requirements.txt must pin `frida==X` and `frida-tools==Y`"
    assert major(found["frida"]) == FRIDA_MAJOR


def test_nothing_in_requirements_allows_another_frida():
    text = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")
    lines = [line.split("#", 1)[0].strip() for line in text.splitlines()]
    frida_lines = [line for line in lines if re.match(r"frida(-tools)?\b", line)]
    assert len(frida_lines) == 2, frida_lines
    assert all("==" in line and not re.search(r"[<>~!]", line) for line in frida_lines), frida_lines


def test_the_dev_requirements_do_not_override_the_pin():
    dev = (REPO_ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert "-r requirements.txt" in dev
    assert not re.search(r"^\s*frida", dev, re.M)


def test_the_ci_workflow_installs_the_pin_and_nothing_else_for_frida():
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "matrix.frida" not in ci
    assert re.search(r"pip install -r requirements-dev\.txt\s*$", ci, re.M)


# --- the Frida that is actually there ---

def test_the_installed_frida_is_the_pinned_one():
    if frida is None:
        pytest.skip("frida is not installed")
    pinned = pins()["frida"]
    assert major(frida.__version__) == major(pinned), (
        f"frida {frida.__version__} is installed, requirements.txt pins {pinned}: the client and the "
        f"frida-server on the device must share a major version")
    if os.environ.get("CI"):         # CI installs from requirements.txt: exactly that release
        assert frida.__version__ == pinned


def test_the_installed_frida_tools_admit_the_pinned_frida():
    metadata = pytest.importorskip("importlib.metadata")
    try:
        required = metadata.requires("frida-tools") or []
    except metadata.PackageNotFoundError:
        pytest.skip("frida-tools is not installed")
    packaging = pytest.importorskip("packaging.requirements")
    spec = next((packaging.Requirement(r).specifier for r in required if re.match(r"frida\b(?!-)", r)), None)
    assert spec is not None, "frida-tools declares no frida requirement?"
    assert pins()["frida"] in spec, f"frida-tools wants frida{spec}, requirements.txt pins frida=={pins()['frida']}"


def test_frida_compile_bundles_with_the_same_frida_major():
    lock = json.loads((REPO_ROOT / "package-lock.json").read_text(encoding="utf-8"))["packages"]
    assert major(lock["node_modules/frida"]["version"]) == FRIDA_MAJOR
    assert lock["node_modules/frida-compile"]["dependencies"]["frida"].lstrip("^~").startswith(f"{FRIDA_MAJOR}.")


# --- nothing Frida 17 removed ---

REMOVED_IN_17 = {
    "a static Module lookup": r"\bModule\s*\.\s*(?:find|get|enumerate|ensure)\w*",
    "Memory.read*": r"\bMemory\s*\.\s*read\w+",
    "Memory.write*": r"\bMemory\s*\.\s*write\w+",
    "an enumerate*Sync form": r"\.\s*enumerate\w*Sync\b",
    "a Java / ObjC / Swift bridge": r"(?<![\w.])(?:Java|ObjC|Swift)\s*\.",
}


@pytest.mark.parametrize("what, source", [
    ("a static Module lookup", 'Module.findExportByName(null, "open")'),
    ("a static Module lookup", "Module.getBaseAddress(name)"),
    ("Memory.read*", "Memory.readU32(p)"),
    ("Memory.write*", "Memory.writeByteArray(p, bytes)"),
    ("an enumerate*Sync form", "Process.enumerateModulesSync()"),
    ("a Java / ObjC / Swift bridge", "Java.perform(() => {})"),
    ("a Java / ObjC / Swift bridge", "if (ObjC.available) {}"),
])
def test_the_guard_below_really_catches_what_it_is_about(what, source):
    assert re.search(REMOVED_IN_17[what], source)


@pytest.mark.parametrize("source", [
    "Process.getModuleByName(name).findExportByName(sym)",
    "mod.enumerateExports()",
    "ptr.readU32()",
    "Memory.alloc(8)",
    "Memory.scanSync(base, size, pattern)",
    "Process.enumerateRanges({ protection: 'rw-' })",
    "const javaVersion = 1; myJava.x",
])
def test_and_leaves_what_17_still_has_alone(source):
    assert not any(re.search(rx, source) for rx in REMOVED_IN_17.values())


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_no_agent_uses_an_api_frida_17_removed(path):
    code = js_code(path)
    found = {what: re.findall(rx, code) for what, rx in REMOVED_IN_17.items()}
    assert {k: v for k, v in found.items() if v} == {}
