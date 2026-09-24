"""
Terminology guard: the address a hook is installed at (FRIDA_OFFSET, --offset,
OFFSET_* in scripts/) is an RVA - a Ghidra address with Image Base 0, relative
to the module's load address. Only tools/relocate_offset.py works in FILE
offsets. The two are equal for a thin Mach-O slice and different for an ELF or
a fat Mach-O, so a comment that calls the hook address a "file offset" invites
someone porting the tool to hook the wrong place. README.md's "RVA vs file
offset" section is the one definition the other files point at.
"""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = sorted((REPO_ROOT / "scripts").glob("*.js"))
# Everything that talks about the hook address but not about relocation.
HOOK_ADDRESS_FILES = SCRIPTS + [REPO_ROOT / "tools" / name for name in
                                ("config.py", "_common.py", "run_hd_quality_dump.py", "list_exports.py")]

# "file offset" is fine when contrasted ("not a file offset", "not file
# offsets") or when it's the name of the README section ("RVA vs file offset").
_WRONG_TERM = re.compile(r"(?<!not )(?<!not a )(?<!RVA vs )file[- ]offset", re.IGNORECASE)


def test_hook_address_is_never_called_a_file_offset():
    offenders = [f"{p.relative_to(REPO_ROOT)}:{n}: {line.strip()}"
                 for p in HOOK_ADDRESS_FILES
                 for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
                 if _WRONG_TERM.search(line)]
    assert not offenders, "the hook address is an RVA, not a file offset:\n" + "\n".join(offenders)


def test_every_script_that_hooks_by_address_calls_it_an_rva():
    for path in SCRIPTS:
        text = path.read_text(encoding="utf-8")
        if re.search(r"^const (?:FRIDA_OFFSET|OFFSET_\w+) = ", text, re.MULTILINE):
            assert "RVA" in text, f"{path.name} sets a hook address but never says it's an RVA"


def test_readme_defines_rva_vs_file_offset_once():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert len(re.findall(r"^## RVA vs file offset$", readme, re.MULTILINE)) == 1
