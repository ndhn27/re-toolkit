"""
check_placeholders.py

Safeguard for this "generic template" repo (see README.md): a real
Ghidra-derived offset or a real app's package/bundle id must never land in
git history, even by accident. Point 5 of the template's threat model is
that this has so far relied on self-discipline plus the runtime
`if (OFFSET === 0x0) throw ...` guards already in scripts/*.js - useful,
but both only fire *after* something's already been typed in. This script
is the automated backstop: it runs *before* a real value can be committed
at all.

Checks exactly what README.md tells you to edit, nothing more:

  1. Every OFFSET-ish scalar `const`/`let`/`var` in scripts/*.js and
     legacy/*.js must still resolve to zero (this covers FRIDA_OFFSET and
     the OFFSET_GetConfigMatchingDevicePattern / OFFSET_GetRecommendedQualityPreset
     pair in dump_selection_logic.js, without hardcoding every name). A
     named *table* of struct field-offsets (e.g. dump_hd_quality_list.js's
     `const OFFSETS = { id: 0x08, ... }`) is skipped - those are documented
     record-layout constants (see docs/MEMORY_LAYOUT.md), not a
     build-specific address to keep secret, and there's no single scalar
     value there to judge against the placeholder anyway.
  2. tools/config.py's TARGET must still be "com.example.unitygame" and its
     FRIDA_OFFSET must still resolve to zero.

Deliberately allow-list, not block-list: earlier versions of this script
matched a *specific* "real value" shape (`const NAME = 0x...;`, a
double-quoted TARGET). Every one of those is trivially dodged by writing
the same value a different way - decimal instead of hex, `0xab68_fc8`
with a digit separator, a `0xab68fc8n` BigInt suffix, `ptr("0xab68fc8")`,
`let`/`var` instead of `const`, a lowercase `offset` identifier, a
single-quoted TARGET string - none of which are a "real offset" pattern
the old regex knew to look for, so all slipped through clean. This version
finds the *identifier* first (OFFSET-ish name, or exactly TARGET) with a
loose, format-agnostic match, then normalizes whatever's on the right of
`=` and checks it against the *known-good placeholder* - anything that
isn't recognizably the placeholder is a violation, no matter how it's
spelled. New, weirder ways to write a real value keep getting caught;
only new ways to write the *placeholder itself* would need adding here.

It does NOT try to detect a renamed class/namespace (e.g. ExampleNamespace
-> something real) - unlike an offset or a bundle id, there's no fixed
placeholder string to diff a comment against, so that part still relies on
you following README.md's "Adapting this template" steps.

Wired in two places, both calling this same script so there's one source
of truth:
  - .githooks/pre-commit (staged files only - install with
    `git config core.hooksPath .githooks`, see README.md)
  - .github/workflows/check-placeholders.yml (the full tree on every push/
    PR - catches it even for someone who never installed the hook, or who
    used `git commit --no-verify`)

`--staged` reads each file's *staged* content (`git show :path`), not
whatever's sitting in the working tree - otherwise a value that's staged
but reset on disk afterward would slip past `OK`, and a value that's only
edited on disk but never staged would get flagged for no reason.

Usage:
    python3 tools/check_placeholders.py            # full working tree
    python3 tools/check_placeholders.py --staged   # staged files only

Exit status: 0 = clean, 1 = a real value was found.

Zero third-party dependencies on purpose - this has to run in a bare
pre-commit hook and a minimal CI job with no `pip install` step.
"""
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PLACEHOLDER_TARGET = "com.example.unitygame"

# Finds any `[const|let|var]? NAME = VALUE` line, whatever NAME is. The
# "NAME contains 'offset'" filter is applied afterwards in Python
# (`"offset" in name.lower()`), not baked into this regex - a NAME like
# "OFFSET_GetConfigMatchingDevicePattern" has the substring starting at
# position 0, and folding that check into the regex itself (requiring a
# separate leading identifier-char token before the literal "offset")
# means the substring can never start at that very first captured
# character - an off-by-one that silently un-matches exactly the
# real-world names this is meant to catch. Filtering after matching sidesteps
# that. VALUE is grabbed as raw text up to a `;` or a `//` comment -
# normalized and judged by _is_placeholder_zero() below, not by this regex,
# so any literal spelling of the value (decimal, hex, `_` separators,
# BigInt `n`, `ptr(...)`) is still found here and only rejected at the
# normalization step.
JS_ASSIGN_RE = re.compile(
    r"""
    ^[ \t]*
    (?:const|let|var)?[ \t]*
    (?P<name>[A-Za-z_$][\w$]*)
    [ \t]*(?<![=!<>])=(?!=)[ \t]*
    (?P<value>[^;\n]+?)
    [ \t]*(?:;|//|$)
    """,
    re.MULTILINE | re.VERBOSE,
)

# Same idea for tools/config.py, scoped to the two names that file's
# docstring says are the actual placeholders - not every identifier that
# happens to contain "offset"/"target", to avoid flagging unrelated config
# (case-insensitive so `frida_offset = ...` / `target = ...` still count).
PY_OFFSET_ASSIGN_RE = re.compile(
    r"""^[ \t]*(?P<name>FRIDA_OFFSET)[ \t]*(?<![=!<>])=(?!=)[ \t]*(?P<value>.+?)[ \t]*(?:\#.*)?$""",
    re.MULTILINE | re.VERBOSE | re.IGNORECASE,
)
PY_TARGET_ASSIGN_RE = re.compile(
    r"""^[ \t]*(?P<name>TARGET)[ \t]*(?<![=!<>])=(?!=)[ \t]*(?P<value>.+?)[ \t]*(?:\#.*)?$""",
    re.MULTILINE | re.VERBOSE | re.IGNORECASE,
)


def _is_placeholder_zero(raw):
    """True if `raw` - whatever sits on the right of `=` - is some way of
    writing the number 0: decimal `0`, hex `0x0`/`0x00000000`, hex with `_`
    digit separators, a trailing BigInt `n`/`N` suffix, a quoted string
    version of any of those, or one of those wrapped in Frida's `ptr(...)`.
    Anything that isn't recognizably zero - including something that isn't
    a number at all - is NOT a placeholder, i.e. counts as a violation.
    """
    s = raw.strip()

    m = re.fullmatch(r"ptr\(\s*(.+?)\s*\)", s, re.IGNORECASE)
    if m:
        s = m.group(1).strip()

    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1]

    s = s.replace("_", "")

    if s and s[-1] in "nN":
        s = s[:-1]

    try:
        value = int(s, 0)
    except ValueError:
        return False

    return value == 0


def _unquote(s):
    """Strip one layer of matching single/double quotes, if present."""
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def _display(path):
    """Repo-relative path for messages when possible, else the raw path (tests
    pass in tmp_path fixtures that aren't under REPO_ROOT)."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _read_text(path, staged):
    """Read `path`'s content: the *staged* blob (`git show :path`, i.e. the
    index) when `staged` is true, otherwise whatever's on disk right now.
    This is what `--staged` actually needs to check what's about to be
    committed - reading the working-tree file instead would miss a value
    that's staged and then reset on disk, and would wrongly flag a value
    that's only edited on disk but never staged.
    """
    if not staged:
        return path.read_text(encoding="utf-8")
    rel = path.resolve().relative_to(REPO_ROOT).as_posix()
    result = subprocess.run(
        ["git", "show", f":{rel}"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    return result.stdout


def _tracked_js_files():
    """scripts/*.js and legacy/*.js - the only places a real OFFSET can hide."""
    js_dirs = ("scripts", "legacy")
    files = []
    for d in js_dirs:
        d_path = REPO_ROOT / d
        if d_path.is_dir():
            files.extend(sorted(d_path.glob("*.js")))
    return files


def _staged_paths():
    """Absolute paths of files staged for commit (git diff --cached)."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    return {REPO_ROOT / p for p in result.stdout.splitlines() if p}


def check_js_file(path, violations, staged=False):
    """Append a violation for each OFFSET-ish assignment in `path` whose
    value isn't recognizably the zero placeholder, however it's spelled."""
    text = _read_text(path, staged)
    for m in JS_ASSIGN_RE.finditer(text):
        name = m.group("name")
        if "offset" not in name.lower():
            continue
        raw_value = m.group("value")
        if raw_value.strip().startswith(("{", "[")):
            # A field-offset *table* (e.g. `const OFFSETS = { id: 0x08, ... }`
            # in dump_hd_quality_list.js), not a single build-specific address
            # like FRIDA_OFFSET. These are documented struct-layout constants
            # (see docs/MEMORY_LAYOUT.md) meant to stay in git, not a secret
            # to resolve to zero - and the regex only captures up to the end
            # of this line anyway, so there's no scalar here to judge.
            continue
        if not _is_placeholder_zero(raw_value):
            violations.append(
                f"{_display(path)}: {name} = {raw_value.strip()} "
                f"(must stay a zero placeholder in git - this looks like a real offset)")


def check_config_py(path, violations, staged=False):
    """Append a violation if tools/config.py's TARGET or FRIDA_OFFSET has
    been changed from its placeholder value, however it's spelled."""
    if not staged and not path.exists():
        return
    text = _read_text(path, staged)

    for m in PY_OFFSET_ASSIGN_RE.finditer(text):
        name, raw_value = m.group("name"), m.group("value")
        if not _is_placeholder_zero(raw_value):
            violations.append(
                f"{_display(path)}: {name} = {raw_value.strip()} "
                f"(must stay a zero placeholder in git - this looks like a real offset)")

    for m in PY_TARGET_ASSIGN_RE.finditer(text):
        name, raw_value = m.group("name"), m.group("value")
        value = _unquote(raw_value)
        if value != PLACEHOLDER_TARGET:
            violations.append(
                f'{_display(path)}: {name} = "{value}" '
                f'(must stay "{PLACEHOLDER_TARGET}" in git - this looks like a real target)')


def main(argv):
    staged_only = "--staged" in argv
    staged = _staged_paths() if staged_only else None

    violations = []

    for path in _tracked_js_files():
        if staged is not None and path not in staged:
            continue
        check_js_file(path, violations, staged=staged_only)

    config_py = REPO_ROOT / "tools" / "config.py"
    if staged is None or config_py in staged:
        check_config_py(config_py, violations, staged=staged_only)

    if violations:
        print(
            "BLOCKED: this looks like a real offset or target, not this "
            "template's placeholder:\n",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        print(
            "\nThis repo is a generic template (see README.md) - real offsets and "
            "target\nids must never be committed. Reset the value to its placeholder "
            "before\ncommitting; keep your real value out of git entirely (pass it via "
            "--offset\n/ --target, $FRIDA_OFFSET / $FRIDA_TARGET, or a git-ignored local "
            "file instead\nof editing config.py in place).\n",
            file=sys.stderr,
        )
        return 1

    print("OK: no real offsets or targets found.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
