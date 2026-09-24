"""
Unit tests for tools/check_placeholders.py.

No git and no real repo tree needed: each test writes a tiny fixture file
under pytest's tmp_path and calls the checker's own functions on it
directly, same spirit as test_relocate_offset.py's in-memory fixtures.

Run from the repo root:

    pytest
"""
import subprocess

import check_placeholders as cp


def test_js_placeholder_offset_is_clean(tmp_path):
    f = tmp_path / "agent.js"
    f.write_text("const FRIDA_OFFSET = 0x0; // <-- SET THIS\n")

    violations = []
    cp.check_js_file(f, violations)

    assert violations == []


def test_js_real_offset_is_blocked(tmp_path):
    f = tmp_path / "agent.js"
    f.write_text("const FRIDA_OFFSET = 0xab68fc8;\n")

    violations = []
    cp.check_js_file(f, violations)

    assert len(violations) == 1
    assert "FRIDA_OFFSET" in violations[0]
    assert "0xab68fc8" in violations[0]


def test_js_real_named_offset_is_blocked(tmp_path):
    # dump_selection_logic.js has its own pair of constants, not FRIDA_OFFSET -
    # both must be caught, and a still-placeholder one must not be flagged.
    f = tmp_path / "dump_selection_logic.js"
    f.write_text(
        "const OFFSET_GetConfigMatchingDevicePattern = 0x1000;\n"
        "const OFFSET_GetRecommendedQualityPreset = 0x0;\n"
    )

    violations = []
    cp.check_js_file(f, violations)

    assert len(violations) == 1
    assert "OFFSET_GetConfigMatchingDevicePattern" in violations[0]


def test_js_probe_style_padded_zero_is_clean(tmp_path):
    # dump_recommend_config_probe.js writes the placeholder as 0x00000000,
    # not 0x0 - both must parse to the same "still a placeholder" value.
    f = tmp_path / "probe.js"
    f.write_text("const FRIDA_OFFSET = 0x00000000; // <-- SET THIS\n")

    violations = []
    cp.check_js_file(f, violations)

    assert violations == []


def test_js_offset_table_object_is_not_flagged(tmp_path):
    # A named struct-field-offset *table* (as in
    # dump_hd_quality_list.js's `const OFFSETS = { id: 0x08, ... }`) is not
    # a build-specific secret like FRIDA_OFFSET - it must not be flagged
    # just because its multi-line object literal doesn't parse as zero.
    f = tmp_path / "agent.js"
    f.write_text(
        "const OFFSETS = {\n"
        "    id: 0x08,\n"
        "    enabled: 0x18,\n"
        "    namePtr: 0x20,\n"
        "};\n"
    )

    violations = []
    cp.check_js_file(f, violations)

    assert violations == []


def test_js_comparison_is_not_mistaken_for_assignment(tmp_path):
    # `if (FRIDA_OFFSET === 0x0)` runtime guards live right next to the
    # const - must not be double-counted as a second assignment.
    f = tmp_path / "agent.js"
    f.write_text(
        "const FRIDA_OFFSET = 0xab68fc8;\n"
        "if (FRIDA_OFFSET === 0x0) {\n"
        "    throw new Error('unset');\n"
        "}\n"
    )

    violations = []
    cp.check_js_file(f, violations)

    assert len(violations) == 1


def test_config_py_placeholders_are_clean(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('TARGET = "com.example.unitygame"\nFRIDA_OFFSET = 0x0\n')

    violations = []
    cp.check_config_py(f, violations)

    assert violations == []


def test_config_py_real_target_is_blocked(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('TARGET = "com.realgamecompany.actualgame"\nFRIDA_OFFSET = 0x0\n')

    violations = []
    cp.check_config_py(f, violations)

    assert len(violations) == 1
    assert "TARGET" in violations[0]
    assert "com.realgamecompany.actualgame" in violations[0]


def test_config_py_real_offset_is_blocked(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('TARGET = "com.example.unitygame"\nFRIDA_OFFSET = 0xab68fc8\n')

    violations = []
    cp.check_config_py(f, violations)

    assert len(violations) == 1
    assert "FRIDA_OFFSET" in violations[0]


def test_config_py_both_real_gives_two_violations(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('TARGET = "com.realgamecompany.actualgame"\nFRIDA_OFFSET = 0xab68fc8\n')

    violations = []
    cp.check_config_py(f, violations)

    assert len(violations) == 2


def test_config_py_missing_file_is_a_noop(tmp_path):
    # main() only calls this when the file exists, but check_config_py stays
    # defensive on its own rather than trusting every future caller.
    violations = []
    cp.check_config_py(tmp_path / "does_not_exist.py", violations)

    assert violations == []


# --- Alternate spellings of a real value (decimal / `_` separators / BigInt
# `n` / `ptr(...)` / `let` / lowercase identifiers / single-quoted TARGET / a
# quoted-string offset in config.py). The checker judges the *value*, not one
# specific shape of "real value"; each of these writes the same real value in
# a different, equally valid shape and must be blocked.

def test_js_decimal_offset_is_blocked(tmp_path):
    f = tmp_path / "agent.js"
    f.write_text("const FRIDA_OFFSET = 179465160;\n")  # 0xab68fc8 in decimal

    violations = []
    cp.check_js_file(f, violations)

    assert len(violations) == 1


def test_js_underscore_hex_offset_is_blocked(tmp_path):
    f = tmp_path / "agent.js"
    f.write_text("const FRIDA_OFFSET = 0xab68_fc8;\n")

    violations = []
    cp.check_js_file(f, violations)

    assert len(violations) == 1


def test_js_bigint_suffix_offset_is_blocked(tmp_path):
    f = tmp_path / "agent.js"
    f.write_text("const FRIDA_OFFSET = 0xab68fc8n;\n")

    violations = []
    cp.check_js_file(f, violations)

    assert len(violations) == 1


def test_js_ptr_wrapped_offset_is_blocked(tmp_path):
    f = tmp_path / "agent.js"
    f.write_text('const FRIDA_OFFSET = ptr("0xab68fc8");\n')

    violations = []
    cp.check_js_file(f, violations)

    assert len(violations) == 1


def test_js_ptr_wrapped_placeholder_is_clean(tmp_path):
    # ptr(0x0) is a legitimate way to write the placeholder too - only the
    # *value* inside ptr(...) matters, not the wrapper.
    f = tmp_path / "agent.js"
    f.write_text('const FRIDA_OFFSET = ptr("0x0"); // <-- SET THIS\n')

    violations = []
    cp.check_js_file(f, violations)

    assert violations == []


def test_js_let_keyword_offset_is_blocked(tmp_path):
    f = tmp_path / "agent.js"
    f.write_text("let FRIDA_OFFSET = 0xab68fc8;\n")

    violations = []
    cp.check_js_file(f, violations)

    assert len(violations) == 1


def test_js_lowercase_identifier_offset_is_blocked(tmp_path):
    f = tmp_path / "agent.js"
    f.write_text("const offset = 0xab68fc8;\n")

    violations = []
    cp.check_js_file(f, violations)

    assert len(violations) == 1


def test_config_py_single_quoted_target_is_blocked(tmp_path):
    f = tmp_path / "config.py"
    f.write_text("TARGET = 'com.real.game'\nFRIDA_OFFSET = 0x0\n")

    violations = []
    cp.check_config_py(f, violations)

    assert len(violations) == 1
    assert "TARGET" in violations[0]
    assert "com.real.game" in violations[0]


def test_config_py_decimal_offset_is_blocked(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('TARGET = "com.example.unitygame"\nFRIDA_OFFSET = 179465160\n')

    violations = []
    cp.check_config_py(f, violations)

    assert len(violations) == 1
    assert "FRIDA_OFFSET" in violations[0]


def test_config_py_quoted_hex_string_offset_is_blocked(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('TARGET = "com.example.unitygame"\nFRIDA_OFFSET = "0xab68fc8"\n')

    violations = []
    cp.check_config_py(f, violations)

    assert len(violations) == 1
    assert "FRIDA_OFFSET" in violations[0]


def test_config_py_lowercase_identifiers_are_still_checked(tmp_path):
    f = tmp_path / "config.py"
    f.write_text("target = 'com.real.game'\nfrida_offset = 0xab68fc8\n")

    violations = []
    cp.check_config_py(f, violations)

    assert len(violations) == 2


# --- `--staged` reads the git index, not the working tree: a value that is
# staged but reset on disk must still be blocked, and one only edited on disk
# must not be flagged.

def _init_repo(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)


def test_staged_real_value_is_blocked_even_after_worktree_reset(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    (tmp_path / "scripts").mkdir()
    f = tmp_path / "scripts" / "agent.js"
    f.write_text("const FRIDA_OFFSET = 0xab68fc8;\n")
    subprocess.run(["git", "add", "scripts/agent.js"], cwd=tmp_path, check=True)
    # Reset the working-tree file back to the placeholder *after* staging -
    # the real value is still what's about to be committed.
    f.write_text("const FRIDA_OFFSET = 0x0; // <-- SET THIS\n")

    monkeypatch.setattr(cp, "REPO_ROOT", tmp_path)
    assert cp.main(["--staged"]) == 1


def test_unstaged_worktree_edit_is_not_flagged(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    (tmp_path / "scripts").mkdir()
    f = tmp_path / "scripts" / "agent.js"
    f.write_text("const FRIDA_OFFSET = 0x0; // <-- SET THIS\n")
    subprocess.run(["git", "add", "scripts/agent.js"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True)
    # Edit on disk only, never staged - nothing is about to be committed.
    f.write_text("const FRIDA_OFFSET = 0xab68fc8;\n")

    monkeypatch.setattr(cp, "REPO_ROOT", tmp_path)
    assert cp.main(["--staged"]) == 0


def test_config_py_staged_real_value_is_blocked_even_after_worktree_reset(tmp_path, monkeypatch):
    # Same property as test_staged_real_value_is_blocked_even_after_worktree_reset
    # above, but for tools/config.py's own --staged path: the tests above
    # only stage a file under scripts/, so this is what exercises
    # check_config_py's _read_text(path, staged=True) (`git show :tools/config.py`).
    _init_repo(tmp_path)
    (tmp_path / "tools").mkdir()
    f = tmp_path / "tools" / "config.py"
    f.write_text('TARGET = "com.realgamecompany.actualgame"\nFRIDA_OFFSET = 0x0\n')
    subprocess.run(["git", "add", "tools/config.py"], cwd=tmp_path, check=True)
    # Reset the working-tree file back to the placeholder *after* staging -
    # the real value is still what's about to be committed.
    f.write_text('TARGET = "com.example.unitygame"\nFRIDA_OFFSET = 0x0\n')

    monkeypatch.setattr(cp, "REPO_ROOT", tmp_path)
    assert cp.main(["--staged"]) == 1


# ===========================================================================
# Classes of bypass the checker closes. The tests above each pin one
# *spelling*; these pin the *classes*: (1) any address-sized literal,
# whatever surrounds it; (2) offset-named assignments however they're
# declared; (3) which files get looked at and how they're listed; (4)
# config.py via ast, not regex.
# ===========================================================================
import pytest  # noqa: E402  (kept next to the tests that use it)

REAL = "0xab68fc8"  # the README's fictional example value


def _js(tmp_path, src, name="a.js"):
    f = tmp_path / name
    f.write_text(src, encoding="utf-8")
    violations = []
    cp.check_js_file(f, violations)
    return violations


def _cfg(tmp_path, src):
    f = tmp_path / "config.py"
    f.write_text(src, encoding="utf-8")
    violations = []
    cp.check_config_py(f, violations)
    return violations


JS_BLOCKED = {
    # -- shapes that dodge a plain `const NAME = VALUE;` line pattern
    "export const":               f"export const FRIDA_OFFSET = {REAL};",
    "HOOK_RVA name":              f"const HOOK_RVA = {REAL};",
    "camelCase rva name":         f"const hookRva = {REAL};",
    "value on the next line":     f"const FRIDA_OFFSET =\n    {REAL};",
    "second declaration, line":   f"const a = 1; const FRIDA_OFFSET = {REAL};",
    "comma declarator":           f"let a = 1, FRIDA_OFFSET = {REAL};",
    "hook offset in a table":     f"const OFFSETS = {{ hook: {REAL} }};",
    "[x][0] array trick":         f"const FRIDA_OFFSET = [{REAL}][0];",
    # -- neighbours of those shapes
    "Object.freeze table":        f"const OFFSETS = Object.freeze({{ hook: {REAL} }});",
    "class field table":          f"class A {{ static OFFSETS = {{ hook: {REAL} }}; }}",
    "small entry in a table":     "const OFFSETS = { hook: 0x2000 };",
    "singular name = object":     "const FRIDA_OFFSET = { a: 0 };",
    "ternary with big literal":   f"const FRIDA_OFFSET = DEBUG ? {REAL} : 0;",
    "ternary with mid literal":   "const FRIDA_OFFSET = DEBUG ? 0x4000 : 0;",
    "mid literal inside a call":  "const hookRva = base.add(0x4000);",
    "continuation line (+)":      "const FRIDA_OFFSET = 0\n  + 0x1000;",
    "small value, next line":     "const FRIDA_OFFSET =\n 0x1000;",
    "= on the next line":         "const FRIDA_OFFSET\n  = 0x1000;",
    "this.offset":                "this.offset = 0x1000;",
    "destructuring default":      "const { offset = 0x1000 } = cfg;",
    "second declarator small":    "const OFFSET_A = 0, OFFSET_B = 0x1000;",
    "after a block comment":      "/* multi\nline */ const FRIDA_OFFSET = 0x1000;",
    "after a url string":         'const u = "http://x/y"; const FRIDA_OFFSET = 0x1000;',
    "|| fallback":                "const FRIDA_OFFSET = 0x0 || 0x1000;",
    "typescript annotation":      f"export const FRIDA_OFFSET: number = {REAL};",
    "+= after a zero init":       f"let FRIDA_OFFSET = 0x0; FRIDA_OFFSET += {REAL};",
    "unprefixed hex in ptr()":    'const FRIDA_OFFSET = ptr("ab68fc8");',
    "small rva, decimal":         "var hookRva = 4096;",
    # -- by value: no offset-ish name at all
    "unnamed constant":           f"const HOOK = {REAL};",
    "glued to an identifier":     f"const hook_{REAL} = 1;",
    "hex in a line comment":      f"// hooked at {REAL}",
    "hex in a block comment":     f"/* base+{REAL} */",
    "hex in a string":            f'const s = "{REAL}";',
    "hex in a template":          f"const t = `${{{REAL}}}`;",
    "decimal":                    "const d = 179465160;",
    "decimal in a string":        'const p = ptr("179465160");',
    "BigInt":                     "const b = 179465160n;",
    "uppercase 0X":               "const x = 0XAB68FC8;",
    "underscore separators":      "const h = 0xab_68_fc8;",
    "Ghidra auto-name":           "// hooked FUN_00ab68fc8",
    "IDA auto-name":              "// sub_AB68FC8",
}

JS_ALLOWED = {
    "placeholder":                "const FRIDA_OFFSET = 0x0; // <-- SET THIS",
    "ptr placeholder":            'const FRIDA_OFFSET = ptr("0x0");',
    "runtime guard":              "if (FRIDA_OFFSET === 0x0) throw new Error('x');",
    "loop counter named offset":  "for (let offset = 8; offset < 0x80; offset += 8) {}",
    "addr from FRIDA_OFFSET":     "const addr = mod.base.add(FRIDA_OFFSET);",
    "offset-named computed":      "const offsetAddr = mod.base.add(FRIDA_OFFSET);",
    "offset arithmetic":          "const nextOffset = offset + 8;",
    "small ternary":              "const FRIDA_OFFSET = DEBUG ? 0x1000 : 0;",
    "arrow parameter":            "const f = offset => offset + 1;",
    "struct table":               "const OFFSETS = {\n  id: 0x08,\n  enabled: 0x18,\n  namePtr: 0x20,\n};",
    "array table":                "const fieldOffsets = [0x08, 0x18, 0x20];",
    "32-bit masks":               "const a = x & 0xffffffff, b = y & 0x7fffffff, c = 0x80000000;",
    "64-bit mask (BigInt)":       "const d = 0xffffffffffffffffn;",
    "power of two":               "const CAP = 0x100000; const K = 1 << 20;",
    "Mach-O / fat magic":         "if (m === 0xfeedfacf || m === 0xcafebabe) {}",
    "ELF magic":                  "const ELF = 0x464c457f;",
    "small timeout":              "setTimeout(f, 30000);",
    "issue url in a comment":     "// see https://github.com/frida/frida/issues/123456",
    "issue ref in a comment":     "// fixes #123456 (see #654321)",
    "date in a comment":          "// 20260920",
    "uuid in a string":           'const id = "a1b2c3d4-e5f6-7890-abcd-123456789012";',
    "digits inside identifiers":  "const sha256 = 1, utf8 = 2, x86_64 = 3, id_1234567 = 5;",
    "non-ASCII comment":          "// Ghi chú: đọc offset của trường (không phải RVA thật)\nconst x = 1;",
    "regex with a quote":         "const re = /[\"']/; const y = 2;",
    "template, no literal":       "const m = `offset: ${off}`;",
    "floats":                     "const r = 1.5, s = 0.25;",
}


@pytest.mark.parametrize("src", JS_BLOCKED.values(), ids=JS_BLOCKED.keys())
def test_js_real_looking_value_is_blocked_whatever_the_spelling(tmp_path, src):
    assert _js(tmp_path, src), f"slipped through: {src!r}"


@pytest.mark.parametrize("src", JS_ALLOWED.values(), ids=JS_ALLOWED.keys())
def test_js_legitimate_code_is_not_flagged(tmp_path, src):
    assert _js(tmp_path, src) == []


def test_js_one_line_gets_one_message(tmp_path):
    # Named and by-value findings on the same line must not double-report.
    assert len(_js(tmp_path, f"export const FRIDA_OFFSET = {REAL};")) == 1


def test_js_violation_message_has_file_and_line(tmp_path):
    (violation,) = _js(tmp_path, f"const a = 1;\nconst FRIDA_OFFSET = {REAL};\n")
    assert violation.startswith(str(tmp_path / "a.js") + ":2:")


PY_BLOCKED = {
    "annotated offset":           f"FRIDA_OFFSET: int = {REAL}\nTARGET = 'com.example.unitygame'",
    "annotated target (single)":  "TARGET: str = 'com.real.game'\nFRIDA_OFFSET = 0x0",
    "annotated target (double)":  'TARGET: str = "com.real.game"',
    "parenthesised, next line":   "TARGET = (\n    'com.real.game'\n)",
    "implicit concatenation":     "TARGET = 'com.real.' 'game'",
    "backslash continuation":     "FRIDA_OFFSET = \\\n    0xab68fc8",
    "chained assignment":         f"A = FRIDA_OFFSET = {REAL}",
    "tuple unpacking (target)":   "TARGET, X = 'com.real.game', 1",
    "tuple unpacking (offset)":   f"X, FRIDA_OFFSET = 1, {REAL}",
    "unpacking from a call":      "TARGET, X = load()",
    "augmented target":           "TARGET = 'com.example.unitygame'\nTARGET += 'x'",
    "augmented offset":           f"FRIDA_OFFSET = 0\nFRIDA_OFFSET += {REAL}",
    "walrus":                     "print(TARGET := 'com.real.game')",
    "dict key":                   "cfg = {}\ncfg['TARGET'] = 'com.real.game'",
    "attribute":                  "import types\nc = types.SimpleNamespace()\nc.TARGET = 'com.real.game'",
    "f-string":                   "TARGET = f'com.real.{1}'",
    "wrapped in a call":          "TARGET = str('com.real.game')",
    "computed from env":          "import os\nFRIDA_OFFSET = int(os.environ.get('FRIDA_OFFSET', '0'), 0)",
    "shifted literals":           "FRIDA_OFFSET = 0xab68 << 16 | 0xfc8",
    "second statement, same line": f"X = 1; FRIDA_OFFSET = {REAL}",
    "RVA name, small":            "HOOK_RVA = 0x1000",
    "annotated RVA name":         "hook_rva: int = 4096",
    "unnamed big integer":        f"HOOK = {REAL}",
    "big integer in a comment":   f"FRIDA_OFFSET = 0x0  # was {REAL}",
    "quoted decimal":             "FRIDA_OFFSET = '179465160'",
    "bytes target":               "TARGET = b'com.example.unitygame'",
    "assigned inside a function": "def f():\n    FRIDA_OFFSET = 0x1000\n    return FRIDA_OFFSET",
    "class attribute":           "class C:\n    TARGET = 'com.real.game'",
    "negative offset":            "FRIDA_OFFSET = -0x1000",
    "does not parse":             "TARGET = (",
}

PY_ALLOWED = {
    "the template itself":        "TARGET = 'com.example.unitygame'\nREMOTE_ADDR = '127.0.0.1:27042'\nFRIDA_OFFSET = 0x0  # <-- SET THIS",
    "annotated placeholders":     'TARGET: str = "com.example.unitygame"\nFRIDA_OFFSET: int = 0x0',
    "parenthesised placeholder":  "TARGET = (\n    'com.example.unitygame'\n)",
    "concatenated placeholder":   "TARGET = 'com.example.' 'unitygame'",
    "every way of writing zero":  "FRIDA_OFFSET = 0\nA_OFFSET = 0_0\nB_OFFSET = 0 * 5\nC_OFFSET = '0x0'\nD_OFFSET = -0",
    "decimals in a comment":      "TARGET = 'com.example.unitygame'  # issue 123456, 20260920",
    "issue url in a comment":     "# https://github.com/x/y/issues/1234567\nFRIDA_OFFSET = 0",
    "comparison":                 "TARGET = 'com.example.unitygame'\nif TARGET == 'x': pass",
    "unrelated names":            "TARGET_PATH = '/tmp/x'\nOFFSET_UNIT = 0",
    "docstring mentioning flags": '"""cfg. Example: --offset 0x0"""\nTARGET = "com.example.unitygame"',
}


@pytest.mark.parametrize("src", PY_BLOCKED.values(), ids=PY_BLOCKED.keys())
def test_config_py_real_looking_value_is_blocked_whatever_the_spelling(tmp_path, src):
    assert _cfg(tmp_path, src), f"slipped through: {src!r}"


@pytest.mark.parametrize("src", PY_ALLOWED.values(), ids=PY_ALLOWED.keys())
def test_config_py_placeholders_are_not_flagged(tmp_path, src):
    assert _cfg(tmp_path, src) == []


def test_config_py_shipped_file_is_clean():
    violations = []
    cp.check_config_py(cp.REPO_ROOT / "tools" / "config.py", violations)
    assert violations == []


# --- which files get checked, and how they're listed. All of these drive
# `main(["--staged"])` against a throwaway git repo - the same code path the
# real pre-commit hook runs.

def _repo_with_script(tmp_path, monkeypatch, name="scripts/agent.js"):
    _init_repo(tmp_path)
    f = tmp_path / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("const FRIDA_OFFSET = 0x0; // <-- SET THIS\n")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=tmp_path, check=True)
    monkeypatch.setattr(cp, "REPO_ROOT", tmp_path)
    return f


def _stage_all(tmp_path):
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)


def test_staged_rename_plus_edit_is_blocked(tmp_path, monkeypatch):
    # `--diff-filter=ACM` skipped status R, so `git mv` + edit went through.
    f = _repo_with_script(tmp_path, monkeypatch)
    subprocess.run(["git", "mv", "scripts/agent.js", "scripts/renamed.js"],
                   cwd=tmp_path, check=True)
    (tmp_path / "scripts" / "renamed.js").write_text(f"const FRIDA_OFFSET = {REAL};\n")
    _stage_all(tmp_path)
    assert cp.main(["--staged"]) == 1


def test_staged_rename_without_edit_is_clean(tmp_path, monkeypatch):
    _repo_with_script(tmp_path, monkeypatch)
    subprocess.run(["git", "mv", "scripts/agent.js", "scripts/renamed.js"],
                   cwd=tmp_path, check=True)
    _stage_all(tmp_path)
    assert cp.main(["--staged"]) == 0


def test_staged_rename_into_another_directory_is_blocked(tmp_path, monkeypatch):
    _repo_with_script(tmp_path, monkeypatch)
    (tmp_path / "tools").mkdir()
    subprocess.run(["git", "mv", "scripts/agent.js", "tools/agent.js"],
                   cwd=tmp_path, check=True)
    (tmp_path / "tools" / "agent.js").write_text(f"const FRIDA_OFFSET = {REAL};\n")
    _stage_all(tmp_path)
    assert cp.main(["--staged"]) == 1


@pytest.mark.parametrize("name", [
    "agent.ts", "src/deep/er/agent.js", "scripts/agent.mjs", "scripts/日本語 tệp.js",
])
def test_staged_js_anywhere_and_any_filename_is_checked(tmp_path, monkeypatch, name):
    # Any staged .js is checked, not just scripts/*.js and legacy/*.js; a
    # non-ASCII name is C-quoted by plain `--name-only`, so the file list
    # must be read in a form that keeps it matchable.
    _init_repo(tmp_path)
    monkeypatch.setattr(cp, "REPO_ROOT", tmp_path)
    f = tmp_path / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(f"const FRIDA_OFFSET = {REAL};\n", encoding="utf-8")
    _stage_all(tmp_path)
    assert cp.main(["--staged"]) == 1


def test_staged_file_that_is_gone_from_the_worktree_is_still_checked(tmp_path, monkeypatch):
    # The file list comes from the git index, not from globbing the working tree.
    _init_repo(tmp_path)
    monkeypatch.setattr(cp, "REPO_ROOT", tmp_path)
    f = tmp_path / "scripts" / "ghost.js"
    f.parent.mkdir()
    f.write_text(f"const FRIDA_OFFSET = {REAL};\n")
    subprocess.run(["git", "add", "scripts/ghost.js"], cwd=tmp_path, check=True)
    f.unlink()
    assert cp.main(["--staged"]) == 1


def test_staged_crlf_and_invalid_utf8_do_not_hide_or_crash(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.setattr(cp, "REPO_ROOT", tmp_path)
    (tmp_path / "a.js").write_bytes(f"const x = 1;\r\nconst FRIDA_OFFSET =\r\n  {REAL};\r\n".encode())
    (tmp_path / "b.js").write_bytes(b"// caf\xe9 \xff\nconst FRIDA_OFFSET = " + REAL.encode() + b";\n")
    _stage_all(tmp_path)
    assert cp.main(["--staged"]) == 1


def test_staged_deletion_is_ignored(tmp_path, monkeypatch):
    _repo_with_script(tmp_path, monkeypatch)
    subprocess.run(["git", "rm", "-q", "scripts/agent.js"], cwd=tmp_path, check=True)
    assert cp.main(["--staged"]) == 0


def test_staged_config_py_type_hint_is_blocked(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.setattr(cp, "REPO_ROOT", tmp_path)
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "config.py").write_text(
        f'TARGET: str = "com.example.unitygame"\nFRIDA_OFFSET: int = {REAL}\n')
    _stage_all(tmp_path)
    assert cp.main(["--staged"]) == 1


# --- full-tree mode (what CI runs).

def test_full_tree_catches_a_renamed_file_that_was_committed(tmp_path, monkeypatch, capsys):
    f = _repo_with_script(tmp_path, monkeypatch)
    subprocess.run(["git", "mv", "scripts/agent.js", "elsewhere.js"], cwd=tmp_path, check=True)
    (tmp_path / "elsewhere.js").write_text(f"const FRIDA_OFFSET = {REAL};\n")
    _stage_all(tmp_path)
    subprocess.run(["git", "commit", "-q", "-m", "renamed"], cwd=tmp_path, check=True)
    assert cp.main([]) == 1
    assert "elsewhere.js" in capsys.readouterr().err


def test_full_tree_ignores_git_ignored_files(tmp_path, monkeypatch):
    # The docs tell you to keep your real offset in a git-ignored local file.
    _repo_with_script(tmp_path, monkeypatch)
    (tmp_path / ".gitignore").write_text("dist/\n")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "_agent.js").write_text(f"const FRIDA_OFFSET = {REAL};\n")
    assert cp.main([]) == 0


def test_full_tree_works_outside_a_git_checkout(tmp_path, monkeypatch):
    # e.g. a downloaded zip: no .git, so it falls back to walking the tree.
    monkeypatch.setattr(cp, "REPO_ROOT", tmp_path)
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "a.js").write_text(f"const HOOK_RVA = {REAL};\n")
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "x.js").write_text(f"const y = {REAL};\n")
    assert cp.main([]) == 1


def test_shipped_tree_is_clean():
    # The template itself must pass its own check.
    assert cp.main([]) == 0
