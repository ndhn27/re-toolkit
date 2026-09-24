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
    # Regression: a named struct-field-offset *table* (as in
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


# --- Regression tests for bypasses that slipped past the old block-list
# regexes (decimal / `_` separators / BigInt `n` / `ptr(...)` / `let` /
# lowercase identifiers / single-quoted TARGET / a quoted-string offset in
# config.py). The old checker required matching a *specific shape* of "real
# value"; these all write the same real value in some other, equally valid
# shape it never accounted for.

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


# --- Regression tests for `--staged` reading the git index, not the
# working tree (previously `path.read_text()` always read whatever was on
# disk, so `--staged` gave the wrong answer whenever disk and index
# disagreed).

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
    # Same regression as test_staged_real_value_is_blocked_even_after_worktree_reset
    # above, but for tools/config.py's own --staged path. Both tests above
    # only ever stage a file under scripts/, so check_config_py's call to
    # _read_text(path, staged=True) (`git show :tools/config.py`) was never
    # actually exercised - this closes that gap.
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
