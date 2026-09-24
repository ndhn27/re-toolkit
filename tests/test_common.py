"""
Unit tests for tools/_common.py.

No device, no Frida and no real binary needed - this only exercises the
CLI/env/config.py precedence logic (_pick/resolve_settings/add_override_args)
and the FRIDA_OFFSET-injection regex in load_agent_source() against small
in-memory/tmp_path fixtures, same spirit as the other test files in this
directory.

Run from the repo root:

    pytest
"""
import argparse

import pytest

import _common as common
import config


class _Args:
    """Minimal stand-in for the argparse.Namespace that resolve_settings()
    reads .target/.remote/.offset off of."""

    def __init__(self, target=None, remote=None, offset=None):
        self.target = target
        self.remote = remote
        self.offset = offset


# --- parse_offset ---

def test_parse_offset_with_0x_prefix():
    assert common.parse_offset("0xab68fc8") == 0xab68fc8


def test_parse_offset_without_0x_prefix():
    assert common.parse_offset("ab68fc8") == 0xab68fc8


def test_parse_offset_rejects_non_hex():
    with pytest.raises(argparse.ArgumentTypeError):
        common.parse_offset("not-a-hex-value")


def test_parse_offset_rejects_negative():
    # int("-5", 16) parses fine as -5 - the explicit `value < 0` check is
    # what actually rejects it, so this exercises that check specifically.
    with pytest.raises(argparse.ArgumentTypeError):
        common.parse_offset("-5")


# --- _pick ---

def test_pick_cli_value_wins_over_everything(monkeypatch):
    monkeypatch.setenv(common.ENV_TARGET, "com.env.value")
    value, source = common._pick("com.cli.value", common.ENV_TARGET, "com.default.value")
    assert (value, source) == ("com.cli.value", "CLI")


def test_pick_env_value_wins_over_default(monkeypatch):
    monkeypatch.setenv(common.ENV_TARGET, "com.env.value")
    value, source = common._pick(None, common.ENV_TARGET, "com.default.value")
    assert (value, source) == ("com.env.value", f"env {common.ENV_TARGET}")


def test_pick_falls_back_to_default_when_nothing_else_set(monkeypatch):
    monkeypatch.delenv(common.ENV_TARGET, raising=False)
    value, source = common._pick(None, common.ENV_TARGET, "com.default.value")
    assert (value, source) == ("com.default.value", "config.py")


def test_pick_empty_env_string_counts_as_not_set(monkeypatch):
    # _pick's own comment says an empty string counts as "not set" -
    # verify that's actually true, not just documented.
    monkeypatch.setenv(common.ENV_TARGET, "")
    value, source = common._pick(None, common.ENV_TARGET, "com.default.value")
    assert (value, source) == ("com.default.value", "config.py")


def test_pick_parses_env_value_when_parse_given(monkeypatch):
    monkeypatch.setenv(common.ENV_OFFSET, "ab68fc8")
    value, source = common._pick(None, common.ENV_OFFSET, 0x0, parse=common.parse_offset)
    assert (value, source) == (0xab68fc8, f"env {common.ENV_OFFSET}")


def test_pick_invalid_env_value_exits(monkeypatch):
    monkeypatch.setenv(common.ENV_OFFSET, "not-a-hex-value")
    with pytest.raises(SystemExit):
        common._pick(None, common.ENV_OFFSET, 0x0, parse=common.parse_offset)


# --- resolve_settings ---

def test_resolve_settings_combines_cli_env_and_config(monkeypatch):
    monkeypatch.setattr(config, "TARGET", "com.example.unitygame")
    monkeypatch.setattr(config, "REMOTE_ADDR", "127.0.0.1:27042")
    monkeypatch.setattr(config, "FRIDA_OFFSET", 0x0)
    monkeypatch.delenv(common.ENV_TARGET, raising=False)
    monkeypatch.delenv(common.ENV_REMOTE, raising=False)
    monkeypatch.setenv(common.ENV_OFFSET, "ab68fc8")

    args = _Args(target="com.cli.value", remote=None, offset=None)
    settings = common.resolve_settings(args)

    assert settings.target == "com.cli.value"          # CLI wins
    assert settings.remote_addr == "127.0.0.1:27042"    # falls back to config.py
    assert settings.offset == 0xab68fc8                 # falls back to env


def test_resolve_settings_offset_false_returns_none(monkeypatch):
    monkeypatch.setattr(config, "TARGET", "com.example.unitygame")
    monkeypatch.setattr(config, "REMOTE_ADDR", "127.0.0.1:27042")
    monkeypatch.delenv(common.ENV_TARGET, raising=False)
    monkeypatch.delenv(common.ENV_REMOTE, raising=False)

    args = _Args(target=None, remote=None)
    settings = common.resolve_settings(args, offset=False)

    assert settings.offset is None


# --- add_override_args ---

def test_add_override_args_includes_offset_by_default():
    parser = argparse.ArgumentParser()
    common.add_override_args(parser)
    args = parser.parse_args(["--offset", "ab68fc8"])
    assert args.offset == 0xab68fc8


def test_add_override_args_omits_offset_when_disabled():
    parser = argparse.ArgumentParser()
    common.add_override_args(parser, offset=False)
    # --offset was never registered (e.g. list_exports.py's driver), so
    # argparse rejects it as an unrecognized argument.
    with pytest.raises(SystemExit):
        parser.parse_args(["--offset", "ab68fc8"])


# --- load_agent_source ---

def test_load_agent_source_injects_offset(tmp_path):
    f = tmp_path / "agent.js"
    f.write_text("const FRIDA_OFFSET = 0x0; // <-- SET THIS\n")

    source = common.load_agent_source(f, offset=0xab68fc8)

    assert "const FRIDA_OFFSET = 0xab68fc8;" in source


def test_load_agent_source_no_offset_leaves_source_unchanged(tmp_path):
    f = tmp_path / "agent.js"
    original = "const FRIDA_OFFSET = 0x0; // <-- SET THIS\n"
    f.write_text(original)

    source = common.load_agent_source(f, offset=None)

    assert source == original


def test_load_agent_source_missing_offset_constant_is_a_noop(tmp_path, capsys):
    # e.g. list_il2cpp_exports.js, which declares no FRIDA_OFFSET at all.
    f = tmp_path / "agent.js"
    original = "console.log('no offset here');\n"
    f.write_text(original)

    source = common.load_agent_source(f, offset=0xab68fc8)

    assert source == original
    assert "no FRIDA_OFFSET constant found" in capsys.readouterr().out


# --- is_gitignored ---

def _git(cwd, *argv):
    import subprocess
    subprocess.run(["git", *argv], cwd=cwd, check=True, capture_output=True)


def test_is_gitignored_true_for_a_covered_name(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("records*.json\n")

    assert common.is_gitignored(tmp_path / "records_ab68fc8.json") is True


def test_is_gitignored_false_for_an_uncovered_name(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("records*.json\n")

    assert common.is_gitignored(tmp_path / "dump_ab68fc8.json") is False


def test_is_gitignored_works_when_the_output_dir_does_not_exist_yet(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("records*.json\n")

    assert common.is_gitignored(tmp_path / "not" / "made" / "yet" / "records.json") is True


def test_is_gitignored_none_outside_a_git_repo(tmp_path):
    # tmp_path has no .git anywhere above it (pytest's tmp dirs live under
    # /tmp) - git can't answer, so the driver must stay quiet, not warn.
    assert common.is_gitignored(tmp_path / "records.json") is None


def test_load_agent_source_missing_file_explains_how_to_build(tmp_path):
    missing = tmp_path / "dist" / "dump_hd_quality_list.js"
    with pytest.raises(FileNotFoundError, match="npm run build"):
        common.load_agent_source(missing)
