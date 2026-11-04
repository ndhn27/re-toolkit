"""
Unit tests for tools/check_identifiers.py.

Every name used here is made up (FooBarRegistry and friends): this file must
never contain a name from a real target, since it is checked in like
everything else - test_shipped_tree_is_clean below runs the checker over the
whole repo, tests included.

Run from the repo root:

    pytest
"""
import re
import subprocess

import pytest

import check_identifiers as ci

NAME = "FooBarRegistry"
DENIED = {ci.digest(NAME)}


def _hits(text, denied=DENIED):
    return [chain for _line, _d, chain in ci.find_in_text(text, denied)]


# --- normalization: one entry covers every spelling of a name

@pytest.mark.parametrize("spelling", [
    "FooBarRegistry", "fooBarRegistry", "foo_bar_registry", "FOO_BAR_REGISTRY",
    "foo-bar-registry", "Foo_Bar_Registry", "foobarregistry",
])
def test_every_spelling_of_a_name_has_the_same_digest(spelling):
    assert ci.digest(spelling) == ci.digest(NAME)


@pytest.mark.parametrize("text", [
    "class FooBarRegistry {}",
    "const x = fooBarRegistry.get(1);",
    "FOO_BAR_REGISTRY = 3",
    "# foo-bar-registry is slow",
    "scripts/dump_foo_bar_registry.js",         # inside a file name
    "getFooBarRegistryEntry()",                  # inside a longer identifier
    "x.FooBarRegistry$$unpack",                  # IL2CPP style
    "HttpFooBarRegistryV2",
])
def test_a_listed_name_is_found_in_any_spelling_and_context(text):
    assert _hits(text), text


def test_acronym_boundaries_are_split_like_camel_case():
    denied = {ci.digest("xy_widget")}
    assert _hits("setXYWidget()", denied)
    assert _hits("XY_WIDGET_LIST", denied)
    assert _hits("xyWidget", denied)


@pytest.mark.parametrize("text", [
    "FooBar",                                    # only part of it
    "BarRegistry",
    "FooRegistryBar",                            # same words, other order
    "foo bar registry",                          # separate words are prose, not an identifier
    "Foo.Bar.Registry",                          # '.' ends an identifier chain
    "FooBarRegistryless is not a thing but",     # NOT a hit: 'registryless' is one other word
    "",
])
def test_things_that_are_not_the_listed_name_are_left_alone(text):
    assert not _hits(text), text


def test_findings_carry_a_line_number_and_the_whole_identifier():
    text = "a\nb\n  call(fooBarRegistry, x)\n"
    [(line, d, chain)] = ci.find_in_text(text, DENIED)
    assert (line, d, chain) == (3, ci.digest(NAME), "fooBarRegistry")


def test_one_finding_per_line_and_name():
    assert len(ci.find_in_text("fooBarRegistry fooBarRegistry foo_bar_registry", DENIED)) == 1


def test_very_long_identifiers_stay_bounded():
    text = "_".join(["word"] * 500)
    assert ci.find_in_text(text, DENIED) == []


# --- the list: digests only, never names

def test_load_rejects_a_plain_name(tmp_path):
    f = tmp_path / "list.txt"
    f.write_text("# header\n" + NAME + "\n")
    with pytest.raises(ci.DenylistError, match="never names"):
        ci.load_digests(f)


def test_add_names_writes_only_digests_and_skips_duplicates(tmp_path):
    f = tmp_path / "list.txt"
    assert ci.add_names([NAME, "foo_bar_registry", "OtherThing"], f) == 2
    assert ci.add_names([NAME.upper()], f) == 0
    lines = [line for line in f.read_text().splitlines() if line and not line.startswith("#")]
    assert lines and all(re.fullmatch(r"[0-9a-f]{64}", line) for line in lines)
    assert "foobarregistry" not in f.read_text().lower()
    assert ci.load_digests(f) == {ci.digest(NAME), ci.digest("OtherThing")}


def test_add_names_rejects_something_with_no_letters(tmp_path):
    with pytest.raises(ci.DenylistError):
        ci.add_names(["___"], tmp_path / "list.txt")


def test_plain_name_file_is_hashed_in_memory(tmp_path):
    f = tmp_path / "private.txt"
    f.write_text("# private\n\n" + NAME + "\n")
    assert ci.load_plain_names(f) == DENIED


def test_shipped_denylist_is_digests_only():
    for n, line in enumerate(ci.DENYLIST_PATH.read_text().splitlines(), 1):
        line = line.strip()
        assert not line or line.startswith("#") or re.fullmatch(r"[0-9a-f]{64}", line), n


def test_shipped_denylist_is_not_empty():
    assert ci.load_digests()


# --- scanning a tree

def _tree(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _denylist(tmp_path):
    f = tmp_path / "_list.txt"
    ci.add_names([NAME], f)
    return str(f)


def test_whole_tree_flags_content_and_file_names(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ci, "REPO_ROOT", tmp_path / "repo")
    _tree(tmp_path / "repo", {
        "ok.md": "nothing to see\n",
        "src/a.js": "line one\nconst r = fooBarRegistry;\n",
        "src/dump_foo_bar_registry.js": "// clean content\n",
    })
    assert ci.main(["--denylist", _denylist(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "src/a.js:2" in err
    assert "src/dump_foo_bar_registry.js (file name)" in err
    assert "ok.md" not in err


def test_output_does_not_repeat_the_name_unless_asked(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ci, "REPO_ROOT", tmp_path / "repo")
    _tree(tmp_path / "repo", {"a.js": "const r = fooBarRegistry;\n"})
    ci.main(["--denylist", _denylist(tmp_path)])
    err = capsys.readouterr().err
    assert "fooBarRegistry" not in err and ci.digest(NAME)[:8] in err

    ci.main(["--denylist", _denylist(tmp_path), "--show"])
    assert "'fooBarRegistry'" in capsys.readouterr().err


def test_clean_tree_passes(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ci, "REPO_ROOT", tmp_path / "repo")
    _tree(tmp_path / "repo", {"a.js": "const r = fooBar;\n", "b/README.md": "foo bar registry\n"})
    assert ci.main(["--denylist", _denylist(tmp_path)]) == 0
    assert "OK" in capsys.readouterr().out


@pytest.mark.parametrize("folder", ["profiles", "build", "dist", "node_modules"])
def test_private_and_generated_folders_are_not_scanned(tmp_path, monkeypatch, folder):
    monkeypatch.setattr(ci, "REPO_ROOT", tmp_path / "repo")
    _tree(tmp_path / "repo", {f"{folder}/myapp/layouts.json": '{"r": "FooBarRegistry"}\n'})
    assert ci.main(["--denylist", _denylist(tmp_path)]) == 0


def test_binary_files_are_skipped(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "blob.bin").write_bytes(b"\0\1\2 FooBarRegistry \0")
    monkeypatch.setattr(ci, "REPO_ROOT", root)
    assert ci.main(["--denylist", _denylist(tmp_path)]) == 0


def test_an_empty_denylist_is_an_error_not_a_pass(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ci, "REPO_ROOT", tmp_path)
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n")
    assert ci.main(["--denylist", str(empty)]) == 2
    assert "empty" in capsys.readouterr().err


def test_malformed_denylist_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(ci, "REPO_ROOT", tmp_path)
    bad = tmp_path / "bad.txt"
    bad.write_text(NAME + "\n")
    assert ci.main(["--denylist", str(bad)]) == 2


def test_private_plain_list_is_checked_in_addition(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    monkeypatch.setattr(ci, "REPO_ROOT", root)
    _tree(root, {"a.js": "const r = secretWidgetName;\n"})
    private = tmp_path / "private.txt"
    private.write_text("SecretWidgetName\n")
    # not on the committed list, so invisible to it ...
    assert ci.main(["--denylist", _denylist(tmp_path)]) == 0
    # ... but caught once the private plain list is supplied (flag or env var)
    assert ci.main(["--denylist", _denylist(tmp_path), "--denylist-file", str(private)]) == 1
    monkeypatch.setenv(ci.ENV_DENYLIST_FILE, str(private))
    assert ci.main(["--denylist", _denylist(tmp_path)]) == 1


def test_hash_and_add_cli(tmp_path, capsys):
    assert ci.main(["--hash", NAME]) == 0
    assert capsys.readouterr().out.strip() == ci.digest(NAME)
    f = tmp_path / "list.txt"
    assert ci.main(["--denylist", str(f), "--add", NAME]) == 0
    assert "added 1" in capsys.readouterr().out
    names = tmp_path / "names.txt"
    names.write_text("# c\nFooBarRegistry\nAnotherName\n")
    assert ci.main(["--denylist", str(f), "--add-file", str(names)]) == 0
    assert "added 1" in capsys.readouterr().out


# --- staged mode: the same code path as the pre-commit hook

def _init_repo(path):
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)


def _stage(path):
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)


def test_staged_blob_is_checked_not_the_worktree(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    _init_repo(root)
    monkeypatch.setattr(ci, "REPO_ROOT", root)
    _tree(root, {"a.js": "const r = fooBarRegistry;\n"})
    _stage(root)
    (root / "a.js").write_text("const r = 1;\n")          # reset on disk after staging
    assert ci.main(["--denylist", _denylist(tmp_path), "--staged"]) == 1


def test_staged_clean_file_passes_even_if_the_worktree_has_the_name(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    _init_repo(root)
    monkeypatch.setattr(ci, "REPO_ROOT", root)
    _tree(root, {"a.js": "const r = 1;\n"})
    _stage(root)
    (root / "a.js").write_text("const r = fooBarRegistry;\n")   # edited, not staged
    assert ci.main(["--denylist", _denylist(tmp_path), "--staged"]) == 0


def test_staged_rename_to_a_listed_name_is_blocked(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    _init_repo(root)
    monkeypatch.setattr(ci, "REPO_ROOT", root)
    _tree(root, {"agent.js": "const r = 1;\n"})
    _stage(root)
    subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=root, check=True)
    subprocess.run(["git", "mv", "agent.js", "dump_foo_bar_registry.js"], cwd=root, check=True)
    assert ci.main(["--denylist", _denylist(tmp_path), "--staged"]) == 1


def test_staged_deletion_is_ignored(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    _init_repo(root)
    monkeypatch.setattr(ci, "REPO_ROOT", root)
    _tree(root, {"a.js": "const r = fooBarRegistry;\n"})
    _stage(root)
    subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=root, check=True)
    subprocess.run(["git", "rm", "-q", "a.js"], cwd=root, check=True)
    assert ci.main(["--denylist", _denylist(tmp_path), "--staged"]) == 0


def test_git_ignored_files_are_not_scanned(tmp_path, monkeypatch):
    # The docs tell you to keep real material in git-ignored places.
    root = tmp_path / "repo"
    _init_repo(root)
    monkeypatch.setattr(ci, "REPO_ROOT", root)
    _tree(root, {".gitignore": "private/\n", "private/notes.md": "FooBarRegistry\n", "a.js": "x\n"})
    assert ci.main(["--denylist", _denylist(tmp_path)]) == 0


# --- the repo itself

def test_shipped_tree_is_clean():
    # The template must pass its own check, tests and docs included.
    assert ci.main([]) == 0
