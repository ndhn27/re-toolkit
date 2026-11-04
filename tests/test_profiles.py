"""
Tests for retk profile: finding and loading a profile, turning it into
the parameters an agent receives, and its small CLI.

A profile is a JSON file outside git; profile.example.json is the template and
doubles as the fixture here (made-up names, every offset 0x0).

Run from the repo root:

    pytest
"""
import copy
import json
from pathlib import Path

import pytest

from retk import layouts
from retk import profiles
REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "profile.example.json"
RAW = json.loads(EXAMPLE.read_text(encoding="utf-8"))


def write(tmp_path, raw, name="p.json"):
    path = tmp_path / name
    path.write_text(raw if isinstance(raw, str) else json.dumps(raw), encoding="utf-8")
    return path


# --- finding ---

def test_a_bare_name_is_looked_up_in_the_profiles_dir(tmp_path, monkeypatch):
    monkeypatch.setenv(profiles.ENV_PROFILES_DIR, str(tmp_path))
    write(tmp_path, RAW, "myapp.json")
    assert profiles.find("myapp") == tmp_path / "myapp.json"
    assert profiles.load("myapp").name == "myapp"


def test_the_default_profiles_dir_is_profiles_in_the_users_data_dir_not_the_repo(monkeypatch, tmp_path):
    monkeypatch.delenv(profiles.ENV_PROFILES_DIR, raising=False)
    monkeypatch.setenv("RE_DATA_DIR", str(tmp_path))
    assert profiles.profiles_dir() == tmp_path / "profiles"
    assert REPO_ROOT not in profiles.profiles_dir().parents


def test_a_profile_still_in_the_repos_old_profiles_dir_is_read_with_a_warning(monkeypatch, tmp_path, capsys):
    legacy = tmp_path / "repo-profiles"
    legacy.mkdir()
    write(legacy, RAW, "old.json")
    monkeypatch.setattr("retk.paths.LEGACY_PROFILES_DIR", legacy)
    assert profiles.find("old") == legacy / "old.json"
    err = capsys.readouterr().err
    assert "outside the repo" in err and str(profiles.profiles_dir() / "old.json") in err
    # a profile in the new place wins, silently
    profiles.profiles_dir().mkdir(parents=True)
    write(profiles.profiles_dir(), RAW, "old.json")
    assert profiles.find("old") == profiles.profiles_dir() / "old.json"
    assert capsys.readouterr().err == ""


def test_the_legacy_dir_is_not_consulted_when_RE_PROFILES_DIR_says_where(monkeypatch, tmp_path):
    legacy = tmp_path / "repo-profiles"
    legacy.mkdir()
    write(legacy, RAW, "old.json")
    monkeypatch.setattr("retk.paths.LEGACY_PROFILES_DIR", legacy)
    monkeypatch.setenv(profiles.ENV_PROFILES_DIR, str(tmp_path / "elsewhere"))
    with pytest.raises(profiles.ProfileError, match="not found"):
        profiles.find("old")


def test_a_path_is_used_as_is(tmp_path):
    path = write(tmp_path, RAW, "anywhere.json")
    assert profiles.find(str(path)) == path


def test_missing_profiles_say_where_they_looked(tmp_path, monkeypatch):
    monkeypatch.setenv(profiles.ENV_PROFILES_DIR, str(tmp_path))
    with pytest.raises(profiles.ProfileError, match=r"nope\.json"):
        profiles.find("nope")
    with pytest.raises(profiles.ProfileError, match="no such file"):
        profiles.find(str(tmp_path / "nope.json"))


def test_profiles_dir_is_git_ignored():
    # The backstop for people who keep profiles inside the repo.
    lines = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "profiles/" in lines


# --- loading ---

def test_the_example_profile_loads_and_is_inert():
    p = profiles.load(EXAMPLE)
    assert p.target.startswith("com.example.")
    assert p.remote == "127.0.0.1:27042" and p.module == "UnityFramework"
    assert p.offsets and set(p.offsets.values()) == {0}      # the agents refuse to hook at 0
    assert set(p.layouts["records"]) == {"TableARecord", "TableBRecord"}


def test_remote_defaults_when_omitted_but_the_module_never_does(tmp_path):
    p = profiles.load(write(tmp_path, {"target": "com.example.t"}))
    assert (p.remote, p.module, p.offsets, p.layouts) == (profiles.DEFAULT_REMOTE, None, {}, None)
    assert not hasattr(profiles, "DEFAULT_MODULE")           # no platform is assumed


def test_offsets_are_parsed_from_hex_strings(tmp_path):
    p = profiles.load(write(tmp_path, {"target": "t", "offsets": {"a": "0xAB68FC8", "b": 16}}))
    assert p.offsets == {"a": 0xab68fc8, "b": 16}


BAD_PROFILES = {
    "not an object": ("[]", "JSON object"),
    "invalid json": ("{", "p.json"),
    "no target": ({"remote": "h:1"}, "target"),
    "empty target": ({"target": " "}, "target must be"),
    "numeric module": ({"target": "t", "module": 3}, "module must be"),
    "offset without 0x": ({"target": "t", "offsets": {"a": "ab68fc8"}}, "offsets.a"),
    "negative offset": ({"target": "t", "offsets": {"a": -1}}, "offsets.a"),
    "boolean offset": ({"target": "t", "offsets": {"a": True}}, "offsets.a"),
}


@pytest.mark.parametrize("case", sorted(BAD_PROFILES))
def test_malformed_profiles_are_rejected_with_the_file_named(tmp_path, case):
    raw, message = BAD_PROFILES[case]
    with pytest.raises(profiles.ProfileError, match=message) as e:
        profiles.load(write(tmp_path, raw))
    assert "p.json" in str(e.value)


def test_a_bad_layout_is_reported_as_the_profiles_problem(tmp_path):
    raw = copy.deepcopy(RAW)
    raw["layouts"]["records"]["TableARecord"]["fields"][0]["offset"] = "0x11"
    with pytest.raises(profiles.ProfileError, match="layouts: .*not naturally aligned"):
        profiles.load(write(tmp_path, raw))


# --- what the agent receives ---

def test_agent_params_need_a_module_from_somewhere():
    with pytest.raises(profiles.ProfileError, match="--module"):
        profiles.agent_params(None)
    assert profiles.agent_params(None, module="libil2cpp.so") == {"module": "libil2cpp.so", "offsets": {}}


def test_a_profile_without_a_module_is_fine_as_long_as_the_cli_names_one(tmp_path):
    p = profiles.load(write(tmp_path, {"target": "t", "offsets": {"a": "0x10"}}))
    with pytest.raises(profiles.ProfileError, match="module"):
        profiles.agent_params(p)
    assert profiles.agent_params(p, module="UnityFramework") == {
        "module": "UnityFramework", "offsets": {"a": 0x10}}


def test_overrides_win_over_the_profile_and_the_rest_stays(tmp_path):
    p = profiles.load(write(tmp_path, {"target": "t", "module": "libil2cpp.so",
                                       "offsets": {"a": "0x10", "b": "0x20"}}))
    params = profiles.agent_params(p, offsets={"a": 0x99, "c": 0x30})
    assert params == {"module": "libil2cpp.so", "offsets": {"a": 0x99, "b": 0x20, "c": 0x30}}
    assert profiles.agent_params(p, module="other")["module"] == "other"
    assert p.offsets == {"a": 0x10, "b": 0x20}                # the profile itself isn't mutated


def test_agent_params_carry_layouts_as_plain_json():
    params = profiles.agent_params(profiles.load(EXAMPLE))
    assert json.loads(json.dumps(params)) == params
    assert params["layouts"] == layouts.for_agent(profiles.load(EXAMPLE).layouts)


# --- the CLI ---

def test_params_command_prints_what_frida_dash_P_wants(capsys):
    assert profiles.main(["params", str(EXAMPLE)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed == profiles.agent_params(profiles.load(EXAMPLE))


def test_params_command_without_a_module_is_an_error_not_a_traceback(tmp_path, capsys):
    path = write(tmp_path, {"target": "t"})
    assert profiles.main(["params", str(path)]) == 2
    assert "module" in capsys.readouterr().err


def test_layout_command_lists_every_record(capsys):
    assert profiles.main(["layout", str(EXAMPLE)]) == 0
    out = capsys.readouterr().out
    assert "TableARecord  key=id" in out and "TableBRecord  key=kind+id" in out


def test_layout_command_without_layouts_fails_cleanly(tmp_path, capsys):
    path = write(tmp_path, {"target": "t"})
    assert profiles.main(["layout", str(path)]) == 2
    assert "no layouts defined" in capsys.readouterr().err


def test_a_missing_profile_is_an_error_not_a_traceback(tmp_path, capsys):
    assert profiles.main(["params", str(tmp_path / "nope.json")]) == 2
    assert "no such file" in capsys.readouterr().err


# --- `retk profile init`: start a profile from the example, on an install with no repo to copy it from ---

def test_init_copies_the_example_into_the_profiles_dir(capsys):
    assert profiles.main(["init", "mygame"], prog="retk profile") == 0
    target = profiles.profiles_dir() / "mygame.json"
    assert target.read_bytes() == EXAMPLE.read_bytes()
    out = capsys.readouterr().out
    assert str(target) in out and "retk profile layout mygame" in out
    assert profiles.load("mygame").target                       # and it is a profile that loads


def test_init_follows_RE_PROFILES_DIR(monkeypatch, tmp_path):
    monkeypatch.setenv(profiles.ENV_PROFILES_DIR, str(tmp_path / "elsewhere"))
    assert profiles.init_profile("g") == tmp_path / "elsewhere" / "g.json"


def test_init_never_overwrites_a_profile_unless_told_to(capsys):
    profiles.init_profile("mygame")
    target = profiles.profiles_dir() / "mygame.json"
    target.write_text('{"mine": true}', encoding="utf-8")
    assert profiles.main(["init", "mygame"]) == 2
    assert "already exists" in capsys.readouterr().err and target.read_text(encoding="utf-8") == '{"mine": true}'
    assert profiles.main(["init", "mygame", "--force"]) == 0
    assert target.read_bytes() == EXAMPLE.read_bytes()


@pytest.mark.parametrize("name", ["a/b", "a\\b", "x.json", "..", "", "/abs/path"])
def test_init_takes_a_name_not_a_path(name):
    with pytest.raises(profiles.ProfileError, match="NAME"):
        profiles.init_profile(name)


def test_init_without_the_template_says_so(monkeypatch):
    monkeypatch.setattr("retk.resources.example_profile_path", lambda: None)
    with pytest.raises(profiles.ProfileError, match="not part of this install"):
        profiles.init_profile("g")
