"""
retk relocate, looking the hook point up BY NAME (`--name` / `--new-metadata`).

A name gives an RVA from the new build's metadata dump; the tool places it in the new binary (RVA -> file
offset, the inverse of the conversion it already printed) and cross-checks it against the byte fingerprint
when the old build is at hand. What is pinned here:

  * rva_to_file_offset() is the exact inverse of file_offset_to_rva() in every container, in the cases
    where the two numbers DIFFER (a mapped-further-on __DATA, a second PT_LOAD, a fat slice), and says
    None - never 0 - where it cannot tell;
  * the name and the bytes AGREE -> HIGH; the bytes find nothing (a rewritten function) -> MEDIUM, which no
    fingerprint could answer; the bytes find SOMEWHERE ELSE -> both candidates and exit 1, never a pick;
  * a name the dump cannot settle (absent, two overloads) or that does not fit the binary (outside every
    segment, misaligned, not code) falls back to the fingerprint when there is an old build, and fails with
    exit 1 when there is not;
  * `--name` needs `--new-metadata`, a malformed name or unreadable dump is a usage error (exit 2);
  * the --json report carries the name block and `via: name`, and the old build is null for a name-only run.

Run from the repo root:

    pytest tests/test_relocate_by_name.py
"""
import json

import pytest

from retk import relocate_offset as ro
from binfmt_fixtures import CODE, NOT_CODE, build_elf64, build_macho
from test_relocate_offset import (HOOK_OFFSET_IN_NEW_TEXT, LDR_LIT_X, NEW_TEXT_WORDS, NOP, OLD_OFFSET, OLD_WORDS, RET, SAFE_RUN,
                                  pack, run_main_err, write_bin, write_blob)
from test_relocate_rva_json import elf_with_two_loads, in_container, macho_with_data

NAME = "ExampleNamespace.ExampleTableA::Unpack/1"
SYMBOL = "ExampleNamespace.ExampleTableA$$Unpack"


def metadata(tmp_path, rva, name=SYMBOL, extra=""):
    path = tmp_path / "symbols.txt"
    path.write_text(f"{name} 0x{rva:x}\n{extra}", encoding="utf-8")
    return str(path)


def run(monkeypatch, capsys, *argv):
    return run_main_err(monkeypatch, capsys, *argv)


# ---------------------------------------------------------------------------
# rva_to_file_offset
# ---------------------------------------------------------------------------

def test_a_thin_macho_maps_text_straight_and_data_further_on():
    blob = macho_with_data()
    assert ro.rva_to_file_offset(blob, 0x1230) == 0x1230
    assert ro.rva_to_file_offset(blob, 0x8010) == 0x4010          # __DATA: file 0x4010 is RVA 0x8010
    assert ro.rva_to_file_offset(blob, 0x5000) is None            # the gap between them has no file bytes


def test_an_elf_maps_each_load_segment_by_its_own_vaddr():
    blob = elf_with_two_loads()
    assert ro.rva_to_file_offset(blob, 0x3010) == 0x1010
    assert ro.rva_to_file_offset(blob, 0x0abc) == 0x0abc
    assert ro.rva_to_file_offset(blob, 0x2000) is None            # between the loads


@pytest.mark.parametrize("make", [macho_with_data, elf_with_two_loads])
def test_it_is_the_inverse_of_file_offset_to_rva(make):
    blob = make()
    checked = 0
    for offset in range(0, len(blob), 0x10):
        rva = ro.file_offset_to_rva(blob, offset)
        if rva is not None:
            assert ro.rva_to_file_offset(blob, rva) == offset
            checked += 1
    assert checked > 100                                           # it really walked both segments


def test_in_a_fat_macho_the_arm64_slice_answers_and_its_offset_is_added():
    blob, file_offset, rva = in_container("fat", NEW_TEXT_WORDS)
    assert file_offset != rva
    assert ro.rva_to_file_offset(blob, rva) == file_offset


@pytest.mark.parametrize("blob", [b"", b"\x00" * 64, b"MZ" + b"\x00" * 100, b"\x7fELF" + b"\x00" * 10])
def test_what_it_cannot_tell_is_none_not_zero(blob):
    assert ro.rva_to_file_offset(blob, 0x10) is None


# ---------------------------------------------------------------------------
# the name and the bytes agree
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["macho", "fat", "elf"])
def test_name_and_fingerprint_agreeing_is_high_in_every_container(tmp_path, monkeypatch, capsys, kind):
    blob, file_offset, rva = in_container(kind, NEW_TEXT_WORDS)
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")

    code, out, _err = run(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--name", NAME,
                          "--new-metadata", metadata(tmp_path, rva))

    assert code == 0
    assert f"NEW FILE OFFSET: 0x{file_offset:x}  (confidence: HIGH, found by name)" in out
    assert f"NEW RVA: 0x{rva:x}" in out
    assert "the name and the byte fingerprint agree" in out
    assert "[pass] name in dump" in out and "[pass] loadable segment" in out and "[pass] executable section" in out


def test_the_report_says_the_name_found_it_and_keeps_the_fingerprints_evidence(tmp_path, monkeypatch, capsys):
    blob, file_offset, rva = in_container("macho", NEW_TEXT_WORDS)
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")
    report = tmp_path / "relocate_name.json"

    code, _out, _err = run(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--name", NAME,
                           "--new-metadata", metadata(tmp_path, rva), "--json", str(report))

    assert code == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["result"] == "unique" and data["old"] == {"binary": old, "file_offset": hex(OLD_OFFSET)}
    [cand] = data["candidates"]
    assert (cand["file_offset"], cand["rva"], cand["confidence"], cand["via"]) == (hex(file_offset), hex(rva), "HIGH", "name")
    assert {c["name"] for c in cand["checks"]} >= {"name in dump", "loadable segment", "executable section"}
    assert data["name"] == {"spec": NAME, "metadata": str(tmp_path / "symbols.txt"), "format": "symbols",
                            "found": True, "how": "name", "rva": hex(rva)}


def test_the_name_settles_which_of_several_look_alikes_is_meant(tmp_path, monkeypatch, capsys):
    # The safe run appears twice in the new build (the fingerprint alone is ambiguous: exit 1).
    words = OLD_WORDS + [NOP] + SAFE_RUN + [RET]
    blob, lay = build_macho([("__TEXT", 5, [("__text", CODE, pack(words))])])
    text = lay["__TEXT,__text"][0]
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")

    code, out, _err = run(monkeypatch, capsys, old, hex(OLD_OFFSET), new)
    assert code == 1 and "More than one match" in out                      # without the name: no answer

    code, out, _err = run(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--name", NAME,
                          "--new-metadata", metadata(tmp_path, text + OLD_OFFSET))
    assert code == 0 and f"NEW FILE OFFSET: 0x{text + OLD_OFFSET:x}  (confidence: HIGH" in out
    assert "the name settles it: the fingerprint alone found 2 places" in out


# ---------------------------------------------------------------------------
# the bytes find nothing: the function was rewritten
# ---------------------------------------------------------------------------

def rewritten_build(tmp_path):
    """A new build where the function's code changed (no fingerprint finds it), in a real container."""
    changed_run = [SAFE_RUN[0]] + [NOP] * 4 + SAFE_RUN[1:]
    words = [NOP] * 4 + changed_run + [LDR_LIT_X, RET] + [NOP] * 4
    blob, lay = build_macho([("__TEXT", 5, [("__text", CODE, pack(words))])])
    return write_blob(tmp_path, blob, "new.bin"), lay["__TEXT,__text"][0], len(words)


def test_a_rewritten_function_is_found_by_name_though_no_fingerprint_can_find_it(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new, text, _n = rewritten_build(tmp_path)

    code, out, _err = run(monkeypatch, capsys, old, hex(OLD_OFFSET), new)
    assert code == 1 and "No matches" in out                               # the bytes alone: nothing

    at = text + 4 * 4
    code, out, _err = run(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--name", NAME,
                          "--new-metadata", metadata(tmp_path, at))
    assert code == 0
    assert f"NEW FILE OFFSET: 0x{at:x}  (confidence: MEDIUM, found by name)" in out
    assert "the byte fingerprint found nothing" in out and "rewritten" in out


# ---------------------------------------------------------------------------
# the bytes find somewhere else
# ---------------------------------------------------------------------------

def test_a_name_that_contradicts_the_fingerprint_is_not_an_answer_and_lists_both(tmp_path, monkeypatch, capsys):
    blob, file_offset, rva = in_container("macho", NEW_TEXT_WORDS)
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")
    elsewhere = rva + 8                                                    # aligned, executable, not the function
    report = tmp_path / "relocate_conflict.json"

    code, out, _err = run(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--name", NAME,
                          "--new-metadata", metadata(tmp_path, elsewhere), "--json", str(report))

    assert code == 1
    assert "NEW FILE OFFSET" not in out and "The name and the byte fingerprint disagree" in out
    assert f"candidate file offset: 0x{elsewhere:x}" in out and f"candidate file offset: 0x{file_offset:x}" in out
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["result"] == "ambiguous"                                   # verify_offset.py settles it by running both
    by_via = {c["via"]: c for c in data["candidates"]}
    assert set(by_via) == {"name", "fingerprint"}
    assert by_via["name"]["file_offset"] == hex(elsewhere) and by_via["name"]["confidence"] == "MEDIUM"
    assert by_via["fingerprint"]["file_offset"] == hex(file_offset) and by_via["fingerprint"]["confidence"] in ("MEDIUM", "LOW")
    assert f"the name {NAME} says file offset 0x{elsewhere:x} instead" in by_via["fingerprint"]["note"]
    assert data["name"]["how"] == "conflict"


# ---------------------------------------------------------------------------
# name only (no old build)
# ---------------------------------------------------------------------------

def test_a_name_alone_is_enough_and_says_nothing_was_compared(tmp_path, monkeypatch, capsys):
    blob, file_offset, rva = in_container("elf", NEW_TEXT_WORDS)
    new = write_blob(tmp_path, blob, "new.bin")
    report = tmp_path / "relocate_only.json"

    code, out, _err = run(monkeypatch, capsys, new, "--name", NAME, "--new-metadata", metadata(tmp_path, rva),
                          "--json", str(report))

    assert code == 0
    assert f"NEW FILE OFFSET: 0x{file_offset:x}  (confidence: MEDIUM, found by name)" in out
    assert f"NEW RVA: 0x{rva:x}" in out and "no OLD_BINARY was given" in out
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["old"] is None and data["mode"] == "name" and data["candidates"][0]["via"] == "name"


def test_a_name_alone_that_the_dump_does_not_have_fails_with_exit_1(tmp_path, monkeypatch, capsys):
    blob, _fo, rva = in_container("macho", NEW_TEXT_WORDS)
    new = write_blob(tmp_path, blob, "new.bin")
    report = tmp_path / "relocate_none.json"

    code, out, _err = run(monkeypatch, capsys, new, "--name", "ExampleNamespace.Missing::Nope",
                          "--new-metadata", metadata(tmp_path, rva), "--json", str(report))

    assert code == 1 and "By name:" in out and "not in the metadata dump" in out and "NEW FILE OFFSET" not in out
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["result"] == "none" and data["candidates"] == []
    assert data["name"]["found"] is False and "not in the metadata dump" in data["name"]["failure"]


# ---------------------------------------------------------------------------
# a name the dump cannot settle, or the binary does not fit: fall back to the bytes
# ---------------------------------------------------------------------------

def test_a_name_missing_from_the_dump_falls_back_to_the_fingerprint(tmp_path, monkeypatch, capsys):
    blob, file_offset, rva = in_container("macho", NEW_TEXT_WORDS)
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")
    report = tmp_path / "relocate_fallback.json"

    code, out, _err = run(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--name", "ExampleNamespace.Missing::Nope",
                          "--new-metadata", metadata(tmp_path, rva), "--json", str(report))

    assert code == 0
    assert "By name:" in out and "Falling back to the byte fingerprint" in out
    assert f"NEW FILE OFFSET: 0x{file_offset:x}" in out and "found by name" not in out
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["candidates"][0]["via"] == "fingerprint"
    assert data["name"]["found"] is False and data["name"]["how"] == "failed"       # the failed attempt is on record


def test_two_overloads_without_a_count_fall_back_and_say_how_to_settle_it(tmp_path, monkeypatch, capsys):
    blob, file_offset, rva = in_container("macho", NEW_TEXT_WORDS)
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")
    meta = metadata(tmp_path, rva, extra=f"{SYMBOL} 0x{rva + 8:x}\n")           # the same name at a second address

    code, out, _err = run(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--name", "ExampleNamespace.ExampleTableA::Unpack",
                          "--new-metadata", meta)

    assert code == 0 and "2 different methods answer to it" in out and f"NEW FILE OFFSET: 0x{file_offset:x}" in out


def raw_dump_binary(tmp_path):
    return write_blob(tmp_path, pack(NEW_TEXT_WORDS), "raw.bin")


def test_a_raw_blob_cannot_place_an_rva_so_the_name_cannot_be_used(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = raw_dump_binary(tmp_path)
    code, out, _err = run(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--name", NAME,
                          "--new-metadata", metadata(tmp_path, HOOK_OFFSET_IN_NEW_TEXT))
    assert "no loadable segment" in out and "a raw blob" in out
    assert code == 0 and "Falling back" in out and f"NEW FILE OFFSET: 0x{HOOK_OFFSET_IN_NEW_TEXT:x}" in out


def test_an_rva_in_no_segment_is_refused_as_not_of_this_build(tmp_path, monkeypatch, capsys):
    blob, _fo, _rva = in_container("macho", NEW_TEXT_WORDS)
    new = write_blob(tmp_path, blob, "new.bin")
    code, out, _err = run(monkeypatch, capsys, new, "--name", NAME, "--new-metadata", metadata(tmp_path, 0x7000000))
    assert code == 1 and "no loadable segment" in out and "Is the dump of this build?" in out


def test_a_misaligned_rva_cannot_be_aarch64_code(tmp_path, monkeypatch, capsys):
    blob, _fo, rva = in_container("macho", NEW_TEXT_WORDS)
    new = write_blob(tmp_path, blob, "new.bin")
    code, out, _err = run(monkeypatch, capsys, new, "--name", NAME, "--new-metadata", metadata(tmp_path, rva + 2))
    assert code == 1 and "is not 4-byte aligned" in out and "the dump is not of this build" in out


def test_an_rva_in_a_data_section_is_not_code(tmp_path, monkeypatch, capsys):
    blob, lay = build_macho([("__TEXT", 5, [("__text", CODE, pack(NEW_TEXT_WORDS))]),
                             ("__DATA", 3, [("__data", NOT_CODE, bytes(64))])])
    new = write_blob(tmp_path, blob, "new.bin")
    in_data = lay["__DATA,__data"][0] + 8
    code, out, _err = run(monkeypatch, capsys, new, "--name", NAME, "--new-metadata", metadata(tmp_path, in_data))
    assert code == 1 and "is not in executable code" in out and "probably of another build" in out


# ---------------------------------------------------------------------------
# an instruction set the fingerprint cannot handle: the name still can
# ---------------------------------------------------------------------------

def test_against_an_x86_64_binary_only_the_name_is_used_and_the_cross_check_says_why_it_did_not_run(tmp_path, monkeypatch, capsys):
    blob, [(start, _end)] = build_elf64([(1, 5, pack(NEW_TEXT_WORDS))], machine=62)
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")
    at = start + 6                                                         # x86 instructions are not 4-byte aligned

    code, out, _err = run(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--name", NAME, "--new-metadata", metadata(tmp_path, at))

    assert code == 0
    assert f"NEW FILE OFFSET: 0x{at:x}  (confidence: MEDIUM, found by name)" in out
    assert "the byte cross-check could not run" in out and "not AArch64" in out
    assert "[pass] alignment" not in out                                   # no AArch64 rule applied to x86 code


# ---------------------------------------------------------------------------
# usage
# ---------------------------------------------------------------------------

def test_name_without_metadata_is_a_usage_error(tmp_path, monkeypatch, capsys):
    new = write_blob(tmp_path, pack(NEW_TEXT_WORDS), "new.bin")
    code, _out, err = run(monkeypatch, capsys, new, "--name", NAME)
    assert code == 2 and "--name needs --new-metadata" in err


def test_metadata_without_name_is_a_usage_error(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, pack(NEW_TEXT_WORDS), "new.bin")
    code, _out, err = run(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--new-metadata", metadata(tmp_path, 0x40))
    assert code == 2 and "--new-metadata is only used with --name" in err


@pytest.mark.parametrize("argv", [[], ["a.bin"], ["a.bin", "0x10"], ["a.bin", "0x10", "b.bin", "c.bin"]])
def test_the_wrong_number_of_positionals_is_a_usage_error(tmp_path, monkeypatch, capsys, argv):
    code, _out, err = run(monkeypatch, capsys, *argv)
    assert code == 2 and "expected OLD_BINARY OLD_OFFSET_HEX NEW_BINARY" in err


def test_a_bad_old_offset_is_still_a_usage_error(tmp_path, monkeypatch, capsys):
    code, _out, err = run(monkeypatch, capsys, "a.bin", "not-hex", "b.bin")
    assert code == 2 and "OLD_OFFSET_HEX" in err


@pytest.mark.parametrize("name, why", [("Unpack", "is not Namespace.Class::Method"),
                                       ("ExampleNamespace.A::Unpack/x", "parameter count")])
def test_a_malformed_name_is_one_error_line_and_exit_2(tmp_path, monkeypatch, capsys, name, why):
    new = write_blob(tmp_path, pack(NEW_TEXT_WORDS), "new.bin")
    code, _out, err = run(monkeypatch, capsys, new, "--name", name, "--new-metadata", metadata(tmp_path, 0x40))
    assert code == 2 and err.startswith("[!] --name") and why in err and "Traceback" not in err


def test_an_unreadable_dump_is_one_error_line_and_exit_2(tmp_path, monkeypatch, capsys):
    new = write_blob(tmp_path, pack(NEW_TEXT_WORDS), "new.bin")
    bad = tmp_path / "bad.txt"
    bad.write_text("just words\n", encoding="utf-8")
    code, _out, err = run(monkeypatch, capsys, new, "--name", NAME, "--new-metadata", str(bad))
    assert code == 2 and err.startswith("[!]") and "expected `NAME ADDRESS`" in err
    code, _out, err = run(monkeypatch, capsys, new, "--name", NAME, "--new-metadata", str(tmp_path / "missing.txt"))
    assert code == 2 and "missing.txt" in err


def test_without_name_nothing_about_the_old_behaviour_changed(tmp_path, monkeypatch, capsys):
    blob, file_offset, _rva = in_container("macho", NEW_TEXT_WORDS)
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")
    report = tmp_path / "relocate_plain.json"
    code, out, _err = run(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--json", str(report))
    assert code == 0 and f"NEW FILE OFFSET: 0x{file_offset:x}" in out and "found by name" not in out
    assert "name" not in json.loads(report.read_text(encoding="utf-8"))
