"""
Tests for the end of retk relocate that the next tool reads: the FILE offset
converted to an RVA (what a profile's `offsets` entry takes), and the --json report.

The conversion reads the container's own headers - a thin Mach-O's segments, the arm64
slice of a fat Mach-O, an ELF's PT_LOAD segments - so the fixtures here are built with real
segment tables where the file offset and the RVA DIFFER (a __DATA segment mapped further
away than it sits in the file, a second PT_LOAD with its own p_vaddr): a converter that just
returned the file offset would pass the thin-Mach-O test only by accident, and these are the
cases that fail it. Where the answer cannot be told (a raw blob, an offset inside no loadable
segment, a slice that is not arm64) it is None, never 0.

The report is what retk verify reads: every accepted candidate - an ambiguous
result lists all of them, so it can be settled by running them - with its RVA, or null when
the container cannot convert it.

Run from the repo root:

    pytest
"""
import json
import struct

import pytest

from retk import relocate_offset as ro
from binfmt_fixtures import CODE, CPU_ARM64, CPU_X86_64, build_elf64, build_fat, build_macho
from test_relocate_offset import (HOOK_OFFSET_IN_NEW_TEXT, NEW_TEXT_WORDS, NOP, OLD_OFFSET, OLD_WORDS, RET,
                                  SAFE_RUN, pack, run_main, write_bin, write_blob)

TEXT_VM = 0x100000000


def macho_with_data(text_size=0x4000, data_gap=0x4000, data_size=0x1000):
    """A thin Mach-O with __TEXT at file offset 0 and a __DATA segment that sits right after
    it in the FILE but is mapped `data_gap` further on: file offset 0x4010 is RVA 0x8010."""
    def seg(name, vmaddr, vmsize, fileoff, filesize, prot):
        return (struct.pack("<II", 0x19, 72) + name.encode().ljust(16, b"\0")
                + struct.pack("<QQQQiiII", vmaddr, vmsize, fileoff, filesize, prot, prot, 0, 0))

    cmds = (seg("__PAGEZERO", 0, TEXT_VM, 0, 0, 0)
            + seg("__TEXT", TEXT_VM, text_size, 0, text_size, 5)
            + seg("__DATA", TEXT_VM + text_size + data_gap, data_size, text_size, data_size, 3))
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, CPU_ARM64, 0, 2, 3, len(cmds), 0, 0)
    blob = header + cmds
    return blob + b"\0" * (text_size + data_size - len(blob))


def elf_with_two_loads():
    """PT_LOAD #0: file 0x0..0x1000 at vaddr 0x0 (r-x); PT_LOAD #1: file 0x1000..0x2000 at vaddr
    0x3000 (rw-): file offset 0x1010 is RVA 0x3010."""
    loads = [(1, 5, 0x0, 0x0, 0x1000), (1, 6, 0x1000, 0x3000, 0x1000)]
    phdrs = b"".join(struct.pack("<IIQQQQQQ", t, f, off, va, va, sz, sz, 0x1000) for t, f, off, va, sz in loads)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0, 64, 0, 0, 64, 56, len(loads), 64, 0, 0)
    blob = ehdr + phdrs
    return blob + b"\0" * (0x2000 - len(blob))


# ---------------------------------------------------------------------------
# file_offset_to_rva
# ---------------------------------------------------------------------------

def test_in_a_thin_macho_code_offset_and_rva_coincide_but_data_does_not():
    blob = macho_with_data()
    assert ro.file_offset_to_rva(blob, 0x1230) == 0x1230          # __TEXT starts at file offset 0
    assert ro.file_offset_to_rva(blob, 0x4010) == 0x8010          # __DATA: mapped 0x4000 further on


def test_a_macho_whose_text_does_not_start_at_the_header_is_still_converted_relative_to_the_header():
    # The builders' own layout: __TEXT begins after the header, so vmaddr - fileoff is the header's address.
    blob, lay = build_macho([("__TEXT", 5, [("__text", CODE, pack([NOP] * 8))])])
    start = lay["__TEXT,__text"][0]
    assert ro.file_offset_to_rva(blob, start + 8) == start + 8


def test_an_offset_inside_no_segment_has_no_rva():
    blob = macho_with_data()
    assert ro.file_offset_to_rva(blob, 0x4000 + 0x1000 + 8) is None    # past the last segment
    assert ro.file_offset_to_rva(blob, 10**9) is None


def test_in_a_fat_macho_the_rva_is_relative_to_the_arm64_slice():
    thin = macho_with_data()
    blob, (arm_at, x86_at) = build_fat([(CPU_ARM64, thin), (CPU_X86_64, thin)])
    assert arm_at != 0
    assert ro.file_offset_to_rva(blob, arm_at + 0x1230) == 0x1230
    assert ro.file_offset_to_rva(blob, arm_at + 0x4010) == 0x8010
    assert ro.file_offset_to_rva(blob, x86_at + 0x1230) is None        # not an arm64 slice: not ours to convert
    assert ro.file_offset_to_rva(blob, 4) is None                      # the fat header itself


def test_with_two_arm64_slices_the_offset_is_converted_by_the_slice_that_holds_it():
    # arm64 and arm64e share a cputype; the first slice must not claim an offset that lies in the second.
    first, second = macho_with_data(data_gap=0x4000), macho_with_data(data_gap=0x8000)
    blob, (at1, at2) = build_fat([(CPU_ARM64, first), (CPU_ARM64, second)])
    assert ro.file_offset_to_rva(blob, at1 + 0x4010) == 0x8010
    assert ro.file_offset_to_rva(blob, at2 + 0x4010) == 0xC010
    assert ro.file_offset_to_rva(blob, at2 - 4) is None                 # padding between the slices


def test_in_an_elf_the_rva_comes_from_the_pt_load_that_holds_the_offset():
    blob = elf_with_two_loads()
    assert ro.file_offset_to_rva(blob, 0x0F00) == 0x0F00
    assert ro.file_offset_to_rva(blob, 0x1010) == 0x3010
    assert ro.file_offset_to_rva(blob, 0x2000) is None                 # one past the last segment


def test_an_elf_whose_first_load_is_not_at_vaddr_zero_is_relative_to_its_lowest_page():
    # build_elf64 maps its single segment at 0x400000 + file offset: the module base is 0x400000.
    blob, [(start, _end)] = build_elf64([(1, 5, pack([NOP] * 8))])
    assert ro.file_offset_to_rva(blob, start + 8) == start + 8


@pytest.mark.parametrize("blob", [b"", b"\0" * 64, pack([NOP] * 16), b"\x7fELF", b"\xfe\xed\xfa\xcf" + b"\0" * 8])
def test_a_raw_blob_or_a_truncated_container_has_no_rva_not_zero(blob):
    assert ro.file_offset_to_rva(blob, 8) is None


def test_a_32_bit_or_big_endian_elf_is_not_converted():
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 60
    assert ro.file_offset_to_rva(ident, 8) is None


def test_rva_of_reads_a_file_and_says_none_for_one_it_cannot_map(tmp_path):
    path = tmp_path / "m.bin"
    path.write_bytes(macho_with_data())
    assert ro.rva_of(str(path), 0x4010) == 0x8010
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert ro.rva_of(str(empty), 0) is None
    assert ro.rva_of(str(tmp_path / "missing.bin"), 0) is None


# ---------------------------------------------------------------------------
# main(): the NEW RVA line
# ---------------------------------------------------------------------------

def in_container(kind, words):
    """The relocated code in each kind of container -> (blob, FILE offset of the hook point, expected RVA)."""
    if kind == "macho":
        blob, lay = build_macho([("__TEXT", 5, [("__text", CODE, pack(words))])])
        at = lay["__TEXT,__text"][0] + HOOK_OFFSET_IN_NEW_TEXT
        return blob, at, at
    if kind == "fat":
        thin, lay = build_macho([("__TEXT", 5, [("__text", CODE, pack(words))])])
        blob, [slice_at] = build_fat([(CPU_ARM64, thin)])
        text_at = lay["__TEXT,__text"][0] + HOOK_OFFSET_IN_NEW_TEXT
        return blob, slice_at + text_at, text_at              # NOT the file offset: the slice's offset is gone
    blob, [(start, _end)] = build_elf64([(1, 5, pack(words))])
    at = start + HOOK_OFFSET_IN_NEW_TEXT
    return blob, at, at


@pytest.mark.parametrize("kind", ["macho", "fat", "elf"])
def test_the_result_prints_the_rva_as_well_as_the_file_offset(tmp_path, monkeypatch, capsys, kind):
    blob, file_offset, rva = in_container(kind, NEW_TEXT_WORDS)
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")

    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new)

    assert code == 0
    assert f"NEW FILE OFFSET: 0x{file_offset:x}" in out
    assert f"NEW RVA: 0x{rva:x}" in out
    assert (file_offset != rva) == (kind == "fat")
    assert out.index("NEW FILE OFFSET") < out.index("NEW RVA")


def test_a_raw_blob_has_no_rva_line_and_says_why(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, pack(NEW_TEXT_WORDS), "new.bin")
    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new)
    assert code == 0 and "NEW RVA" not in out and "Unrecognised container" in out


# ---------------------------------------------------------------------------
# main(): --json
# ---------------------------------------------------------------------------

def read_report(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_a_unique_result_is_written_with_its_rva_and_the_evidence(tmp_path, monkeypatch, capsys):
    blob, file_offset, rva = in_container("fat", NEW_TEXT_WORDS)
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")
    report_path = tmp_path / "relocate_test.json"

    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--json", str(report_path))

    assert code == 0 and "Wrote" in out
    report = read_report(report_path)
    assert report["version"] == 1 and report["result"] == "unique"
    assert report["old"] == {"binary": old, "file_offset": hex(OLD_OFFSET)}
    assert report["new"] == {"binary": new} and report["mode"] in ("after", "before")
    [cand] = report["candidates"]
    assert (cand["file_offset"], cand["rva"]) == (hex(file_offset), hex(rva))
    assert cand["confidence"] in ("HIGH", "MEDIUM", "LOW") and cand["via"] == "fingerprint"
    assert any(c["name"] == "executable-section" and c["status"] == "pass" for c in cand["checks"])
    assert report["rejected"] == [] and report["outvoted"] == []


def test_an_unconvertible_container_gives_a_null_rva_not_a_guess(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, pack(NEW_TEXT_WORDS), "new.bin")
    report_path = tmp_path / "relocate_raw.json"
    run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--json", str(report_path))
    [cand] = read_report(report_path)["candidates"]
    assert cand["file_offset"] == hex(HOOK_OFFSET_IN_NEW_TEXT) and cand["rva"] is None


def test_an_ambiguous_result_lists_every_candidate_so_they_can_be_run(tmp_path, monkeypatch, capsys):
    # The safe run appears twice in the new build, and nothing but the app can say which one it calls.
    words = OLD_WORDS + [NOP] + SAFE_RUN + [RET]
    blob, lay = build_macho([("__TEXT", 5, [("__text", CODE, pack(words))])])
    start = lay["__TEXT,__text"][0]
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")
    report_path = tmp_path / "relocate_ambiguous.json"

    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--anchors", "none", "--json", str(report_path))

    assert code == 1 and "More than one match" in out and "retk verify" in out
    report = read_report(report_path)
    assert report["result"] == "ambiguous"
    second = start + (len(OLD_WORDS) + 1 + len(SAFE_RUN)) * 4
    assert [c["file_offset"] for c in report["candidates"]] == [hex(start + OLD_OFFSET), hex(second)]
    assert [c["rva"] for c in report["candidates"]] == [hex(start + OLD_OFFSET), hex(second)]    # thin Mach-O
    assert f"RVA 0x{second:x}" in out


def test_no_match_is_written_as_none_with_no_candidates(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, pack([NOP] * 16), "new.bin")
    report_path = tmp_path / "relocate_none.json"

    code, _out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--json", str(report_path))

    assert code == 1
    assert read_report(report_path)["result"] == "none" and read_report(report_path)["candidates"] == []


def test_candidates_rejected_as_not_code_are_reported_but_are_not_candidates(tmp_path, monkeypatch, capsys):
    # The code sits in a section that is not executable: every byte match is rejected.
    blob, _lay = build_macho([("__TEXT", 5, [("__text", CODE, pack([NOP] * 4))]),
                              ("__DATA", 3, [("__data", 0, pack(NEW_TEXT_WORDS))])])
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")
    report_path = tmp_path / "relocate_rejected.json"

    code, _out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--json", str(report_path))

    report = read_report(report_path)
    assert code == 1 and report["result"] == "none" and report["candidates"] == []
    assert report["rejected"] and "executable" in report["rejected"][0]["reasons"][0]


def test_without_json_nothing_is_written(tmp_path, monkeypatch, capsys):
    blob, _fo, _rva = in_container("macho", NEW_TEXT_WORDS)
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")
    monkeypatch.chdir(tmp_path)
    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new)
    assert code == 0 and "Wrote" not in out and not list(tmp_path.glob("*.json"))
