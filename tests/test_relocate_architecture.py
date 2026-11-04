"""
Tests for relocate_offset's architecture guard.

A fingerprint is made of AArch64 instruction words, so it means something only in
a binary whose code is AArch64. Handed an x86-64 ELF, a 32-bit ARM ELF, a Mach-O
with no arm64 slice or an x86-64 PE, the tool used to search it anyway for byte
patterns that are not instructions there, and report whatever matched. It now
refuses, naming what it found - for either of the two binaries - while every
AArch64 container (and a raw blob, which can't be told) is let through exactly as
before. This is a guard, not support for other architectures.

Run from the repo root:

    pytest
"""
import sys

import pytest

from retk import relocate_offset as ro
from binfmt_fixtures import (CODE, CPU_ARM64, CPU_X86_64, build_elf32, build_elf64, build_fat,
                             build_macho, build_pe)
from test_relocate_offset import OLD_OFFSET, OLD_WORDS, pack, write_bin


def write_blob(tmp_path, blob, name):
    path = tmp_path / name
    path.write_bytes(blob)
    return str(path)


def macho(cputype):
    blob, _ = build_macho([("__TEXT", 5, [("__text", CODE, pack(OLD_WORDS))])], cputype)
    return blob


# What each container is detected as: (name, builder, container text, arch text, is_aarch64).
CASES = {
    "arm64 mach-o": (lambda: macho(CPU_ARM64), "Mach-O", "arm64", True),
    "x86_64 mach-o": (lambda: macho(CPU_X86_64), "Mach-O", "x86_64", False),
    "fat with an arm64 slice": (lambda: build_fat([(CPU_X86_64, macho(CPU_X86_64)), (CPU_ARM64, macho(CPU_ARM64))])[0],
                                "fat Mach-O", "arm64", True),
    "fat without one": (lambda: build_fat([(CPU_X86_64, macho(CPU_X86_64))])[0], "fat Mach-O", "x86_64", False),
    "aarch64 elf": (lambda: build_elf64([(1, 5, pack(OLD_WORDS))])[0], "64-bit little-endian ELF", "AArch64", True),
    "x86-64 elf": (lambda: build_elf64([(1, 5, pack(OLD_WORDS))], machine=62)[0],
                   "64-bit little-endian ELF", "x86-64", False),
    "32-bit arm elf": (lambda: build_elf32(40), "32-bit little-endian ELF", "32-bit ARM", False),
    "big-endian elf": (lambda: build_elf32(40, big_endian=True), "32-bit big-endian ELF", "32-bit ARM", False),
    "arm64 pe": (lambda: build_pe(0xAA64), "PE", "ARM64", True),
    "x86-64 pe": (lambda: build_pe(0x8664), "PE", "x86-64", False),
    "x86 pe": (lambda: build_pe(0x14C), "PE", "x86 (32-bit)", False),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_detect_architecture_names_what_it_found(case):
    build, container, arch, aarch64 = CASES[case]
    found_container, archs, is_aarch64 = ro.detect_architecture(build())
    assert (found_container, is_aarch64) == (container, aarch64)
    assert arch in archs


@pytest.mark.parametrize("blob", [
    pack(OLD_WORDS),                                         # a raw blob of code
    b"",
    b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 64,        # a Java class file shares the fat magic
    b"MZ" + b"\0" * 100,                                     # DOS header, no PE signature
    b"\x7fELF\x09\x01",                                      # nonsense class byte
    b"\x7fELF\x02\x01",                                      # truncated
    b"\xcf\xfa\xed\xfe",                                     # truncated Mach-O
])
def test_what_is_not_a_recognised_container_cannot_be_told(blob):
    assert ro.detect_architecture(blob) is None


def test_the_fat_header_is_read_in_the_64_bit_form_too():
    import struct
    thin = macho(CPU_ARM64)
    blob = struct.pack(">IIiiQQII", 0xCAFEBABF, 1, CPU_ARM64, 0, 0x4000, len(thin), 14, 0) + b"\0" * 0x4000
    assert ro.detect_architecture(blob) == ("fat Mach-O", ["arm64"], True)


# --- main() ------------------------------------------------------------------

def run(monkeypatch, capsys, old, new):
    monkeypatch.setattr(sys, "argv", ["relocate_offset.py", old, hex(OLD_OFFSET), new])
    try:
        ro.main()
        code = 0
    except SystemExit as e:
        code = e.code
    cap = capsys.readouterr()
    return code, cap.out, cap.err


@pytest.mark.parametrize("case", [c for c in sorted(CASES) if not CASES[c][3]])
def test_a_new_build_that_is_not_aarch64_is_refused_with_the_reason(tmp_path, monkeypatch, capsys, case):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, CASES[case][0](), "new.bin")

    code, out, err = run(monkeypatch, capsys, old, new)

    assert code == 2 and "Traceback" not in err
    assert "the new binary" in err and CASES[case][1] in err and CASES[case][2] in err
    assert "not AArch64" in err and "Ghidra" in err
    assert "Matches found" not in out                  # nothing was searched


def test_an_old_build_that_is_not_aarch64_is_refused_and_named_as_the_old_one(tmp_path, monkeypatch, capsys):
    # A port from one platform to another: the offset in the old binary means nothing either.
    old = write_blob(tmp_path, CASES["x86-64 elf"][0](), "old.bin")
    new = write_bin(tmp_path, OLD_WORDS, "new.bin")
    code, _out, err = run(monkeypatch, capsys, old, new)
    assert code == 2 and "the old binary" in err and "x86-64" in err


@pytest.mark.parametrize("case", [c for c in sorted(CASES) if CASES[c][3]])
def test_every_aarch64_container_is_still_accepted(tmp_path, monkeypatch, capsys, case):
    blob = CASES[case][0]()
    old = write_blob(tmp_path, blob, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")
    ro.check_architecture(old, "old")                  # the guard itself lets it through
    ro.check_architecture(new, "new")


def test_a_raw_blob_is_let_through_as_before(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_bin(tmp_path, OLD_WORDS, "new.bin")
    code, out, _err = run(monkeypatch, capsys, old, new)
    assert code == 0 and "NEW FILE OFFSET: 0x%x" % OLD_OFFSET in out


def test_a_missing_file_is_still_the_usual_error(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    code, _out, err = run(monkeypatch, capsys, old, str(tmp_path / "nope.bin"))
    assert code == 2 and "nope.bin" in err
