"""
The build id of a binary: the Mach-O UUID or the ELF GNU build-id.

retk/buildid.py reads it from a FILE, scripts/_buildid.js from a module LOADED in the target, and the build
cache is only as good as the two agreeing - a key the driver computes from a file has to be the key the agent
reports from memory. So both are run over the same synthetic images here (a Mach-O with LC_UUID, an ELF64 with
a GNU note, placed at an address of the fake process), and over damaged ones, which must be "no build id", not a
crash and not a guess. The Node-backed tests skip when `node` is not installed (and fail instead under $CI).

Run from the repo root:

    pytest tests/test_buildid.py
"""
import shutil
import struct
import subprocess
import uuid

import pytest

from retk import buildid
from node_support import run_harness

UUID = "6f1a2b3c-4d5e-4f60-8a7b-8c9d0e1f2a3b"
BUILD_ID = "8e9fd827446c24067541ac5390e6f527fb5947bb"


def macho(uuid_text=UUID, extra=True, ncmds=None, cputype=0x0100000C):
    """A 64-bit little-endian Mach-O header with load commands (UUID in the middle, like a real one)."""
    cmds = b""
    count = 0
    if extra:
        cmds += struct.pack("<II", 0x19, 72) + b"\0" * 64          # LC_SEGMENT_64, zeroed
        count += 1
    cmds += struct.pack("<II", 0x1B, 24) + uuid.UUID(uuid_text).bytes
    count += 1
    if extra:
        cmds += struct.pack("<II", 0x32, 24) + b"\0" * 16          # LC_BUILD_VERSION
        count += 1
    head = struct.pack("<IIIIIIII", 0xFEEDFACF, cputype, 0, 6, ncmds if ncmds is not None else count, len(cmds), 0, 0)
    return head + cmds + b"\0" * 64


def fat(slices):
    """A fat binary holding [(cputype, bytes)]."""
    entries, body, offset = b"", b"", 8 + 20 * len(slices)
    for cputype, data in slices:
        pad = -offset % 16384
        entries += struct.pack(">IIIII", cputype, 0, offset + pad, len(data), 14)
        body += b"\0" * pad + data
        offset += pad + len(data)
    return struct.pack(">II", 0xCAFEBABE, len(slices)) + entries + body


def elf(build_id=BUILD_ID, lowest_vaddr=0, abi_tag_first=True, with_note=True, ei_class=2):
    """An ELF64 whose PT_LOAD maps the whole file at `lowest_vaddr` and whose PT_NOTE holds the GNU notes."""
    notes = b""
    if abi_tag_first:                                              # NT_GNU_ABI_TAG, 16 bytes of desc
        notes += struct.pack("<III", 4, 16, 1) + b"GNU\0" + b"\0" * 16
    if with_note:
        notes += struct.pack("<III", 4, len(build_id) // 2, 3) + b"GNU\0" + bytes.fromhex(build_id)
    note_off = 64 + 2 * 56
    total = note_off + len(notes)
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, lowest_vaddr, lowest_vaddr, total, total, 0x1000)
    note = struct.pack("<IIQQQQQQ", 4, 4, note_off, lowest_vaddr + note_off, lowest_vaddr + note_off, len(notes), len(notes), 4)
    ident = b"\x7fELF" + bytes([ei_class, 1, 1, 0]) + b"\0" * 8
    header = ident + struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    return header + load + note + notes


def js_build(node_scripts, image, base=0):
    return run_harness(node_scripts, image, mode="buildId", base=base)["build"]


def placed(data, base):
    """`data` at address `base` of a fake process whose other bytes are 0xEE garbage."""
    return b"\xee" * base + data + b"\xee" * 256


CASES = {
    "mach-o": (macho(), buildid.BuildId(buildid.KIND_MACHO, UUID)),
    "mach-o with the UUID first": (macho(extra=False), buildid.BuildId(buildid.KIND_MACHO, UUID)),
    "elf": (elf(), buildid.BuildId(buildid.KIND_ELF, BUILD_ID)),
    "elf, build-id note first": (elf(abi_tag_first=False), buildid.BuildId(buildid.KIND_ELF, BUILD_ID)),
    "elf loaded at a non-zero address": (elf(lowest_vaddr=0x4000), buildid.BuildId(buildid.KIND_ELF, BUILD_ID)),
    "a 20-byte sha1 vs a 16-byte md5 build-id": (elf("ab" * 16), buildid.BuildId(buildid.KIND_ELF, "ab" * 16)),
}

NOTHING = {
    "random bytes": b"\xee" * 512,
    "empty": b"",
    "a 32-bit ELF": elf(ei_class=1),
    "an ELF with no build-id note": elf(with_note=False),
    "a Mach-O without LC_UUID": macho()[:32] + struct.pack("<II", 0x32, 24) + b"\0" * 16 + b"\0" * 64,
    "a Mach-O claiming a million load commands": macho(ncmds=1_000_000),
    "a truncated Mach-O header": macho()[:20],
    "a truncated ELF": elf()[:90],
    "a PE": b"MZ" + b"\0" * 126 + b"PE\0\0" + b"\0" * 200,
    "a fat binary with no arm64 slice": fat([(7, macho())]),
}


# --- the file reader ---

@pytest.mark.parametrize("name", CASES)
def test_the_file_reader_finds_the_id(name):
    data, expected = CASES[name]
    assert buildid.from_bytes(data) == expected


@pytest.mark.parametrize("name", NOTHING)
def test_the_file_reader_says_none_for_what_has_no_id(name):
    assert buildid.from_bytes(NOTHING[name]) is None


def test_a_fat_binary_is_read_at_its_arm64_slice():
    other = macho("11111111-2222-4333-8444-555555555555", cputype=0x01000007)
    mine = macho()
    assert buildid.from_bytes(fat([(0x01000007, other), (0x0100000C, mine)])) == buildid.BuildId(buildid.KIND_MACHO, UUID)


def test_text_and_filename_are_what_the_cache_and_the_agent_use():
    b = buildid.BuildId(buildid.KIND_ELF, BUILD_ID)
    assert b.text == f"gnu-build-id:{BUILD_ID}"
    assert b.filename == f"gnu-build-id_{BUILD_ID}" and ":" not in b.filename      # Windows file names


@pytest.mark.parametrize("kind, ident, ok", [
    (buildid.KIND_MACHO, UUID, True),
    (buildid.KIND_MACHO, UUID.upper(), False),
    (buildid.KIND_MACHO, "../../etc/passwd", False),
    (buildid.KIND_ELF, BUILD_ID, True),
    (buildid.KIND_ELF, "xyz", False),
    (buildid.KIND_ELF, "", False),
    ("pe-guid", "ab", False),
])
def test_only_well_formed_ids_are_valid(kind, ident, ok):
    assert buildid.valid_id(kind, ident) is ok


@pytest.mark.skipif(not shutil.which("readelf"), reason="readelf (binutils) is not installed")
def test_the_file_reader_agrees_with_readelf_on_a_real_binary():
    path = shutil.which("ls")
    out = subprocess.run(["readelf", "-n", path], capture_output=True, text=True).stdout
    if "Build ID" not in out:
        pytest.skip("this ls has no build-id")
    wanted = out.split("Build ID:")[1].split()[0]
    assert buildid.from_file(path) == buildid.BuildId(buildid.KIND_ELF, wanted)


# --- the agent reader, held to the same answers ---

@pytest.mark.parametrize("base", [0, 0x3000])
@pytest.mark.parametrize("name", CASES)
def test_the_agent_reads_the_same_id_from_memory(node_scripts, name, base):
    data, expected = CASES[name]
    got = js_build(node_scripts, placed(data, base), base)
    assert got == {"kind": expected.kind, "id": expected.id}


@pytest.mark.parametrize("name", NOTHING)
def test_the_agent_says_null_for_what_has_no_id_and_does_not_throw(node_scripts, name):
    assert js_build(node_scripts, placed(NOTHING[name], 0)) is None


def test_the_agent_says_null_for_an_unreadable_address(node_scripts):
    assert js_build(node_scripts, b"\0" * 64, base=10_000_000) is None


def test_the_agent_reads_a_fat_slice_nowhere_because_a_loaded_module_is_one_slice(node_scripts):
    # a fat file is never in memory as such: dyld maps one slice, whose header is a thin Mach-O
    assert js_build(node_scripts, placed(fat([(0x0100000C, macho())]), 0)) is None
