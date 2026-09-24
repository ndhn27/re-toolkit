"""
Unit tests for tools/relocate_offset.py.

No device and no real binary needed: every fixture is a handful of AArch64
instruction words packed into a temp file (or just passed to capstone).

Encodings below were generated with keystone and re-checked against capstone;
`test_is_pc_relative_*` re-decode each word and assert the mnemonic, so a typo
in a table entry fails loudly instead of silently testing the wrong thing.

Run from the repo root:

    pip install capstone pytest
    pytest
"""
import struct
import sys

import pytest
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

import relocate_offset as ro
from binfmt_fixtures import (CODE, CPU_ARM64, CPU_X86_64, NOT_CODE, S_CSTRING_LITERALS,
                             build_elf64, build_fat, build_macho)

_MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# --------------------------------------------------------------------------
# Instruction words (little-endian uint32). Comments = what capstone prints.
# --------------------------------------------------------------------------

# PC-relative: the encoded immediate changes when the code moves.
ADRP = 0x90000020          # adrp x0, #0x5000
ADRP_MOVED = 0xB0000020    # adrp x0, <other page>  (same insn, different target)
ADR = 0x10000201           # adr  x1, #0x1040
BL = 0x94000400            # bl   #0x2000
BL_MOVED = 0x94000401      # bl   #0x2004
B = 0x14000040             # b    #0x1100
CBZ = 0xB4000200           # cbz  x0, #0x1040
CBNZ = 0x35000201          # cbnz w1, #0x1040
TBZ = 0x36180202           # tbz  w2, #3, #0x1040
TBNZ = 0xB7E00203          # tbnz x3, #0x3c, #0x1040
B_EQ = 0x54000200          # b.eq #0x1040
LDR_LIT_X = 0x58000200     # ldr  x0, #0x1040   (literal pool)
LDR_LIT_W = 0x18000200     # ldr  w0, #0x1040
LDRSW_LIT = 0x98000200     # ldrsw x0, #0x1040
LDR_LIT_D = 0x5C000200     # ldr  d0, #0x1040   (SIMD/FP literal)
LDR_LIT_Q = 0x9C000200     # ldr  q0, #0x1040
PRFM_LIT = 0xD8000200      # prfm pldl1keep, #0x1040

# Position-independent: safe to put in a fingerprint.
MOV_X = 0xAA0103E0         # mov  x0, x1
MOV_IMM = 0x52824680       # mov  w0, #0x1234
ADD = 0x91004000           # add  x0, x0, #0x10
SUB_SP = 0xD10083FF        # sub  sp, sp, #0x20
CMP = 0xF100001F           # cmp  x0, #0
NOP = 0xD503201F           # nop
RET = 0xD65F03C0           # ret
LDR_IMM = 0xF9400900       # ldr  x0, [x8, #0x10]
STR = 0xF9000900           # str  x0, [x8, #0x10]
LDR_REG = 0xF8697900       # ldr  x0, [x8, x9, lsl #3]
LDP = 0xA9417BFD           # ldp  x29, x30, [sp, #0x10]

SAFE4 = [MOV_X, ADD, SUB_SP, CMP]


def pack(words):
    return b"".join(struct.pack("<I", w) for w in words)


def write_bin(tmp_path, words, name="build.bin"):
    path = tmp_path / name
    path.write_bytes(pack(words))
    return str(path)


def decode(word, addr=0x1000):
    """Disassemble one word; None if capstone can't decode it."""
    return next(_MD.disasm(struct.pack("<I", word), addr), None)


def _first_undecodable():
    for w in (0xFFFFFFFF, 0xDEADBEEF, 0x00100000):
        if decode(w) is None:
            return w
    return None


# A word capstone refuses to decode (stands in for a literal pool / jump table
# entry sitting in the code). Tests that need it are skipped if a future
# capstone version happens to decode all of the candidates.
BAD = _first_undecodable()
needs_undecodable = pytest.mark.skipif(
    BAD is None, reason="this capstone version decodes every candidate 'bad' word")


# --------------------------------------------------------------------------
# is_pc_relative()
# --------------------------------------------------------------------------

PC_RELATIVE_CASES = [
    pytest.param(ADRP, "adrp", id="adrp"),
    pytest.param(ADR, "adr", id="adr"),
    pytest.param(BL, "bl", id="bl"),
    pytest.param(B, "b", id="b"),
    pytest.param(CBZ, "cbz", id="cbz"),
    pytest.param(CBNZ, "cbnz", id="cbnz"),
    pytest.param(TBZ, "tbz", id="tbz"),
    pytest.param(TBNZ, "tbnz", id="tbnz"),
    pytest.param(LDR_LIT_X, "ldr", id="ldr-literal-x"),
    pytest.param(LDR_LIT_W, "ldr", id="ldr-literal-w"),
    pytest.param(LDRSW_LIT, "ldrsw", id="ldrsw-literal"),
    pytest.param(LDR_LIT_D, "ldr", id="ldr-literal-simd-d"),
    pytest.param(LDR_LIT_Q, "ldr", id="ldr-literal-simd-q"),
    pytest.param(PRFM_LIT, "prfm", id="prfm-literal"),
]


@pytest.mark.parametrize("word, mnemonic", PC_RELATIVE_CASES)
def test_is_pc_relative_true(word, mnemonic):
    insn = decode(word)
    assert insn is not None and insn.mnemonic == mnemonic  # guards the table itself
    assert ro.is_pc_relative(insn)


@pytest.mark.parametrize("cond", range(16))
def test_is_pc_relative_true_for_every_conditional_branch(cond):
    insn = decode(B_EQ | cond)  # b.<cond>: eq, ne, hs, lo, ..., le, al, nv
    assert insn is not None and insn.mnemonic.startswith("b.")
    assert ro.is_pc_relative(insn)


NOT_PC_RELATIVE_CASES = [
    # Loads/stores through a base register: the "[" form of ldr must NOT be
    # confused with the literal-pool form.
    pytest.param(0xF9400100, "ldr", id="ldr-base"),                # ldr x0, [x8]
    pytest.param(LDR_IMM, "ldr", id="ldr-base-imm"),               # ldr x0, [x8, #0x10]
    pytest.param(0xB9400500, "ldr", id="ldr-w-base-imm"),          # ldr w0, [x8, #4]
    pytest.param(0xF8408500, "ldr", id="ldr-post-index"),          # ldr x0, [x8], #8
    pytest.param(0xF8408D00, "ldr", id="ldr-pre-index"),           # ldr x0, [x8, #8]!
    pytest.param(0xF8696900, "ldr", id="ldr-reg-offset"),          # ldr x0, [x8, x9]
    pytest.param(LDR_REG, "ldr", id="ldr-reg-offset-shifted"),     # ldr x0, [x8, x9, lsl #3]
    pytest.param(0xB9800500, "ldrsw", id="ldrsw-base-imm"),        # ldrsw x0, [x8, #4]
    pytest.param(0xF9800000, "prfm", id="prfm-base-imm"),          # prfm pldl1keep, [x0]
    pytest.param(0xF85F8100, "ldur", id="ldur"),                   # ldur x0, [x8, #-8]
    pytest.param(LDP, "ldp", id="ldp"),
    pytest.param(0xA9BF7BFD, "stp", id="stp-pre-index"),           # stp x29, x30, [sp, #-0x10]!
    pytest.param(STR, "str", id="str"),
    # Indirect branches start with "b" but jump through a register.
    pytest.param(0xD61F0200, "br", id="br"),                       # br x16
    pytest.param(0xD63F0100, "blr", id="blr"),                     # blr x8
    pytest.param(RET, "ret", id="ret"),
    # Plain ALU / misc.
    pytest.param(MOV_X, "mov", id="mov-reg"),
    pytest.param(MOV_IMM, "mov", id="mov-imm"),
    pytest.param(ADD, "add", id="add"),
    pytest.param(SUB_SP, "sub", id="sub-sp"),
    pytest.param(CMP, "cmp", id="cmp"),
    pytest.param(0x9A820020, "csel", id="csel"),
    pytest.param(0x1E6E1000, "fmov", id="fmov-imm"),
    pytest.param(NOP, "nop", id="nop"),
    pytest.param(0xD4001001, "svc", id="svc"),
]


@pytest.mark.parametrize("word, mnemonic", NOT_PC_RELATIVE_CASES)
def test_is_pc_relative_false(word, mnemonic):
    insn = decode(word)
    assert insn is not None and insn.mnemonic == mnemonic  # guards the table itself
    assert not ro.is_pc_relative(insn)


# --------------------------------------------------------------------------
# build_fingerprint()
# --------------------------------------------------------------------------

class TestBuildFingerprint:
    def test_returns_safe_run_right_before_offset(self, tmp_path, capsys):
        # idx: 0=bl 1..4=safe 5=nop(<- offset) 6=ret
        path = write_bin(tmp_path, [BL] + SAFE4 + [NOP, RET])
        fp = ro.build_fingerprint(path, 5 * 4, min_instrs=4)

        assert fp == pack(SAFE4)
        assert "4 instructions, 16 bytes, from 0x4 to 0x14" in capsys.readouterr().out

    @pytest.mark.parametrize("barrier", [
        pytest.param(ADRP, id="adrp"),
        pytest.param(ADR, id="adr"),
        pytest.param(BL, id="bl"),
        pytest.param(B, id="b"),
        pytest.param(CBZ, id="cbz"),
        pytest.param(CBNZ, id="cbnz"),
        pytest.param(TBZ, id="tbz"),
        pytest.param(TBNZ, id="tbnz"),
        pytest.param(B_EQ, id="b.eq"),
        pytest.param(LDR_LIT_X, id="ldr-literal"),
        pytest.param(LDRSW_LIT, id="ldrsw-literal"),
    ])
    def test_stops_at_pc_relative_instruction(self, tmp_path, barrier):
        # The two ADDs sit *before* the barrier: they'd be picked up if the
        # walk skipped the barrier instead of stopping at it.
        words = [ADD, ADD, barrier] + SAFE4 + [NOP]
        path = write_bin(tmp_path, words)

        fp = ro.build_fingerprint(path, 7 * 4, min_instrs=4)

        assert fp == pack(SAFE4)

    def test_base_register_loads_and_stores_are_not_barriers(self, tmp_path):
        run = [LDR_IMM, LDR_REG, LDP, STR]
        path = write_bin(tmp_path, [BL] + run + [NOP])

        assert ro.build_fingerprint(path, 5 * 4, min_instrs=4) == pack(run)

    def test_too_few_safe_instructions_raises(self, tmp_path):
        path = write_bin(tmp_path, [BL, MOV_X, ADD, SUB_SP, NOP])  # only 3 safe before idx 4

        with pytest.raises(RuntimeError, match="Only found 3"):
            ro.build_fingerprint(path, 4 * 4, min_instrs=4)

        # ...and the same input is fine once the threshold is lowered.
        assert ro.build_fingerprint(path, 4 * 4, min_instrs=3) == pack([MOV_X, ADD, SUB_SP])

    def test_pc_relative_right_before_offset_raises(self, tmp_path):
        path = write_bin(tmp_path, [ADD] * 4 + [BL, NOP])

        with pytest.raises(RuntimeError, match="Only found 0"):
            ro.build_fingerprint(path, 5 * 4, min_instrs=4)

    @pytest.mark.parametrize("word_at_offset", [
        pytest.param(BL, id="pc-relative-at-offset"),
        pytest.param(ADD, id="safe-at-offset"),
    ])
    def test_instruction_at_offset_is_not_part_of_fingerprint(self, tmp_path, word_at_offset):
        path = write_bin(tmp_path, SAFE4 + [word_at_offset, NOP])

        assert ro.build_fingerprint(path, 4 * 4, min_instrs=4) == pack(SAFE4)

    def test_offset_near_start_of_file(self, tmp_path, capsys):
        # old_offset (16) is smaller than the lookback window (64).
        path = write_bin(tmp_path, SAFE4 + [NOP, NOP])

        fp = ro.build_fingerprint(path, 4 * 4, min_instrs=4)

        assert fp == pack(SAFE4)
        assert "from 0x0 to 0x10" in capsys.readouterr().out

    def test_lookback_smaller_than_one_instruction_raises(self, tmp_path):
        path = write_bin(tmp_path, SAFE4 + [NOP])

        with pytest.raises(ro.RelocateError, match="increase lookback_window"):
            ro.build_fingerprint(path, 16, min_instrs=4, lookback_window=2)

    def test_offset_0_says_nothing_precedes_it_not_to_grow_the_lookback(self, tmp_path):
        # No lookback window can help an offset with nothing in front of it,
        # so the message must not suggest one.
        path = write_bin(tmp_path, SAFE4 + [NOP])

        with pytest.raises(ro.RelocateError, match="no instructions before it") as ei:
            ro.build_fingerprint(path, 0, min_instrs=4)
        assert "lookback" not in str(ei.value)

    def test_offset_beyond_end_of_file_points_at_offset_kind_not_lookback(self, tmp_path):
        path = write_bin(tmp_path, SAFE4)  # 16 bytes

        with pytest.raises(ro.RelocateError, match="past the end") as ei:
            ro.build_fingerprint(path, 64, min_instrs=4)
        msg = str(ei.value)
        assert "FILE offset" in msg and "lookback" not in msg

    @pytest.mark.parametrize("offset", [0x11, 0x12, 0x13])
    def test_misaligned_offset_raises_alignment_error(self, tmp_path, offset):
        path = write_bin(tmp_path, SAFE4 + [NOP, NOP])

        with pytest.raises(ro.RelocateError, match="not 4-byte aligned") as ei:
            ro.build_fingerprint(path, offset, min_instrs=1)
        assert "lookback" not in str(ei.value)

    def test_offset_exactly_at_end_of_file_is_accepted(self, tmp_path):
        path = write_bin(tmp_path, SAFE4)  # 16 bytes; offset 16 == size

        assert ro.build_fingerprint(path, 16, min_instrs=4) == pack(SAFE4)

    def test_lookback_window_caps_fingerprint_length(self, tmp_path):
        words = [MOV_X, ADD] * 16 + [NOP]  # 32 safe words, offset after them
        path = write_bin(tmp_path, words)
        offset = 32 * 4

        assert ro.build_fingerprint(path, offset, min_instrs=4) == pack(words[16:32])  # default 64 B
        assert ro.build_fingerprint(path, offset, min_instrs=4, lookback_window=32) == pack(words[24:32])

    def test_lookback_not_multiple_of_four_stays_aligned_to_offset(self, tmp_path):
        words = SAFE4 * 4 + [NOP]
        path = write_bin(tmp_path, words)

        fp = ro.build_fingerprint(path, 16 * 4, min_instrs=4, lookback_window=30)

        assert fp == pack(words[9:16])  # 30 bytes -> 7 whole instructions

    # -- undecodable words (literal pool / jump table / data in code) ------

    @needs_undecodable
    def test_undecodable_word_ends_the_run(self, tmp_path):
        # Everything before BAD is unreachable; only the 4 words after it count.
        path = write_bin(tmp_path, [ADD, ADD, BAD] + SAFE4 + [NOP])

        fp = ro.build_fingerprint(path, 7 * 4, min_instrs=4)

        assert fp == pack(SAFE4)
        assert struct.pack("<I", BAD) not in fp

    @needs_undecodable
    def test_undecodable_word_does_not_leak_unchecked_bytes(self, tmp_path):
        # capstone's disasm() stops at the first undecodable word, so a
        # naive scan never looks at the `bl` after BAD and would put it in
        # the fingerprint anyway (reporting "4 instructions, 28 bytes").
        # Correct behaviour: only the trailing ADD is a safe, decoded
        # instruction -> not enough for min_instrs=4.
        words = [BL] + [ADD] * 4 + [BAD, BL, ADD, NOP]
        path = write_bin(tmp_path, words)

        with pytest.raises(RuntimeError, match="Only found 1"):
            ro.build_fingerprint(path, 8 * 4, min_instrs=4)

    @needs_undecodable
    def test_undecodable_word_right_before_offset_raises(self, tmp_path):
        path = write_bin(tmp_path, [ADD] * 4 + [BAD, NOP])

        with pytest.raises(RuntimeError, match="Only found 0"):
            ro.build_fingerprint(path, 5 * 4, min_instrs=4)


# --------------------------------------------------------------------------
# find_new_offset()
# --------------------------------------------------------------------------

class TestFindNewOffset:
    def test_no_match(self, tmp_path):
        path = write_bin(tmp_path, [NOP] * 8)

        assert ro.find_new_offset(path, pack(SAFE4)) == []

    def test_single_match_returns_start_of_fingerprint(self, tmp_path):
        path = write_bin(tmp_path, [NOP] * 2 + SAFE4 + [NOP] * 2)

        assert ro.find_new_offset(path, pack(SAFE4)) == [8]

    def test_reports_every_match_including_overlapping_ones(self, tmp_path):
        path = tmp_path / "blob.bin"
        path.write_bytes(b"\xaa" * 5)

        assert ro.find_new_offset(str(path), b"\xaa\xaa") == [0, 1, 2, 3]


# --------------------------------------------------------------------------
# End to end: build_fingerprint() -> find_new_offset() through main()
# --------------------------------------------------------------------------

SAFE_RUN = [MOV_X, ADD, LDR_IMM, SUB_SP, CMP, STR]

# Old build: the hook point is the ldr-literal right after the safe run.
OLD_WORDS = [NOP] * 3 + [ADRP, BL] + SAFE_RUN + [LDR_LIT_X, RET]
OLD_OFFSET = (3 + 2 + len(SAFE_RUN)) * 4  # 0x2c


def run_main(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["relocate_offset.py"] + list(argv))
    try:
        ro.main()
        code = 0
    except SystemExit as e:
        code = e.code
    return code, capsys.readouterr().out


def test_relocates_after_code_moved_and_pc_relative_targets_changed(tmp_path, monkeypatch, capsys):
    # New build: 7 extra words up front, so everything shifted; the adrp/bl
    # encode different targets; the instruction at the hook point changed too.
    new_words = [NOP] * 10 + [ADRP_MOVED, BL_MOVED] + SAFE_RUN + [B, RET] + SAFE_RUN[:3] + [NOP]
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_bin(tmp_path, new_words, "new.bin")
    assert pack([ADRP, BL]) != pack([ADRP_MOVED, BL_MOVED])

    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new)

    assert code == 0
    assert "Matches found in the new build: 1" in out
    assert "NEW OFFSET: 0x%x" % ((10 + 2 + len(SAFE_RUN)) * 4) in out


def test_relocating_a_build_onto_itself_returns_the_same_offset(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")

    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), old)

    assert code == 0
    assert "NEW OFFSET: 0x%x" % OLD_OFFSET in out


def test_exits_1_when_code_genuinely_changed(tmp_path, monkeypatch, capsys):
    changed_run = [SUB_SP if w == ADD else w for w in SAFE_RUN]  # one insn differs
    new_words = [NOP] * 4 + [BL_MOVED] + changed_run + [RET]
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_bin(tmp_path, new_words, "new.bin")

    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new)

    assert code == 1
    assert "No matches" in out
    assert "NEW OFFSET" not in out


def test_exits_1_and_lists_candidates_when_fingerprint_is_ambiguous(tmp_path, monkeypatch, capsys):
    # The safe run appears twice in the new build.
    second_copy_end = (len(OLD_WORDS) + 1 + len(SAFE_RUN)) * 4
    new_words = OLD_WORDS + [NOP] + SAFE_RUN + [RET]
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_bin(tmp_path, new_words, "new.bin")

    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new)

    assert code == 1
    assert "More than one match" in out
    assert "candidate: 0x%x" % OLD_OFFSET in out
    assert "candidate: 0x%x" % second_copy_end in out
    assert "NEW OFFSET" not in out


# --------------------------------------------------------------------------
# main(): bad input is one `[!]` line + exit 2, never a raw traceback
# --------------------------------------------------------------------------

def run_main_err(monkeypatch, capsys, *argv):
    """Like run_main, but also returns stderr (where [!] errors go)."""
    monkeypatch.setattr(sys, "argv", ["relocate_offset.py"] + list(argv))
    try:
        ro.main()
        code = 0
    except SystemExit as e:
        code = e.code
    cap = capsys.readouterr()
    return code, cap.out, cap.err


@pytest.mark.parametrize("bad_hex", ["0xZZ", "zz", "", "0x"])
def test_bad_hex_offset_is_a_usage_error_not_a_traceback(tmp_path, monkeypatch, capsys, bad_hex):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_bin(tmp_path, OLD_WORDS, "new.bin")

    code, out, err = run_main_err(monkeypatch, capsys, old, bad_hex, new)

    assert code == 2
    assert "Traceback" not in err
    assert "not a hex offset" in err


def test_offset_past_eof_exits_2_with_one_line_message(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_bin(tmp_path, OLD_WORDS, "new.bin")

    code, out, err = run_main_err(monkeypatch, capsys, old, "0x100000", new)

    assert code == 2
    assert err.startswith("[!] offset 0x100000 is past the end")
    assert "Traceback" not in err


def test_misaligned_offset_exits_2(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_bin(tmp_path, OLD_WORDS, "new.bin")

    code, out, err = run_main_err(monkeypatch, capsys, old, hex(OLD_OFFSET + 2), new)

    assert code == 2
    assert "not 4-byte aligned" in err


def test_missing_file_exits_2_without_traceback(tmp_path, monkeypatch, capsys):
    new = write_bin(tmp_path, OLD_WORDS, "new.bin")

    code, out, err = run_main_err(monkeypatch, capsys, str(tmp_path / "nope.bin"), hex(OLD_OFFSET), new)

    assert code == 2
    assert err.startswith("[!]") and "Traceback" not in err


def test_too_few_safe_instructions_is_also_a_clean_exit_2(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, [BL, BL, BL, BL], "old.bin")
    new = write_bin(tmp_path, OLD_WORDS, "new.bin")

    code, out, err = run_main_err(monkeypatch, capsys, old, "0x10", new)

    assert code == 2
    assert "Only found 0" in err and "Traceback" not in err



# --------------------------------------------------------------------------
# executable_ranges(): where code can live, per container format
# --------------------------------------------------------------------------

DATA = b"\xbb" * 32


def test_macho_returns_only_instruction_sections_with_absolute_offsets():
    blob, lay = build_macho([
        ("__TEXT", 5, [("__text", CODE, b"\x11" * 64), ("__stubs", CODE, b"\x22" * 16),
                       ("__cstring", S_CSTRING_LITERALS, b"hello\0" * 4)]),
        ("__DATA", 3, [("__data", NOT_CODE, DATA)]),
    ])

    fmt, ranges = ro.executable_ranges(blob)

    assert fmt == "Mach-O"
    assert ranges == [(*lay["__TEXT,__text"], "__TEXT,__text"),
                      (*lay["__TEXT,__stubs"], "__TEXT,__stubs")]


def test_macho_without_instruction_sections_falls_back_to_executable_segments():
    blob, lay = build_macho([("__TEXT", 5, [("__const", NOT_CODE, DATA)]),
                             ("__DATA", 3, [("__data", NOT_CODE, DATA)])])

    fmt, ranges = ro.executable_ranges(blob)

    assert [r[2] for r in ranges] == ["segment __TEXT"]      # __DATA isn't executable
    assert ranges[0][:2] == lay["__TEXT,__const"]


def test_fat_macho_uses_only_arm64_slices_and_makes_offsets_absolute():
    arm, arm_lay = build_macho([("__TEXT", 5, [("__text", CODE, b"\x11" * 64)])], CPU_ARM64)
    x86, _ = build_macho([("__TEXT", 5, [("__text", CODE, b"\x22" * 64)])], CPU_X86_64)
    blob, offs = build_fat([(CPU_X86_64, x86), (CPU_ARM64, arm)])

    fmt, ranges = ro.executable_ranges(blob)

    start, end = arm_lay["__TEXT,__text"]
    assert ranges == [(offs[1] + start, offs[1] + end, "__TEXT,__text")]


def test_fat_macho_without_an_arm64_slice_has_no_code_ranges():
    x86, _ = build_macho([("__TEXT", 5, [("__text", CODE, b"\x22" * 64)])], CPU_X86_64)
    blob, _ = build_fat([(CPU_X86_64, x86)])

    assert ro.executable_ranges(blob) == ("fat Mach-O (arm64 slices)", [])


def test_elf_returns_only_executable_load_segments():
    blob, spans = build_elf64([(1, 4, b"\x11" * 32),       # PT_LOAD  R
                               (1, 5, b"\x22" * 64),       # PT_LOAD  R X
                               (1, 6, b"\x33" * 32),       # PT_LOAD  RW
                               (4, 5, b"\x44" * 16)])      # PT_NOTE, even with X set: not a load
    fmt, ranges = ro.executable_ranges(blob)

    assert fmt == "ELF64"
    assert [(a, b) for a, b, _ in ranges] == [spans[1]]


@pytest.mark.parametrize("blob", [
    pytest.param(pack(SAFE4), id="raw-instruction-words"),
    pytest.param(b"", id="empty"),
    pytest.param(b"\x7fELF\x01\x01" + b"\0" * 60, id="elf32"),
    pytest.param(b"\x7fELF\x02\x02" + b"\0" * 60, id="elf64-big-endian"),
    pytest.param(b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 60, id="java-class-not-fat"),
    pytest.param(build_macho([("__TEXT", 5, [("__text", CODE, b"\x11" * 64)])])[0][:60],
                 id="truncated-macho"),
])
def test_unrecognised_or_malformed_files_are_none_not_an_error(blob):
    assert ro.executable_ranges(blob) is None


# --------------------------------------------------------------------------
# validate_candidates() / main(): reject non-code matches, grade the rest
# --------------------------------------------------------------------------

FP = pack(SAFE_RUN)
HOOK_OFFSET_IN_NEW_TEXT = (10 + 2 + len(SAFE_RUN)) * 4
NEW_TEXT_WORDS = [NOP] * 10 + [ADRP_MOVED, BL_MOVED] + SAFE_RUN + [LDR_LIT_X, RET] + [NOP] * 6


def write_blob(tmp_path, blob, name):
    path = tmp_path / name
    path.write_bytes(blob)
    return str(path)


def validate(tmp_path, new_blob, matches=None):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, new_blob, "new.bin")
    if matches is None:
        matches = ro.find_new_offset(new, FP)
    return ro.validate_candidates(old, OLD_OFFSET, new, FP, matches)


def status(cand, name):
    return next(c.status for c in cand.checks if c.name == name)


def test_a_match_that_is_not_word_aligned_is_rejected(tmp_path):
    # Same bytes, but starting one byte into the file: not an instruction boundary.
    (cand,) = validate(tmp_path, b"\x00" + pack([NOP] * 2 + SAFE_RUN + [RET]))

    assert cand.match % 4 == 1
    assert cand.confidence == "rejected"
    assert "boundary" in cand.rejected[0]


def test_main_rejecting_every_match_exits_1_and_says_why(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, b"\x00" + pack([NOP] * 2 + SAFE_RUN + [RET]), "new.bin")

    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new)

    assert code == 1
    assert "Matches found in the new build: 1" in out
    assert "Surviving validation: 0 of 1" in out and "rejected 0x" in out
    assert "NEW OFFSET" not in out


def test_byte_match_in_a_data_section_is_rejected_and_the_code_match_survives(tmp_path, monkeypatch, capsys):
    # The same bytes exist once as code and once in __cstring: a raw search
    # calls that ambiguous, the section check knows one of them is data.
    blob, lay = build_macho([
        ("__TEXT", 5, [("__text", CODE, pack(NEW_TEXT_WORDS)),
                       ("__cstring", S_CSTRING_LITERALS, pack(SAFE_RUN + [LDR_LIT_X, RET]))]),
    ])
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")
    expected = lay["__TEXT,__text"][0] + HOOK_OFFSET_IN_NEW_TEXT
    assert len(ro.find_new_offset(new, FP)) == 2

    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new)

    assert code == 0
    assert "Matches found in the new build: 2" in out
    assert "Surviving validation: 1 of 2" in out
    assert "NEW OFFSET: 0x%x" % expected in out
    assert "not inside an executable Mach-O region" in out


def test_no_validate_restores_the_raw_ambiguous_result(tmp_path, monkeypatch, capsys):
    blob, _ = build_macho([
        ("__TEXT", 5, [("__text", CODE, pack(NEW_TEXT_WORDS)),
                       ("__cstring", S_CSTRING_LITERALS, pack(SAFE_RUN + [LDR_LIT_X, RET]))]),
    ])
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")

    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new, "--no-validate")

    assert code == 1
    assert "--no-validate" in out and "More than one match" in out


def test_match_only_in_data_exits_1(tmp_path, monkeypatch, capsys):
    blob, _ = build_macho([
        ("__TEXT", 5, [("__text", CODE, pack([NOP] * 16)),
                       ("__const", NOT_CODE, pack(SAFE_RUN + [LDR_LIT_X, RET]))]),
    ])
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")

    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new)

    assert code == 1
    assert "Surviving validation: 0 of 1" in out and "NEW OFFSET" not in out


def test_match_whose_hook_point_falls_outside_the_section_is_rejected(tmp_path):
    # The fingerprint is the very last thing in __text; the word at the hook
    # offset already belongs to the next (data) section.
    blob, _ = build_macho([
        ("__TEXT", 5, [("__text", CODE, pack([NOP] * 4 + SAFE_RUN)),
                       ("__const", NOT_CODE, pack([LDR_LIT_X, RET]))]),
    ])

    (cand,) = validate(tmp_path, blob)

    assert cand.confidence == "rejected"
    assert "run past the end of __TEXT,__text" in cand.rejected[0]


def test_elf_read_only_segment_match_is_rejected_and_exec_segment_match_survives(tmp_path):
    code_seg = pack(NEW_TEXT_WORDS)
    ro_seg = pack(SAFE_RUN + [LDR_LIT_X, RET])
    blob, spans = build_elf64([(1, 4, ro_seg), (1, 5, code_seg)])

    cands = validate(tmp_path, blob)

    assert [c.confidence == "rejected" for c in cands] == [True, False]
    assert cands[1].offset == spans[1][0] + HOOK_OFFSET_IN_NEW_TEXT
    assert status(cands[1], "executable-section") == "pass"


def test_faithful_relocation_inside_a_real_container_is_high_confidence(tmp_path):
    blob, _ = build_macho([("__TEXT", 5, [("__text", CODE, pack(NEW_TEXT_WORDS))])])

    (cand,) = validate(tmp_path, blob)

    assert not cand.rejected
    assert cand.confidence == "HIGH"
    assert [status(cand, n) for n in ("alignment", "executable-section", "after-decode",
                                      "before-anchor", "after-similarity")] == ["pass"] * 5


def test_unknown_container_can_never_be_high_confidence(tmp_path):
    # Same faithful relocation, but a raw blob: nothing proves it's in a code section.
    (cand,) = validate(tmp_path, pack(NEW_TEXT_WORDS))

    assert status(cand, "executable-section") == "n/a"
    assert cand.confidence == "MEDIUM"


def test_different_barrier_before_the_fingerprint_is_a_soft_failure_not_a_rejection(tmp_path):
    # `b` where the old build had `bl` in front of the run.
    words = [NOP] * 10 + [ADRP_MOVED, B] + SAFE_RUN + [LDR_LIT_X, RET] + [NOP] * 6
    blob, _ = build_macho([("__TEXT", 5, [("__text", CODE, pack(words))])])

    (cand,) = validate(tmp_path, blob)

    assert not cand.rejected
    assert status(cand, "before-anchor") == "fail"
    assert cand.confidence == "MEDIUM"


@needs_undecodable
def test_data_like_words_after_the_hook_point_give_low_confidence_but_still_succeed(
        tmp_path, monkeypatch, capsys):
    words = [NOP] * 10 + [ADRP_MOVED, B] + SAFE_RUN + [BAD] * 6
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, pack(words), "new.bin")

    (cand,) = ro.validate_candidates(old, OLD_OFFSET, new, FP, ro.find_new_offset(new, FP))
    assert status(cand, "after-decode") == "fail" and cand.confidence == "LOW"

    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new)
    assert code == 0                       # a soft grade never blocks a unique match
    assert "(confidence: LOW)" in out and "Check this one in Ghidra" in out


def test_successful_main_prints_the_confidence_and_the_checks(tmp_path, monkeypatch, capsys):
    blob, lay = build_macho([("__TEXT", 5, [("__text", CODE, pack(NEW_TEXT_WORDS))])])
    old = write_bin(tmp_path, OLD_WORDS, "old.bin")
    new = write_blob(tmp_path, blob, "new.bin")

    code, out = run_main(monkeypatch, capsys, old, hex(OLD_OFFSET), new)

    assert code == 0
    assert "NEW OFFSET: 0x%x  (confidence: HIGH)" % (lay["__TEXT,__text"][0] + HOOK_OFFSET_IN_NEW_TEXT) in out
    assert "executable-section: inside __TEXT,__text" in out
