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
    pytest.param(
        PRFM_LIT, "prfm", id="prfm-literal",
        marks=pytest.mark.xfail(
            strict=True,
            reason="known gap: literal prfm is PC-relative but not detected "
                   "(compilers practically never emit it). Remove this marker "
                   "if is_pc_relative() ever learns about it.")),
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

    @pytest.mark.parametrize("offset, lookback", [
        pytest.param(0, 64, id="offset-0"),
        pytest.param(16, 2, id="lookback-smaller-than-one-instruction"),
    ])
    def test_nothing_to_disassemble_raises(self, tmp_path, offset, lookback):
        path = write_bin(tmp_path, SAFE4 + [NOP])

        with pytest.raises(RuntimeError, match="Could not disassemble anything"):
            ro.build_fingerprint(path, offset, min_instrs=4, lookback_window=lookback)

    def test_offset_beyond_end_of_file_raises(self, tmp_path):
        path = write_bin(tmp_path, SAFE4)  # 16 bytes

        with pytest.raises(RuntimeError, match="Only found 0"):
            ro.build_fingerprint(path, 64, min_instrs=4)

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
        # Regression: capstone's disasm() stops at the first undecodable word,
        # so the old code never looked at the `bl` after BAD and put it in the
        # fingerprint anyway (reporting "4 instructions, 28 bytes").
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
