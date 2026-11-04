"""
Tests for relocate_offset.py's handling of a hook point at a FUNCTION ENTRY.

The original algorithm fingerprinted the instructions in front of the hook point.
At a function entry those belong to the previous function, so the "fingerprint of
the target" was the tail of its neighbour: it broke when the neighbour changed, and
when the target was rewritten, a function was inserted in front of it or the
neighbours were reordered it still found exactly one match - the wrong function -
with every soft check passing. The end-to-end tests at the bottom replay exactly
those situations on a synthetic build (tests/synth_image.py: 300 functions, a
hook at the entry of the 150th), and fail on the old algorithm.

Run from the repo root: `pytest`.
"""
import copy
import random
import struct
import sys

import pytest
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

from retk import relocate_offset as ro
import synth_image as si

_MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
_MD_DETAIL = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
_MD_DETAIL.detail = True

# Position-independent / flow words (see test_relocate_offset.py for the table style).
MOV_X = 0xAA0103E0         # mov  x0, x1
ADD = 0x91004000           # add  x0, x0, #0x10
SUB_SP = 0xD10083FF        # sub  sp, sp, #0x20
CMP = 0xF100001F           # cmp  x0, #0
NOP = 0xD503201F
RET = 0xD65F03C0
RETAA = 0xD65F0BFF         # retaa
BR = 0xD61F0200            # br   x16
BRK = 0xD4200020           # brk  #1
BLR = 0xD63F0100           # blr  x8
B = 0x14000040             # b    #0x100
BL = 0x94000400            # bl   #0x1000
B_EQ = 0x54000200          # b.eq #0x40
LDP = 0xA9417BFD           # ldp  x29, x30, [sp, #0x10]
STP, MOV_FP = si.STP_FP_LR, si.MOV_FP_SP
SAFE4 = [MOV_X, ADD, SUB_SP, CMP]
WORD_MASK = ro.WORD_MASK


def pack(words):
    return struct.pack(f"<{len(words)}I", *words)


def write_bin(tmp_path, words, name="build.bin"):
    path = tmp_path / name
    path.write_bytes(pack(words))
    return str(path)


def decode(word, addr=0x1000, md=_MD):
    return next(md.disasm(struct.pack("<I", word), addr), None)


def decode_run(words, base=0x1000):
    return [next(_MD_DETAIL.disasm(struct.pack("<I", w), base + 4 * i)) for i, w in enumerate(words)]


def _first_undecodable():
    for w in (0xFFFFFFFF, 0xDEADBEEF, 0x00100000):
        if decode(w) is None:
            return w


BAD = _first_undecodable()
needs_undecodable = pytest.mark.skipif(BAD is None, reason="this capstone decodes every candidate 'bad' word")


def run_main(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["relocate_offset.py", *map(str, argv)])
    try:
        ro.main()
        code = 0
    except SystemExit as e:
        code = e.code
    cap = capsys.readouterr()
    return code, cap.out, cap.err


# --------------------------------------------------------------------------
# is_terminator() / is_barrier()
# --------------------------------------------------------------------------

@pytest.mark.parametrize("word, mnemonic", [
    pytest.param(RET, "ret", id="ret"),
    pytest.param(RETAA, "retaa", id="retaa"),
    pytest.param(BR, "br", id="br"),
    pytest.param(BRK, "brk", id="brk"),
    pytest.param(B, "b", id="b"),
])
def test_terminators_end_a_run(word, mnemonic):
    insn = decode(word)
    assert insn is not None and insn.mnemonic == mnemonic        # guards the table itself
    assert ro.is_terminator(insn) and ro.is_barrier(insn)


@pytest.mark.parametrize("word, mnemonic, barrier", [
    pytest.param(BL, "bl", True, id="bl: a call returns, but PC-relative"),
    pytest.param(B_EQ, "b.eq", True, id="b.eq: falls through, but PC-relative"),
    pytest.param(BLR, "blr", False, id="blr: a call through a register"),
    pytest.param(NOP, "nop", False, id="nop"),
    pytest.param(ADD, "add", False, id="add"),
    pytest.param(LDP, "ldp", False, id="ldp"),
])
def test_calls_and_conditional_branches_are_not_terminators(word, mnemonic, barrier):
    insn = decode(word)
    assert insn is not None and insn.mnemonic == mnemonic
    assert not ro.is_terminator(insn)
    assert ro.is_barrier(insn) == barrier


# --------------------------------------------------------------------------
# build_fingerprint() ("before") never walks across a function boundary
# --------------------------------------------------------------------------

class TestBackwardRunStopsAtFunctionEnd:
    @pytest.mark.parametrize("end", [RET, RETAA, BR, BRK])
    def test_run_stops_at_terminator(self, tmp_path, end):
        # The ADDs are the previous function's tail; they sit behind its `ret`.
        path = write_bin(tmp_path, [ADD] * 4 + [end] + SAFE4 + [NOP])

        assert ro.build_fingerprint(path, 9 * 4, min_instrs=4) == pack(SAFE4)

    def test_hook_at_function_entry_is_refused_with_a_pointer_to_after_mode(self, tmp_path):
        path = write_bin(tmp_path, [ADD] * 6 + [RET, NOP])      # neighbour's tail is plenty "safe"

        with pytest.raises(ro.TooFewInstructions, match="Only found 0") as ei:
            ro.build_fingerprint(path, 7 * 4, min_instrs=4)
        assert "function entry" in str(ei.value) and "--mode after" in str(ei.value)

    def test_no_hint_when_the_run_was_cut_short_by_a_pc_relative_instruction(self, tmp_path):
        path = write_bin(tmp_path, [ADD] * 4 + [BL, ADD, NOP])

        with pytest.raises(ro.TooFewInstructions) as ei:
            ro.build_fingerprint(path, 6 * 4, min_instrs=4)
        assert "function entry" not in str(ei.value)


# --------------------------------------------------------------------------
# operand_mask(): which bits of a PC-relative instruction move
# --------------------------------------------------------------------------

PC_RELATIVE = [
    pytest.param(0x90000020, "adrp", id="adrp"),
    pytest.param(0x10000201, "adr", id="adr"),
    pytest.param(BL, "bl", id="bl"),
    pytest.param(B, "b", id="b"),
    pytest.param(0xB4000200, "cbz", id="cbz"),
    pytest.param(0x35000201, "cbnz", id="cbnz"),
    pytest.param(0x36180202, "tbz", id="tbz"),
    pytest.param(0xB7E00203, "tbnz", id="tbnz"),
    pytest.param(B_EQ, "b.eq", id="b.eq"),
    pytest.param(0x58000200, "ldr", id="ldr-literal-x"),
    pytest.param(0x5C000200, "ldr", id="ldr-literal-simd"),
    pytest.param(0x98000200, "ldrsw", id="ldrsw-literal"),
    pytest.param(0xD8000200, "prfm", id="prfm-literal"),
]


@pytest.mark.parametrize("word, mnemonic", PC_RELATIVE)
def test_operand_mask_wildcards_exactly_the_relative_target(word, mnemonic):
    insn = decode(word)
    assert insn is not None and insn.mnemonic == mnemonic
    mask = ro.operand_mask(insn)
    assert mask != WORD_MASK
    rng = random.Random(word)
    for _ in range(300):
        # Any value in the wildcarded bits is the same instruction pointing elsewhere...
        other = decode((word & mask) | (rng.getrandbits(32) & ~mask & WORD_MASK))
        assert other is not None and other.mnemonic == mnemonic and ro.is_pc_relative(other)
        assert ro.operand_mask(other) == mask
    # ...and the bits that stay are not all zero: opcode (and registers) are still checked.
    assert mask & word


@pytest.mark.parametrize("word", [MOV_X, ADD, LDP, RET, 0xF9400900, 0xB9400500])
def test_operand_mask_keeps_every_bit_of_a_position_independent_instruction(word):
    assert ro.operand_mask(decode(word)) == WORD_MASK


# --------------------------------------------------------------------------
# wildcard_masks(): the lo12 immediate that goes with an adrp
# --------------------------------------------------------------------------

IMM12 = 0x003FFC00
PAGE = 0x4000000


def adrp_x(reg):
    return si.adrp(reg, 0x1000, PAGE)


def masks(words):
    return ro.wildcard_masks(decode_run(words))


def test_load_through_an_adrp_register_has_its_page_offset_wildcarded():
    m = masks([adrp_x(8), si.ldr_x(0, 8, 0x11)])           # adrp x8; ldr x0, [x8, #lo12]

    assert m[0] == 0x9F00001F
    assert m[1] == WORD_MASK & ~IMM12


def test_add_of_the_page_offset_is_wildcarded_including_the_shift_bit():
    m = masks([adrp_x(9), si.add_imm(9, 9, 0x88)])

    assert m[1] == WORD_MASK & ~(IMM12 | 0x00400000)


def test_page_register_stays_a_page_until_it_is_written():
    # Two symbols in the same page: both page offsets move.
    m = masks([adrp_x(8), si.ldr_x(0, 8, 0x11), si.ldr_x(1, 8, 0x22)])
    assert m[1] == m[2] == WORD_MASK & ~IMM12


@pytest.mark.parametrize("name, words", [
    ("the loaded pointer is a field base, not a page",
     [adrp_x(8), si.ldr_x(8, 8, 0x11), si.ldr_x(0, 8, 0x10)]),         # ldr x8,[x8,#lo12]; ldr x0,[x8,#0x10]
    ("add of lo12 produced the full address, not a page",
     [adrp_x(9), si.add_imm(9, 9, 0x88), si.ldr_x(0, 9, 0x1)]),
    ("the register was overwritten",
     [adrp_x(8), si.mov_reg(8, 1), si.ldr_x(0, 8, 0x1)]),
    ("a different register than the adrp's",
     [adrp_x(8), si.ldr_x(0, 7, 0x1)]),
    ("no adrp at all",
     [si.ldr_x(0, 8, 0x1)]),
])
def test_field_offsets_and_unrelated_registers_are_not_wildcarded(name, words):
    assert masks(words)[-1] == WORD_MASK, name


# --------------------------------------------------------------------------
# build_entry_fingerprint() ("after")
# --------------------------------------------------------------------------

class TestEntryFingerprint:
    def test_is_the_functions_own_code_not_the_neighbours_tail(self, tmp_path, capsys):
        neighbour_tail = [ADD, ADD, ADD, ADD, RET]
        func = [STP, MOV_FP, BL, ADD, SUB_SP, CMP, RET]
        path = write_bin(tmp_path, neighbour_tail + func + [ADD] * 4)

        fp = ro.build_entry_fingerprint(path, 5 * 4, min_instrs=4)

        assert (fp.mode, fp.hook_delta, len(fp.words)) == ("after", 0, 7)
        assert [value for value, _ in fp.words][:2] == [STP, MOV_FP]
        assert [mask == WORD_MASK for _, mask in fp.words] == [True, True, False, True, True, True, True]
        assert fp.words[2] == (BL & 0xFC000000, 0xFC000000)       # the call target is a wildcard
        out = capsys.readouterr().out
        assert "7 instructions (1 with a wildcarded operand" in out and "stopped at `ret`" in out

    def test_stops_after_an_unconditional_branch(self, tmp_path):
        path = write_bin(tmp_path, SAFE4 + [B, ADD, ADD])

        fp = ro.build_entry_fingerprint(path, 0, min_instrs=4)

        assert len(fp.words) == 5 and fp.words[-1][1] != WORD_MASK

    @needs_undecodable
    def test_stops_at_an_undecodable_word(self, tmp_path):
        path = write_bin(tmp_path, SAFE4 + [BAD, ADD, ADD])

        assert len(ro.build_entry_fingerprint(path, 0, min_instrs=4).words) == 4

    def test_lookahead_caps_the_length(self, tmp_path):
        path = write_bin(tmp_path, [ADD, MOV_X] * 16 + [RET])

        assert len(ro.build_entry_fingerprint(path, 0, min_instrs=4, lookahead_window=32).words) == 8

    def test_hook_point_near_the_end_of_the_file_uses_what_is_there(self, tmp_path):
        path = write_bin(tmp_path, [NOP] * 4 + SAFE4)

        assert len(ro.build_entry_fingerprint(path, 16, min_instrs=4).words) == 4

    def test_only_fully_fixed_instructions_count_towards_min_instrs(self, tmp_path):
        path = write_bin(tmp_path, [BL, BL, BL, ADD, SUB_SP, CMP, RET, NOP])    # 3 wildcarded + 4 fixed

        assert len(ro.build_entry_fingerprint(path, 0, min_instrs=4).words) == 7
        with pytest.raises(ro.TooFewInstructions, match=r"Only found 4 fully fixed instructions \(of 7\)"):
            ro.build_entry_fingerprint(path, 0, min_instrs=5)

    def test_a_function_that_is_only_calls_is_not_a_fingerprint(self, tmp_path):
        path = write_bin(tmp_path, [BL] * 8)

        with pytest.raises(ro.TooFewInstructions, match="Only found 0 fully fixed"):
            ro.build_entry_fingerprint(path, 0, min_instrs=1)

    @pytest.mark.parametrize("offset, message", [
        (0x11, "not 4-byte aligned"),
        (16, "past the end"),          # nothing AT the offset to fingerprint
        (400, "past the end"),
    ])
    def test_bad_offsets_are_relocate_errors(self, tmp_path, offset, message):
        path = write_bin(tmp_path, SAFE4)

        with pytest.raises(ro.RelocateError, match=message):
            ro.build_entry_fingerprint(path, offset, min_instrs=1)

    def test_min_instrs_below_one_raises(self, tmp_path):
        path = write_bin(tmp_path, SAFE4)

        with pytest.raises(ro.RelocateError, match="min-instrs must be >= 1"):
            ro.build_entry_fingerprint(path, 0, min_instrs=0)


# --------------------------------------------------------------------------
# find_masked_matches()
# --------------------------------------------------------------------------

BL_WORD = (BL & 0xFC000000, 0xFC000000)
PATTERN = [(MOV_X, WORD_MASK), BL_WORD, (ADD, WORD_MASK), (SUB_SP, WORD_MASK)]


class TestFindMaskedMatches:
    def test_wildcarded_operand_may_differ(self, tmp_path):
        words = [NOP, MOV_X, si.bl(0, 0x1230), ADD, SUB_SP, NOP, MOV_X, si.bl(0, 0x9990), ADD, SUB_SP]
        path = write_bin(tmp_path, words)

        assert ro.find_masked_matches(path, PATTERN) == [4, 24]

    def test_a_fixed_word_that_differs_is_not_a_match(self, tmp_path):
        path = write_bin(tmp_path, [MOV_X, BL, CMP, SUB_SP])

        assert ro.find_masked_matches(path, PATTERN) == []

    def test_the_wildcard_is_the_operand_not_the_instruction(self, tmp_path):
        path = write_bin(tmp_path, [MOV_X, ADD, ADD, SUB_SP])              # an add where the bl should be

        assert ro.find_masked_matches(path, PATTERN) == []

    def test_only_aligned_positions_are_reported(self, tmp_path):
        p = tmp_path / "shifted.bin"
        p.write_bytes(b"\x00" + pack([MOV_X, BL, ADD, SUB_SP]))

        assert ro.find_masked_matches(str(p), PATTERN) == []

    def test_pattern_at_the_very_start_and_the_very_end(self, tmp_path):
        path = write_bin(tmp_path, [MOV_X, BL, ADD, SUB_SP, NOP, MOV_X, BL, ADD, SUB_SP])

        assert ro.find_masked_matches(path, PATTERN) == [0, 20]

    def test_pattern_longer_than_the_file_is_not_a_match(self, tmp_path):
        path = write_bin(tmp_path, [ADD, SUB_SP])

        assert ro.find_masked_matches(path, PATTERN) == []

    def test_matches_may_overlap(self, tmp_path):
        path = write_bin(tmp_path, [ADD] * 5)

        assert ro.find_masked_matches(path, [(ADD, WORD_MASK)] * 3) == [0, 4, 8]

    def test_anchors_on_a_fixed_word_even_when_it_is_not_the_first(self, tmp_path):
        pattern = [BL_WORD, BL_WORD, (SUB_SP, WORD_MASK)]
        path = write_bin(tmp_path, [NOP, BL, BL, SUB_SP, NOP])

        assert ro.find_masked_matches(path, pattern) == [4]

    def test_a_pattern_with_no_fixed_word_cannot_be_searched(self, tmp_path):
        path = write_bin(tmp_path, [BL, BL])

        with pytest.raises(ro.RelocateError, match="fully fixed"):
            ro.find_masked_matches(path, [BL_WORD, BL_WORD])


# --------------------------------------------------------------------------
# entry_context(): does the hook point look like a function entry?
# --------------------------------------------------------------------------

class TestEntryContext:
    @pytest.mark.parametrize("before, expected", [
        ([ADD, RET], "`ret`"),
        ([ADD, B], "`b`"),            # tail call
        ([ADD, BR], "`br`"),
        ([ADD, BRK], "`brk`"),
        ([ADD, RET, NOP, NOP], "`ret`"),                  # alignment padding
        ([ADD, ADD], None),                               # mid-function
        ([ADD, BL], None),                                # right after a call
        ([ADD, B_EQ], None),
        ([RET, ADD], None),                               # a ret, but not the word in front
    ])
    def test_classifies_the_words_in_front(self, tmp_path, before, expected):
        path = write_bin(tmp_path, [NOP] * 2 + before + [STP, MOV_FP])

        assert ro.entry_context(path, (2 + len(before)) * 4) == expected

    @needs_undecodable
    def test_undecodable_word_in_front_counts(self, tmp_path):
        path = write_bin(tmp_path, [ADD, BAD, STP])

        assert ro.entry_context(path, 8) == "an undecodable word"

    def test_start_of_file(self, tmp_path):
        path = write_bin(tmp_path, [STP, MOV_FP])

        assert ro.entry_context(path, 0) == "the start of the file"

    def test_a_long_run_of_nops_is_not_evidence_either_way(self, tmp_path):
        path = write_bin(tmp_path, [RET] + [NOP] * 12 + [STP])

        assert ro.entry_context(path, 13 * 4) is None


# --------------------------------------------------------------------------
# main(): --mode
# --------------------------------------------------------------------------

def test_auto_fingerprints_the_function_when_the_hook_point_is_an_entry(tmp_path, monkeypatch, capsys):
    func = [STP, MOV_FP, BL, ADD, SUB_SP, CMP, MOV_X, RET]
    old = write_bin(tmp_path, [ADD] * 6 + [RET] + func + [ADD] * 6, "old.bin")
    # In the new build the neighbour in front is different, and the call target moved.
    new = write_bin(tmp_path, [SUB_SP] * 3 + [RET] + [NOP] + [STP, MOV_FP, BL | 5, ADD, SUB_SP, CMP, MOV_X, RET], "new.bin")

    code, out, _ = run_main(monkeypatch, capsys, old, hex(7 * 4), new)

    assert code == 0
    assert "looks like a function entry" in out
    assert "NEW FILE OFFSET: 0x%x" % (5 * 4) in out


def test_auto_keeps_using_the_instructions_in_front_for_a_mid_function_hook(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, [STP, MOV_FP] + SAFE4 + [LDP, RET], "old.bin")
    new = write_bin(tmp_path, [NOP] * 3 + [ADD, ADD, RET] + [STP, MOV_FP] + SAFE4 + [LDP, RET], "new.bin")

    code, out, _ = run_main(monkeypatch, capsys, old, hex(6 * 4), new)

    assert code == 0
    assert "function entry" not in out and "Fingerprint: 6 instructions" in out    # stp, mov, SAFE4
    assert "NEW FILE OFFSET: 0x%x" % (12 * 4) in out


def test_auto_falls_back_to_the_code_after_the_hook_point_when_nothing_precedes_it(
        tmp_path, monkeypatch, capsys):
    # Mid-function hook right after a call: no safe run in front, but plenty after.
    body = [ADD, SUB_SP, CMP, MOV_X, ADD]
    old = write_bin(tmp_path, [STP, MOV_FP, BL] + body + [RET], "old.bin")
    new = write_bin(tmp_path, [NOP] * 4 + [STP, MOV_FP, BL | 9] + body + [RET], "new.bin")

    code, out, _ = run_main(monkeypatch, capsys, old, hex(3 * 4), new)

    assert code == 0
    assert "fingerprinting the code from the hook point forward instead" in out
    assert "NEW FILE OFFSET: 0x%x" % (7 * 4) in out


def test_auto_reports_both_directions_when_neither_works(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, [BL, BL, BL, BL, RET], "old.bin")
    new = write_bin(tmp_path, [NOP] * 8, "new.bin")

    code, _, err = run_main(monkeypatch, capsys, old, hex(3 * 4), new)

    assert code == 2
    assert "Only found 0 consecutive safe" in err and "forward didn't work either" in err


def test_forced_before_mode_refuses_a_function_entry(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, [ADD] * 6 + [RET, STP, MOV_FP, ADD, SUB_SP, CMP, RET], "old.bin")

    code, _, err = run_main(monkeypatch, capsys, old, hex(7 * 4), old, "--mode", "before")

    assert code == 2 and "--mode after" in err


def test_forced_after_mode_works_mid_function(tmp_path, monkeypatch, capsys):
    old = write_bin(tmp_path, [STP, MOV_FP] + SAFE4 + [LDP, RET], "old.bin")

    code, out, _ = run_main(monkeypatch, capsys, old, hex(2 * 4), old, "--mode", "after")

    assert code == 0 and "NEW FILE OFFSET: 0x%x" % (2 * 4) in out


def test_no_validate_with_an_after_fingerprint_reports_the_hook_point_not_the_end_of_it(
        tmp_path, monkeypatch, capsys):
    func = [STP, MOV_FP, ADD, SUB_SP, CMP, RET]
    old = write_bin(tmp_path, [ADD, RET] + func, "old.bin")
    new = write_bin(tmp_path, [NOP] * 3 + func, "new.bin")

    code, out, _ = run_main(monkeypatch, capsys, old, hex(2 * 4), new, "--no-validate")

    assert code == 0 and "NEW FILE OFFSET: 0x%x" % (3 * 4) in out


# --------------------------------------------------------------------------
# End to end on a synthetic build: the situations that used to answer wrongly
# --------------------------------------------------------------------------

N_FUNCS, TARGET = 300, 150
OLD_ORDER = list(range(N_FUNCS))


@pytest.fixture(scope="module")
def old_image():
    return si.Image(si.make_functions(seed=7, n_funcs=N_FUNCS), OLD_ORDER)


def fresh_functions():
    return si.make_functions(seed=7, n_funcs=N_FUNCS)


def new_function(seed):
    return si.gen_function(random.Random(seed), N_FUNCS, 64)


def relocate(tmp_path, monkeypatch, capsys, old_image, new_image, *extra):
    old = old_image.write(tmp_path / "old.bin")
    new = new_image.write(tmp_path / "new.bin")
    code, out, err = run_main(monkeypatch, capsys, old, hex(old_image.entry[TARGET]), new, *extra)
    return code, out, err


def assert_found_at(new_image, code, out, confidence="HIGH"):
    assert code == 0, out
    assert "NEW FILE OFFSET: 0x%x  (confidence: %s)" % (new_image.entry[TARGET], confidence) in out


def test_unchanged_build(tmp_path, monkeypatch, capsys, old_image):
    new = si.Image(fresh_functions(), OLD_ORDER)

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

    assert_found_at(new, code, out)
    assert "looks like a function entry" in out


def test_a_change_in_the_neighbours_tail_does_not_matter(tmp_path, monkeypatch, capsys, old_image):
    f = fresh_functions()
    tail = len(f[TARGET - 1]) - 4                       # the last body op, just above `ldp; ret`
    assert f[TARGET - 1][tail][0] == "raw"
    f[TARGET - 1][tail] = ("raw", si.add_imm(3, 4, 0x321))
    new = si.Image(f, OLD_ORDER)

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

    assert_found_at(new, code, out)                     # the old algorithm: "No matches"


def test_a_rewritten_function_is_not_found(tmp_path, monkeypatch, capsys, old_image):
    f = fresh_functions()
    f[TARGET] = new_function(999)
    new = si.Image(f, OLD_ORDER)

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

    assert code == 1 and "No matches" in out            # the old algorithm: "found it", MEDIUM
    assert "NEW FILE OFFSET" not in out


def test_a_function_inserted_in_front_does_not_get_mistaken_for_the_target(
        tmp_path, monkeypatch, capsys, old_image):
    f = fresh_functions()
    f[N_FUNCS] = new_function(1234)
    new = si.Image(f, OLD_ORDER[:TARGET] + [N_FUNCS] + OLD_ORDER[TARGET:])

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

    assert_found_at(new, code, out)                     # the old algorithm: the NEW function's entry
    assert new.entry[TARGET] != new.entry[N_FUNCS]


def test_reordered_neighbours_do_not_move_the_answer_to_another_function(
        tmp_path, monkeypatch, capsys, old_image):
    order = OLD_ORDER[:]
    order[TARGET - 1], order[TARGET + 1] = order[TARGET + 1], order[TARGET - 1]
    new = si.Image(fresh_functions(), order)

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

    assert_found_at(new, code, out)                     # the old algorithm: the entry of fn 152


@pytest.mark.parametrize("touch_neighbour", [False, True])
def test_a_full_relink_re_encodes_every_call_page_and_offset(
        tmp_path, monkeypatch, capsys, old_image, touch_neighbour):
    # A new function near the start shifts everything (every `bl` distance changes) and
    # the data section moves (every adrp page and every lo12 offset changes).
    f = fresh_functions()
    f[N_FUNCS] = new_function(5)
    if touch_neighbour:
        f[TARGET - 1][len(f[TARGET - 1]) - 4] = ("raw", si.add_imm(3, 4, 0x321))
    new = si.Image(f, OLD_ORDER[:10] + [N_FUNCS] + OLD_ORDER[10:], data_base=si.DATA_BASE + 0x3A18)
    assert old_image.function_words(TARGET) != new.function_words(TARGET)     # really re-encoded

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

    assert_found_at(new, code, out)


def test_alignment_padding_between_functions_is_not_part_of_the_answer(
        tmp_path, monkeypatch, capsys):
    old = si.Image(fresh_functions(), OLD_ORDER, padding=3)
    new = si.Image(fresh_functions(), OLD_ORDER, padding=5)

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old, new)

    assert_found_at(new, code, out)
    assert "`ret`" in out                               # the nops sit behind a ret: still an entry


def test_a_body_that_only_starts_the_same_is_graded_down(tmp_path, monkeypatch, capsys, old_image):
    # Same first 16 instructions (all the fingerprint covers), different rest.
    f = fresh_functions()
    ops, words = [], 0
    for op in f[TARGET]:
        if words >= 16:
            break
        ops.append(op)
        words += si._SIZE[op[0]]
    ops += [("raw", si.mul(1, 2, 3))] * 20 + [("raw", si.LDP_FP_LR), ("raw", si.RET)]
    f[TARGET] = ops
    new = si.Image(f, OLD_ORDER)

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

    assert code == 0 and "NEW FILE OFFSET: 0x%x  (confidence: MEDIUM)" % new.entry[TARGET] in out
    assert "[fail] body-similarity" in out


def test_two_identical_functions_are_reported_as_ambiguous_not_guessed(
        tmp_path, monkeypatch, capsys, old_image):
    # The fingerprint alone can't tell identical code apart (--anchors none). What the call sites
    # and body windows add to that is in test_relocate_anchors.py.
    f = fresh_functions()
    f[N_FUNCS] = copy.deepcopy(f[TARGET])               # same code, once more
    new = si.Image(f, OLD_ORDER + [N_FUNCS])

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new, "--anchors", "none")

    assert code == 1 and "More than one match" in out and "--lookahead" in out
    assert "candidate file offset: 0x%x" % new.entry[TARGET] in out
    assert "candidate file offset: 0x%x" % new.entry[N_FUNCS] in out


def test_forcing_the_old_direction_at_a_function_entry_is_an_error_not_a_wrong_answer(
        tmp_path, monkeypatch, capsys, old_image):
    new = si.Image(fresh_functions(), OLD_ORDER)

    code, out, err = relocate(tmp_path, monkeypatch, capsys, old_image, new, "--mode", "before")

    assert code == 2 and "NEW FILE OFFSET" not in out and "--mode after" in err
