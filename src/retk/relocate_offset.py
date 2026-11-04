"""
relocate_offset.py

Automatically re-locates a hook point in a NEW build of an IL2CPP binary
(UnityFramework on iOS, libil2cpp.so on Android, ...), based on its known
location in an OLD build - no Ghidra and no symbol/export name required.

AArch64 ONLY. A fingerprint is made of AArch64 instruction words (and masks over
the bits that hold an address), so it means something only in a binary whose code
is AArch64: an arm64 / arm64e Mach-O, an arm64-v8a ELF, a Windows-on-ARM PE. Both
binaries are checked first, and one that is recognisably something else - an
x86-64 or 32-bit ARM ELF, a Mach-O with no arm64 slice, an x86-64 PE - is refused
with the reason, instead of being searched for byte patterns that are not
instructions there (which finds "matches" that mean nothing). This is a guard, not
support: x86-64 / ARM32 would need their own instruction decoding, wildcarding and
barriers. A file that is none of those containers (a raw blob) can't be told and is
let through, as before.

What gets fingerprinted depends on where the hook point sits (--mode):

  after   The hook point is a FUNCTION ENTRY - which is what a profile's offsets
          normally are (the RVA of the method being hooked). The fingerprint is
          that function's own code, from the hook point forward, up to the first
          instruction that ends straight-line flow (ret, br, b, brk, ...) or
          --lookahead bytes. Operands that change when code or data moves are
          wildcarded rather than ending the run: the offset of every PC-relative
          instruction (bl, b, b.<cond>, cbz/cbnz, tbz/tbnz, adr/adrp, literal
          ldr/prfm) and the lo12 immediate of an add / ldr / str that completes an
          `adrp` pair (the page changes when the data moves, and so does lo12).
  before  The hook point is MID-function, and the instructions in front of it are
          the fingerprint: walk backwards, collecting consecutive instructions that
          do NOT depend on an absolute address (adrp/adr/bl/b/cbz/cbnz/... end the
          run - they encode a relative offset, which changes if the code moves),
          and stop at an undecodable word (literal pool, jump table) or at an
          instruction that ends a function (ret, br, ...): the run never crosses a
          function boundary.
  auto    (default) "after" if the hook point looks like a function entry - the
          word in front of it is a ret/br/b/brk or an undecodable word, possibly
          followed by nop padding - otherwise "before"; and "after" when "before"
          cannot find enough instructions.

Why not always scan backwards: at a function entry the words in front of the hook
point are the TAIL OF THE PREVIOUS FUNCTION, not code of the target. Such a
fingerprint finds that neighbour's tail, so it breaks when the neighbour changes
though the target didn't, and when the target is rewritten, or another function is
inserted in front of it, or the neighbours are reordered, it still finds a unique
match - at the wrong function, passing every soft check. "after" fingerprints the
target itself, and "before" is kept for hook points that really are mid-function.

How it works:
  1. Build the fingerprint (above): a list of (value, mask) instruction words.
  2. Search for it in the new build: every 4-byte-aligned position where all the
     bits that aren't wildcarded are equal. (An all-exact fingerprint is searched
     as a plain byte string, unaligned positions included - they are rejected in
     step 3, and reported as such.)
  3. Validate every raw match before believing it (a byte string alone can't tell
     code from data or from a literal pool that happens to hold the same bytes):
       HARD checks - a candidate that fails one is discarded:
         - alignment: the match starts on a 4-byte boundary (AArch64
           instructions can't start anywhere else);
         - executable section: the fingerprint and the hook point lie inside
           one executable region of the new build (Mach-O sections flagged as
           instructions, or ELF PT_LOAD segments with PF_X; fat Mach-O is
           handled per arm64 slice). Skipped, and reported as such, when the
           file is neither Mach-O nor ELF (e.g. a raw blob).
       SOFT checks - reported and folded into a HIGH/MEDIUM/LOW confidence
       label, never used to discard (the code AT the hook point may legitimately
       differ between builds - see the assumption below):
         - mode "before": the words after the hook point decode at least as
           cleanly as they did in the old build (data/literal-pool bytes usually
           don't), and their mnemonic sequence resembles the old build's;
         - mode "after": the function body (from the hook point to its first
           `ret`, at most BODY_WORDS words) has a mnemonic sequence that resembles
           the old build's - the fingerprint only covers the start of the function,
           this looks at all of it;
         - both: the word just before the fingerprint is the same kind of barrier
           (same mnemonic, or undecodable) as in the old build - for a function
           entry, the end of whatever precedes it.
     Disassembling the fingerprint bytes themselves is deliberately not a
     check: they are the same bytes that were decoded in the old build, so
     the result would be the same by construction.
  4. If exactly ONE candidate survives, print the new FILE offset of the hook
     point, with the checks and the confidence label, then a note on whether that
     number can be used as the RVA (a profile `offsets` entry, or `--offset
     KEY=HEX`) as is or has to be converted first (see below).
     --no-validate skips step 3 (the raw behaviour: unique match = accepted) if
     the format parser misjudges an unusual binary.
  5. Count the votes of the other anchors (see "Several anchors"): they can lower the
     label, settle a tie between candidates, or - when the fingerprint itself found
     nothing - propose one. --anchors none skips this step.

Several anchors (--anchors, on by default): the fingerprint above is one witness, and a
single witness can be fooled - two functions that start alike, a function whose first
instructions changed but whose body didn't, a copy of the function that nobody calls. So
the old build is also cut into other windows that point at the hook point by a different
route, each is searched for in the new build on its own, and where it points is a vote:
  body       windows deeper in the same function (the middle, and the end of its straight-line
             code), a known distance behind the hook point; wildcarded like the fingerprint
  call site  the code around each `bl <hook point>` in the old build (up to 3, skipping calls
             from inside the function); its vote is where that `bl` lands in the new build.
             Needs a scan of the whole old binary for `bl`s (a second or two per 100 MB);
             `--anchors code` skips it. Calls through a register or a vtable, and tail calls,
             are not call sites, so a method reached only like that has none.
  forward    for a hook point in the MIDDLE of a function the main fingerprint is the code in
             front of it, so the code after it is the second opinion.
An anchor found in more than MAX_ANCHOR_HITS places says nothing. One found in exactly one
place either agrees with a candidate or conflicts with it. What the votes may do:
  - a conflict -> LOW ("the anchors disagree about where the hook point went");
  - a window of the function's own code that is no longer where it should be (changed body,
    or moved elsewhere in several places) -> at most MEDIUM;
  - several candidates -> the one that no single-place anchor contradicts and at least one
    agrees with wins; it is capped at MEDIUM if only call sites decided (the code itself
    can't tell identical copies apart), and stays ambiguous (exit 1) otherwise;
  - the main fingerprint found nothing usable -> windows of the function's own code that were
    found in one place each may propose the candidate (typically: the start of the function
    changed, the rest didn't); it needs two agreeing anchors, one of them code, or it is LOW,
    and it is at most MEDIUM. Call sites can confirm or contradict, never propose: a function
    that was rewritten is still called from the same places, and "No matches" stays the answer
    (with the call sites' target printed as a lead to follow in Ghidra).
Votes never RAISE a grade. They exist to catch what one fingerprint can't see; HIGH still
means what it meant before (the checks above pass), now with every anchor that could be
located agreeing. The printed `anchor ...` lines are the vote table. Caveat: a call site's
vote is a file-offset distance, so in a binary whose code spans several executable segments
a `bl` across segments votes wrongly - which shows up as a conflict (LOW), not as a silent
wrong answer.

What this is NOT: it does not build a control-flow graph, find function
boundaries or use symbols. It is still fingerprint matching with sanity
checks around it. Treat HIGH as "very likely", not "proved", and verify the
result once in Ghidra or with a hook before relying on it. In particular, a
function that was rewritten but starts with the same instructions, or two
functions with identical code, are not told apart by the fingerprint alone.

OFFSETS ARE FILE OFFSETS. OLD_OFFSET_HEX is a position in the file passed as
OLD_BINARY (that's what gets `seek`ed/searched), and NEW OFFSET is a position
in NEW_BINARY - not an RVA / Ghidra address / vmaddr, even though the rest of
the repo (profile `offsets`, --offset, Frida's `module.base + offset`) speaks RVA. The
two coincide for a thin Mach-O slice (its __TEXT segment starts at file offset
0), so for the iOS `UnityFramework` case you can pass the RVA straight in. They
do NOT coincide for a fat/universal Mach-O (add the arch slice's file offset)
or for an ELF such as Android's `libil2cpp.so` (depends on the PT_LOAD
segment's p_offset vs p_vaddr - check with `readelf -lW`). Convert OLD_OFFSET
first in those cases. For the NEW offset the tool does the conversion itself:
besides `NEW FILE OFFSET` it prints `NEW RVA` (the thin Mach-O __TEXT address minus
the image base, the fat Mach-O slice's own segments, an ELF's PT_LOAD p_vaddr - the
image base being the lowest mapped page, i.e. Frida's module.base), computed from the
container's headers, and the note printed after each result says which case the new
build looks like. A raw blob has no headers to convert with: no RVA is printed.

--json PATH writes the outcome for the next step - retk verify - as
`{"result": "unique" | "ambiguous" | "none", "candidates": [{"file_offset", "rva",
"confidence", ...}], ...}`. Every accepted candidate is listed, so an AMBIGUOUS result
(exit status 1) can be settled by running them instead of by guessing. Written for every
outcome except a usage/IO error (exit status 2); it names the binaries and offsets of a
real target, so keep it out of git (`relocate*.json` is ignored by this repo's .gitignore).

LOOKING A METHOD UP BY NAME (--name, --new-metadata): when the NEW build's metadata is at hand -
the dump.cs / script.json an IL2CPP dumper wrote for it, or a `NAME ADDRESS` symbol map
(retk/il2cpp_names.py) - the hook point can be found by its `Namespace.Class::Method` instead of by
its bytes. The dump says where the method was compiled to; that RVA becomes the file offset
(NEW FILE OFFSET / NEW RVA, same lines as ever). What that buys: it finds a function that was REWRITTEN,
which no fingerprint can, and it never mistakes a look-alike for the function. What it costs: the dump
must be of the same build as NEW_BINARY, which nothing in the name proves - so when OLD_BINARY and
OLD_OFFSET are given too, the byte fingerprint still runs, as the cross-check:

    the fingerprint finds the same place      HIGH     (the name settles it even if the fingerprint
                                                         alone had found several look-alikes)
    the fingerprint finds nothing             MEDIUM   (rewritten - or the dump is of another build)
    the fingerprint finds somewhere else      both candidates, exit 1: not an answer. Run them with
                                                         retk verify --from-relocate
    no OLD_BINARY at all (name only)          MEDIUM   (nothing to compare it with)

A name the dump does not settle - not in it, or more than one overload - falls back to the byte
fingerprint when there is an OLD_BINARY, and is a failure (exit 1) when there is not. The name path does
not care about the instruction set (the lookup is a table), but the fingerprint does: against a binary
that is not AArch64 only the name is used. The dump and the binary are checked against each other as far as
a name allows: the RVA must lie in a loadable segment, in executable code, and be 4-byte aligned on AArch64.

Assumption: the algorithm/struct layout hasn't changed between the two
builds, only the code has moved due to a rebuild (true for most
minor/patch updates, may not hold for a major update that changes the
logic itself).

Usage:
    retk relocate OLD_BINARY OLD_OFFSET_HEX NEW_BINARY [--mode {auto,before,after}]
                              [--min-instrs N] [--lookahead BYTES] [--lookback BYTES]
                              [--anchors {all,code,none}] [--no-validate] [--json PATH]
                              [--name Namespace.Class::Method[/N] --new-metadata DUMP]
    retk relocate NEW_BINARY --name Namespace.Class::Method[/N] --new-metadata DUMP [--json PATH]

Examples:
    retk relocate UnityFramework_old 0xab68fc8 UnityFramework_new
    retk relocate UnityFramework_old 0xab68fc8 UnityFramework_new \\
        --name ExampleNamespace.ExampleTableA::Unpack/1 --new-metadata dump_new.cs
"""
import contextlib
import io
import json
import os
import re
import sys
import argparse
import mmap
import struct
from dataclasses import dataclass, field, replace
from difflib import SequenceMatcher
from typing import Optional
from capstone import Cs, CsError, CS_ARCH_ARM64, CS_MODE_ARM

from . import il2cpp_names
from . import profiles
from ._common import parse_offset  # same hex parsing as the drivers' --offset

INSTR_LEN = 4  # AArch64: every instruction is a fixed 4 bytes

# Validation (see the module docstring). CONTEXT_WORDS is how many words after
# the hook point are compared between builds; SIMILARITY_MIN is the fraction of
# them whose mnemonic must match for that soft check to pass. Both are
# heuristics, not derived from anything - the raw counts are printed so you can
# judge a result yourself.
CONTEXT_WORDS = 8
SIMILARITY_MIN = 0.5

# Mode "after": BODY_WORDS caps how much of the function (hook point -> first
# `ret`) is compared between builds; BODY_SIMILARITY_MIN is the SequenceMatcher
# ratio of the two mnemonic sequences needed to pass. Heuristic, like the above.
BODY_WORDS = 64
BODY_SIMILARITY_MIN = 0.75

WORD_MASK = 0xFFFFFFFF   # "every bit of this word must match"

# Anchors that vote (see the module docstring, "Several anchors"). All of these are
# heuristics, like the numbers above; the printed vote table shows what they decided.
#   MAX_ANCHOR_HITS    an anchor found in more places than this is too generic to say
#                      anything - it abstains rather than vote for all of them.
#   BODY_SCAN_WORDS    how far into the function (straight-line, up to the first
#                      ret/br/b/brk) windows for the body anchors are taken from.
#   BODY_WINDOW_WORDS  size of one body window, in instructions.
#   MAX_BODY_ANCHORS   body windows used (one in the middle, one at the end).
#   MAX_CALLERS        call sites of the old function used as anchors.
#   CALLER_*_WORDS     instructions around a call site that make up its window.
MAX_ANCHOR_HITS = 8
BODY_SCAN_WORDS = 256
BODY_WINDOW_WORDS = 8
MAX_BODY_ANCHORS = 2
MAX_CALLERS = 3
CALLER_BEFORE_WORDS = 6
CALLER_AFTER_WORDS = 3
MAX_CALL_SITES_SCANNED = 64      # windows built per run, before keeping the best MAX_CALLERS
CODE_KINDS = ("entry", "before", "forward", "body")   # anchors made of the function's own code
ANCHOR_SCOPES = ("all", "code", "none")

# Instructions after which execution does not fall through to the next word. The
# word in front of a function entry is always one of these (or padding/data), and
# a backward run must never walk across one: what is behind it is another function
# (or at best another basic block), not a straight line into the hook point.
_TERMINATORS = frozenset({
    "ret", "retaa", "retab", "eret", "eretaa", "eretab", "drps",
    "br", "braa", "braaz", "brab", "brabz",
    "b",                     # unconditional; the conditional b.<cond> falls through
    "brk", "hlt", "udf",
})
# The terminators that really end a function when read straight through (an
# unconditional `b` or a `br` can also be a jump inside the same function).
_FUNCTION_END = frozenset({"ret", "retaa", "retab", "eret", "eretaa", "eretab"})

# Binary-format constants used by executable_ranges().
CPU_TYPE_ARM64 = 0x0100000C          # arm64 and arm64e share this cputype
MH_MAGIC_64 = 0xFEEDFACF             # thin 64-bit Mach-O, little-endian
FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF   # big-endian on disk
LC_SEGMENT_64 = 0x19
VM_PROT_EXECUTE = 0x4
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
PT_LOAD, PF_X = 1, 1

# What detect_architecture() reports, for naming the problem to the user.
EM_AARCH64 = 183
PE_MACHINE_ARM64 = 0xAA64
_ELF_MACHINES = {183: "AArch64", 62: "x86-64", 40: "32-bit ARM", 3: "x86 (32-bit)", 243: "RISC-V",
                 8: "MIPS", 20: "PowerPC", 21: "PowerPC64"}
_MACHO_CPUS = {0x0100000C: "arm64", 0x0200000C: "arm64_32", 0x01000007: "x86_64", 12: "32-bit arm",
               7: "i386", 0x01000012: "ppc64", 18: "ppc"}
_PE_MACHINES = {0xAA64: "ARM64", 0x8664: "x86-64", 0x14C: "x86 (32-bit)", 0x1C4: "32-bit ARM (Thumb-2)",
                0xA641: "ARM64EC", 0x200: "Itanium"}


class RelocateError(RuntimeError):
    """A problem with the inputs or with what the fingerprint found - as
    opposed to a bug. main() reports these as one `[!]` line, no traceback.
    (Subclasses RuntimeError so callers that already catch that keep working.)"""


class TooFewInstructions(RelocateError):
    """The input was fine, but the run of usable instructions around the hook
    point is shorter than --min-instrs. The one error `--mode auto` answers by
    trying the other direction."""


def check_offset(path, offset, need_before=True):
    """Reject an `offset` that can't be a fingerprint anchor in `path`, with a
    message that names the real problem. Without this, a bad offset just
    produced "found 0 safe instructions - try a larger lookback", which is the
    wrong advice: no lookback window fixes an offset that's out of range or
    misaligned.

    `need_before`: the fingerprint is made of the words in front of `offset`
    (mode "before"). Otherwise (mode "after") it is made of the words from
    `offset` on, so one must exist there instead."""
    if offset % INSTR_LEN:
        raise RelocateError(
            f"offset 0x{offset:x} is not {INSTR_LEN}-byte aligned - AArch64 code is "
            f"fixed-width, so a function can't start here. Is it the right kind of "
            f"offset? (This tool takes FILE offsets - see the module docstring.)")
    size = os.path.getsize(path)  # OSError (missing file) is handled by main()
    if offset > size or (not need_before and offset + INSTR_LEN > size):
        raise RelocateError(
            f"offset 0x{offset:x} is past the end of {path} (0x{size:x} bytes). This "
            f"tool takes FILE offsets; if 0x{offset:x} is an RVA / Ghidra address, it "
            f"only equals the file offset for a thin Mach-O slice - for a fat "
            f"Mach-O or an ELF ({profiles.PLATFORM_MODULES['android']}) convert it first.")
    if need_before and offset < INSTR_LEN:
        raise RelocateError(
            f"offset 0x{offset:x} has no instructions before it to fingerprint.")


def is_pc_relative(insn):
    """True if `insn`'s encoding depends on its own address, so it can't be
    reused as-is once the surrounding code moves.

    This is the single source of truth for that classification (see
    test_relocate_offset.py's is_pc_relative_* tests) - don't duplicate the
    mnemonic list elsewhere as a plain set/tuple: a flat list can't express
    the b.<cond> variants or tell literal-pool ldr from base-register ldr -
    the exact distinction handled below."""
    if insn.mnemonic in ("adrp", "adr", "bl", "cbz", "cbnz", "tbz", "tbnz"):
        return True
    if insn.mnemonic == "b" or insn.mnemonic.startswith("b."):
        return True
    # "ldr xN, #imm" / "prfm <prfop>, #imm" (literal pool) is PC-relative;
    # "ldr wN, [xM, #imm]" / "prfm <prfop>, [xM, #imm]" is not.
    if insn.mnemonic in ("ldr", "ldrsw", "prfm") and "[" not in insn.op_str:
        return True
    return False


def is_terminator(insn):
    """True if execution does not fall through `insn` to the next word (ret, br,
    unconditional b, brk, ...). A call (bl/blr) returns, so it is not one."""
    return insn.mnemonic in _TERMINATORS


def is_barrier(insn):
    """Ends a backward run: either it can't be reused as-is once the code moves
    (PC-relative), or the word after it starts something else (terminator)."""
    return is_pc_relative(insn) or is_terminator(insn)


def operand_mask(insn):
    """The bits of `insn`'s encoding that stay the same when the code or data it
    refers to moves: all of them, except the immediate of a PC-relative
    instruction (a rebuild re-encodes that, the opcode and registers stay)."""
    if not is_pc_relative(insn):
        return WORD_MASK
    if insn.mnemonic in ("b", "bl"):
        return 0xFC000000                  # imm26
    if insn.mnemonic in ("tbz", "tbnz"):
        return 0xFFF8001F                  # imm14 (b5/b40 and the register are kept)
    if insn.mnemonic in ("adr", "adrp"):
        return 0x9F00001F                  # immlo + immhi (op and Rd are kept)
    return 0xFF00001F                      # imm19: b.<cond>, cbz/cbnz, literal ldr/ldrsw/prfm


# `adrp xN, page` is followed by an instruction that adds the offset within the
# page - `add xM, xN, #lo12`, or a load/store `[xN, #lo12]`. The page changes when
# the data moves, and so does lo12, so that immediate is wildcarded too.
_ADD_SUB_IMM = (0x1F800000, 0x11000000)    # add/sub[s] (immediate): bits 28:23 = 100010
_LDST_UIMM = (0x3B000000, 0x39000000)      # load/store, unsigned immediate offset (GPR and SIMD&FP)
_IMM12_BITS = 0x003FFC00                   # bits 21:10
_ADD_SH_BIT = 0x00400000                   # bit 22: add/sub imm12 shifted left by 12


def _reg_number(name):
    """"x8" / "w8" -> 8; None for anything else (sp, xzr, v0, ...)."""
    return int(name[1:]) if name and name[0] in "xw" and name[1:].isdigit() else None


def wildcard_masks(insns):
    """Per-instruction masks (bits that must match) for a straight run of decoded
    instructions, from a Cs with `detail = True`: `operand_mask`, plus the lo12
    immediate of an add / load / store whose base register still holds the page
    address an earlier `adrp` produced. A register stops being "the page address"
    when anything writes to it, so `adrp x8; ldr x8, [x8, #lo12]; ldr x0, [x8, #0x10]`
    wildcards the first load and keeps the second: 0x10 is a field offset in the
    object that was loaded, and it doesn't move with the data. Straight-line
    approximation - it doesn't follow branches."""
    masks, page_regs = [], set()
    for insn in insns:
        word = int.from_bytes(insn.bytes, "little")
        mask = operand_mask(insn)
        base = (word >> 5) & 0x1F
        if base in page_regs:
            if (word & _ADD_SUB_IMM[0]) == _ADD_SUB_IMM[1]:
                mask &= ~(_IMM12_BITS | _ADD_SH_BIT)
            elif (word & _LDST_UIMM[0]) == _LDST_UIMM[1]:
                mask &= ~_IMM12_BITS
        try:
            written = insn.regs_access()[1]
            page_regs -= {_reg_number(insn.reg_name(r)) for r in written}
        except CsError:
            pass                           # no register info: keep the taint, wildcard a bit more
        if insn.mnemonic == "adrp" and (word & 0x1F) != 31:
            page_regs.add(word & 0x1F)
        masks.append(mask & WORD_MASK)
    return masks


def build_fingerprint(old_path, old_offset, min_instrs, lookback_window=64):
    """Mode "before": the run of position-independent instructions in front of
    `old_offset`, as bytes. Never crosses a PC-relative instruction, an
    undecodable word or a terminator (ret, br, b, ...)."""
    if min_instrs < 1:
        raise RelocateError(f"--min-instrs must be >= 1 (got {min_instrs}).")
    check_offset(old_path, old_offset)
    base = max(0, old_offset - lookback_window)
    if old_offset - base < INSTR_LEN:
        raise RelocateError("Could not disassemble anything before old_offset - increase lookback_window.")

    with open(old_path, "rb") as f:
        f.seek(base)
        chunk = f.read(old_offset - base)

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    # Walk backwards from the instruction closest to the offset, stopping as
    # soon as a barrier is hit: a PC-relative instruction, an undecodable word,
    # or a terminator (ret, br, b, ...) - the last one is what keeps the walk from
    # leaving the function the hook point is in. AArch64 is fixed-width, so
    # decode one word at a time: md.disasm() on the whole chunk silently stops at
    # the first undecodable word (literal pool, jump table, ...), and the bytes
    # after it - never checked for PC-relative instructions - would end up in the
    # fingerprint.
    safe_insns, barrier = [], None
    for addr in range(old_offset - INSTR_LEN, base - 1, -INSTR_LEN):
        word = chunk[addr - base:addr - base + INSTR_LEN]
        insn = next(md.disasm(word, addr), None)
        if insn is None or is_barrier(insn):
            barrier = insn
            break
        safe_insns.insert(0, insn)

    if len(safe_insns) < min_instrs:
        hint = ""
        if barrier is not None and is_terminator(barrier):
            hint = (f" The run stops at a `{barrier.mnemonic}`, so this offset looks like a function "
                    f"entry: the words before it belong to the previous function. Use --mode after "
                    f"to fingerprint the function's own code instead.")
        raise TooFewInstructions(
            f"Only found {len(safe_insns)} consecutive safe instructions right "
            f"before the offset (need >= {min_instrs}). Try a larger lookback_window or a lower --min-instrs."
            + hint
        )

    fp_start = safe_insns[0].address
    fp_len = old_offset - fp_start
    with open(old_path, "rb") as f:
        f.seek(fp_start)
        fingerprint = f.read(fp_len)

    print(f"[+] Fingerprint: {len(safe_insns)} instructions, {fp_len} bytes, from 0x{fp_start:x} to 0x{old_offset:x}")
    for insn in safe_insns:
        print(f"      0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")

    return fingerprint


def find_new_offset(new_path, fingerprint):
    with open(new_path, "rb") as f:
        data = f.read()

    idxs = []
    start = 0
    while True:
        i = data.find(fingerprint, start)
        if i == -1:
            break
        idxs.append(i)
        start = i + 1

    return idxs


# --------------------------------------------------------------------------
# Fingerprints: what to search for, and where the hook point sits in it
# --------------------------------------------------------------------------

@dataclass
class Fingerprint:
    """A window of the old build's code that can be looked for in the new build:
    the main fingerprint, and also each anchor that votes (see "Several anchors").

    `words` is a list of (value, mask) pairs, one per instruction (value is
    already `& mask`). `hook_delta` is the distance in bytes from the first word
    to the hook point: the whole fingerprint for mode "before" (the hook point is
    right after it), 0 for mode "after" (the hook point is its first word), and
    negative for a body anchor, whose window lies further into the function (the
    hook point is `-hook_delta` bytes in front of it).

    `kind` says what the window is - "entry" (the function's own code from the hook
    point forward), "before" (the instructions in front of a mid-function hook
    point), "forward" (the code after a mid-function hook point, as a second
    opinion), "body" (a window deeper into the function) or "caller" (the code
    around a call site of the old function). A "caller" window doesn't point at
    the hook point by distance: its vote is where the `bl` at word index `xref`
    lands in the new build. `complete` is set when the window reaches the end of
    the function's straight-line code (a terminator), so no body window exists."""
    mode: str
    words: list
    hook_delta: int
    kind: str = "entry"
    label: str = ""
    xref: Optional[int] = None
    complete: bool = False

    def __post_init__(self):
        if not self.label:
            self.label = self.kind

    def __len__(self):                         # in bytes
        return INSTR_LEN * len(self.words)

    @property
    def is_exact(self):
        return all(mask == WORD_MASK for _value, mask in self.words)

    @property
    def n_wildcarded(self):
        return sum(1 for _value, mask in self.words if mask != WORD_MASK)

    def as_bytes(self):
        return b"".join(struct.pack("<I", value) for value, _mask in self.words)

    @classmethod
    def from_bytes(cls, data, mode="before"):
        """An all-exact fingerprint from raw bytes (what build_fingerprint returns)."""
        words = [(w, WORD_MASK) for w in struct.unpack(f"<{len(data) // INSTR_LEN}I", data)]
        return cls(mode, words, len(data) if mode == "before" else 0,
                   kind="before" if mode == "before" else "entry")


def _straight_run(path, offset, n_words):
    """Decode the straight-line code from `offset` in `path`: up to `n_words`
    words, ending after the first terminator (ret, br, b, brk - past it is
    another function or an unrelated block), at an undecodable word, at the end
    of the file or at the word limit. Returns (instructions, what stopped it) -
    the `Cs` has `detail` on, which wildcard_masks needs."""
    n_words = min(n_words, (os.path.getsize(path) - offset) // INSTR_LEN)
    if n_words < 1:
        return [], "the end of the file"
    with open(path, "rb") as f:
        f.seek(offset)
        chunk = f.read(n_words * INSTR_LEN)

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True                           # wildcard_masks needs the registers written
    insns, stopped_by = [], "the lookahead window"
    for i in range(n_words):
        insn = next(md.disasm(chunk[i * INSTR_LEN:(i + 1) * INSTR_LEN], offset + i * INSTR_LEN), None)
        if insn is None:
            stopped_by = "an undecodable word"
            break
        insns.append(insn)
        if is_terminator(insn):
            stopped_by = f"`{insn.mnemonic}`"
            break
    return insns, stopped_by


def _masked_words(insns, masks):
    return [(int.from_bytes(i.bytes, "little") & m, m) for i, m in zip(insns, masks)]


def build_entry_fingerprint(old_path, old_offset, min_instrs, lookahead_window=64, verbose=True):
    """Mode "after": the function's own code from `old_offset` forward, with the
    operands that move wildcarded (see wildcard_masks). Ends after the first
    terminator (ret, br, b, brk - past it is another function or an unrelated
    block), at an undecodable word, or after `lookahead_window` bytes.
    `min_instrs` counts the instructions with no wildcard in them: a run of
    nothing but `bl`s would match every call sequence in the binary."""
    if min_instrs < 1:
        raise RelocateError(f"--min-instrs must be >= 1 (got {min_instrs}).")
    check_offset(old_path, old_offset, need_before=False)
    n_words = min(lookahead_window, os.path.getsize(old_path) - old_offset) // INSTR_LEN
    if n_words < 1:
        raise RelocateError("Could not disassemble anything at old_offset - increase --lookahead.")

    insns, stopped_by = _straight_run(old_path, old_offset, n_words)
    masks = wildcard_masks(insns)
    n_exact = sum(1 for m in masks if m == WORD_MASK)
    if n_exact < min_instrs:
        raise TooFewInstructions(
            f"Only found {n_exact} fully fixed instructions (of {len(insns)}) in the function's own "
            f"code from the offset forward (stopped at {stopped_by}); need >= {min_instrs}. "
            f"Try a larger --lookahead or a lower --min-instrs.")

    words = _masked_words(insns, masks)
    n_masked = len(insns) - n_exact
    if verbose:
        print(f"[+] Fingerprint: the function's own code from the hook point forward - {len(insns)} instructions "
              f"({n_masked} with a wildcarded operand, marked *), {len(insns) * INSTR_LEN} bytes, from "
              f"0x{old_offset:x} to 0x{old_offset + len(insns) * INSTR_LEN:x} (stopped at {stopped_by})")
        for insn, m in zip(insns, masks):
            print(f"     {'*' if m != WORD_MASK else ' '}0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
    return Fingerprint("after", words, 0, complete=is_terminator(insns[-1]))


def entry_context(path, offset, max_padding=8):
    """If the words in front of `offset` look like the end of a previous function
    - a terminator (ret, br, b, brk, ...) or an undecodable word, with nothing but
    nop padding in between - return what they are, e.g. "`ret`"; otherwise None.
    A hook point in the middle of a function has an ordinary instruction (or a
    call, or a conditional branch) in front of it."""
    if offset == 0:
        return "the start of the file"
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    base = max(0, offset - INSTR_LEN * (max_padding + 1))
    with open(path, "rb") as f:
        f.seek(base)
        chunk = f.read(offset - base)
    for addr in range(offset - INSTR_LEN, base - 1, -INSTR_LEN):
        insn = next(md.disasm(chunk[addr - base:addr - base + INSTR_LEN], addr), None)
        if insn is None:
            return "an undecodable word"
        if is_terminator(insn):
            return f"`{insn.mnemonic}`"
        if insn.mnemonic != "nop":
            return None
    return "the start of the file" if base == 0 else None


def choose_fingerprint(old_path, old_offset, mode, min_instrs, lookback, lookahead):
    """Build the fingerprint for `mode` ("auto", "before" or "after", see the
    module docstring)."""
    if mode == "after":
        return build_entry_fingerprint(old_path, old_offset, min_instrs, lookahead)
    if mode == "before":
        return Fingerprint.from_bytes(build_fingerprint(old_path, old_offset, min_instrs, lookback))

    # Only look at what precedes the offset if it can be read at all; a bad offset
    # is reported by whichever builder runs next, with its own message.
    in_file = old_offset % INSTR_LEN == 0 and old_offset < os.path.getsize(old_path)
    before = entry_context(old_path, old_offset) if in_file else None
    if before:
        print(f"[i] The word before the hook point is {before}: this looks like a function entry, so the "
              f"function's own code is fingerprinted, not what precedes it (--mode after).")
        return build_entry_fingerprint(old_path, old_offset, min_instrs, lookahead)
    try:
        return Fingerprint.from_bytes(build_fingerprint(old_path, old_offset, min_instrs, lookback))
    except TooFewInstructions as before_error:
        try:
            fp = build_entry_fingerprint(old_path, old_offset, min_instrs, lookahead)
        except TooFewInstructions as after_error:
            raise TooFewInstructions(f"{before_error} Fingerprinting the code from the hook point "
                                     f"forward didn't work either: {after_error}") from None
        except RelocateError:              # the offset itself is unusable in that direction
            raise before_error from None
        print("[i] Too few position-independent instructions in front of the hook point; "
              "fingerprinting the code from the hook point forward instead (--mode after).")
        return fp


def masked_matches(data, words, limit=None, counts=None):
    """4-byte-aligned offsets in `data` (the bytes of a whole binary) where every
    (value, mask) word of a fingerprint matches. Anchors on the fully fixed word
    that occurs least often in the file (a C-speed `bytes.find`), then checks the
    whole pattern around each hit. `limit` stops after that many matches (an anchor
    that common is not worth listing in full); `counts` is a cache of how often a
    word occurs, shared between searches of the same `data`."""
    fixed = [(j, value) for j, (value, mask) in enumerate(words) if mask == WORD_MASK]
    if not fixed:
        raise RelocateError("A fingerprint without a single fully fixed instruction can't be searched for.")
    if counts is None:
        counts = {}

    def occurrences(value):
        if value not in counts:
            counts[value] = data.count(struct.pack("<I", value))
        return counts[value]

    j, value = min(fixed, key=lambda jv: occurrences(jv[1]))
    needle, span, fmt = struct.pack("<I", value), INSTR_LEN * len(words), f"<{len(words)}I"
    found = []
    i = data.find(needle)
    while i != -1:
        p = i - INSTR_LEN * j
        if i % INSTR_LEN == 0 and p >= 0 and p + span <= len(data):
            if all(got & mask == want for got, (want, mask) in zip(struct.unpack_from(fmt, data, p), words)):
                found.append(p)
                if limit is not None and len(found) >= limit:
                    break
        i = data.find(needle, i + 1)
    return found


def find_masked_matches(path, words):
    """masked_matches() on the file at `path`."""
    with open(path, "rb") as f:
        data = f.read()
    return masked_matches(data, words)


def find_matches(new_path, fingerprint):
    """Raw matches (file offsets of the fingerprint's first byte) in the new build."""
    if fingerprint.is_exact:
        return find_new_offset(new_path, fingerprint.as_bytes())   # plain byte search, unaligned hits included
    return find_masked_matches(new_path, fingerprint.words)


# --------------------------------------------------------------------------
# Executable regions (Mach-O / ELF), as FILE offsets
# --------------------------------------------------------------------------

def _macho_exec_ranges(buf, base):
    """Executable (start, end, label) file ranges of the thin 64-bit Mach-O
    whose header sits at `base` in `buf`. Sections carrying the instruction
    attributes are preferred; if there are none, executable segments are used.
    All offsets are made absolute by adding `base`, so this also serves the
    slices of a fat binary. Raises struct.error on a truncated/garbled file."""
    _magic, _cputype, _sub, _ftype, ncmds, sizeofcmds = struct.unpack_from("<IiiIII", buf, base)
    off = base + 32                      # mach_header_64 is 32 bytes
    cmds_end = off + sizeofcmds
    sections, segments = [], []
    for _ in range(ncmds):
        if off + 8 > cmds_end:
            break
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmdsize < 8 or off + cmdsize > cmds_end:
            break
        if cmd == LC_SEGMENT_64:
            segname = bytes(buf[off + 8:off + 24]).split(b"\0")[0].decode("ascii", "replace")
            fileoff, filesize = struct.unpack_from("<QQ", buf, off + 40)
            _maxprot, initprot, nsects, _flags = struct.unpack_from("<iiII", buf, off + 56)
            if initprot & VM_PROT_EXECUTE and filesize:
                segments.append((base + fileoff, base + fileoff + filesize, f"segment {segname}"))
            sec = off + 72               # segment_command_64 is 72 bytes
            for _i in range(nsects):     # section_64 is 80 bytes
                sectname = bytes(buf[sec:sec + 16]).split(b"\0")[0].decode("ascii", "replace")
                size, = struct.unpack_from("<Q", buf, sec + 40)
                offset, = struct.unpack_from("<I", buf, sec + 48)
                sflags, = struct.unpack_from("<I", buf, sec + 64)
                if sflags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) and size:
                    sections.append((base + offset, base + offset + size, f"{segname},{sectname}"))
                sec += 80
        off += cmdsize
    return sections or segments


def _elf_exec_ranges(buf):
    """Executable PT_LOAD segments (PF_X) of a 64-bit little-endian ELF, as
    file ranges. Segment-level, so coarser than section-level (it includes
    things like .plt next to .text) - but it works on files whose section
    headers were stripped, which libil2cpp.so-style targets often are."""
    e_phoff, = struct.unpack_from("<Q", buf, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", buf, 0x36)
    ranges = []
    for i in range(e_phnum):
        p = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, _vaddr, _paddr, p_filesz = struct.unpack_from("<IIQQQQ", buf, p)
        if p_type == PT_LOAD and p_flags & PF_X and p_filesz:
            ranges.append((p_offset, p_offset + p_filesz, f"PT_LOAD #{i} (flags 0x{p_flags:x})"))
    return ranges


def executable_ranges(buf):
    """Where code can live in `buf` (bytes or an mmap of a whole binary).

    Returns (format_name, [(start, end, label), ...]) with FILE offsets, or
    None if the file isn't a recognised/well-formed Mach-O or ELF - callers
    must treat that as "can't tell", not "no code". A fat Mach-O contributes
    only its arm64 slices (an empty list if it has none)."""
    try:
        head = bytes(buf[:4])
        if head == b"\x7fELF":
            if buf[4] != 2 or buf[5] != 1:      # not ELFCLASS64 / ELFDATA2LSB
                return None
            return "ELF64", _elf_exec_ranges(buf)
        if head == struct.pack("<I", MH_MAGIC_64):
            return "Mach-O", _macho_exec_ranges(buf, 0)
        magic, = struct.unpack(">I", head)
        if magic in (FAT_MAGIC, FAT_MAGIC_64):
            nfat, = struct.unpack_from(">I", buf, 4)
            if nfat == 0 or nfat > 32:          # 0xcafebabe is also the Java class magic
                return None
            ranges = []
            for i in range(nfat):
                if magic == FAT_MAGIC:          # fat_arch: 5 x u32
                    cputype, _sub, offset, _size, _align = struct.unpack_from(">iiIII", buf, 8 + 20 * i)
                else:                           # fat_arch_64: cputype, sub, u64, u64, u32, u32
                    cputype, _sub, offset, _size, _align, _res = struct.unpack_from(">iiQQII", buf, 8 + 32 * i)
                if cputype != CPU_TYPE_ARM64:
                    continue
                # A truncated or non-Mach-O slice is skipped, not treated as
                # "this whole file is unrecognised" - otherwise a single bad
                # slice would drop the executable-section hard check for the
                # valid arm64 slice sitting next to it.
                if offset < 0 or offset + 4 > len(buf):
                    continue
                if bytes(buf[offset:offset + 4]) != struct.pack("<I", MH_MAGIC_64):
                    continue
                ranges += _macho_exec_ranges(buf, offset)
            return "fat Mach-O (arm64 slices)", ranges
    except (struct.error, IndexError):
        pass
    return None


def detect_architecture(buf):
    """What `buf` (the start of a binary - 64 KiB is plenty) is, as
    (container, [architecture names], is_aarch64), or None when it isn't a
    recognised Mach-O / fat Mach-O / ELF / PE (callers must treat that as "can't
    tell", not "unsupported"). `is_aarch64` means the code the fingerprint is made
    of can be there: a 64-bit little-endian ELF for AArch64, a thin Mach-O of cputype
    arm64 (arm64e included), a fat Mach-O with at least one such slice, a PE whose
    machine is ARM64."""
    try:
        head = bytes(buf[:4])
        if head == b"\x7fELF":
            ei_class, ei_data = buf[4], buf[5]
            if ei_class not in (1, 2) or ei_data not in (1, 2):
                return None
            machine, = struct.unpack_from("<H" if ei_data == 1 else ">H", buf, 0x12)
            name = _ELF_MACHINES.get(machine, f"machine {machine}")
            container = f"{'64' if ei_class == 2 else '32'}-bit {'little' if ei_data == 1 else 'big'}-endian ELF"
            return container, [name], machine == EM_AARCH64 and ei_class == 2 and ei_data == 1
        magic_le, = struct.unpack("<I", head)
        if magic_le in (MH_MAGIC_64, 0xFEEDFACE):                # thin Mach-O, little-endian
            cputype, = struct.unpack_from("<i", buf, 4)
            container = "Mach-O" if magic_le == MH_MAGIC_64 else "32-bit Mach-O"
            return container, [_MACHO_CPUS.get(cputype, f"cputype {cputype:#x}")], \
                cputype == CPU_TYPE_ARM64 and magic_le == MH_MAGIC_64
        if magic_le in (0xCEFAEDFE, 0xCFFAEDFE):                 # big-endian Mach-O (PowerPC)
            cputype, = struct.unpack_from(">i", buf, 4)
            return "big-endian Mach-O", [_MACHO_CPUS.get(cputype, f"cputype {cputype:#x}")], False
        magic, = struct.unpack(">I", head)
        if magic in (FAT_MAGIC, FAT_MAGIC_64):
            nfat, = struct.unpack_from(">I", buf, 4)
            if nfat == 0 or nfat > 32:                           # 0xcafebabe is also the Java class magic
                return None
            cpus = []
            for i in range(nfat):
                at = 8 + (20 if magic == FAT_MAGIC else 32) * i
                cpus.append(struct.unpack_from(">i", buf, at)[0])
            return ("fat Mach-O", [_MACHO_CPUS.get(c, f"cputype {c:#x}") for c in cpus],
                    CPU_TYPE_ARM64 in cpus)
        if head[:2] == b"MZ":
            e_lfanew, = struct.unpack_from("<I", buf, 0x3C)
            if bytes(buf[e_lfanew:e_lfanew + 4]) != b"PE\0\0":
                return None
            machine, = struct.unpack_from("<H", buf, e_lfanew + 4)
            return "PE", [_PE_MACHINES.get(machine, f"machine {machine:#x}")], machine == PE_MACHINE_ARM64
    except (struct.error, IndexError):
        pass
    return None


def check_architecture(path, which):
    """Refuse a binary that is recognisably not AArch64 code (see the module
    docstring): `which` ("old" / "new") says which of the two it was. A file that
    isn't a recognised container passes - it can't be told."""
    with open(path, "rb") as f:                                  # OSError is handled by main()
        found = detect_architecture(f.read(0x10000))
    if found is None or found[2]:
        return
    container, archs, _ = found
    raise RelocateError(
        f"the {which} binary {path} is a {container} for {', '.join(archs)}, not AArch64. This tool "
        f"fingerprints AArch64 instruction words, which are not instructions here, so a search would "
        f"'find' byte patterns that mean nothing. It supports arm64 / arm64e Mach-O (a fat binary needs "
        f"an arm64 slice), arm64-v8a ELF and ARM64 PE only - for another architecture, re-locate the "
        f"hook in a disassembler (Ghidra), or use the profile's `--offset` once you know it.")


# --------------------------------------------------------------------------
# Candidate validation
# --------------------------------------------------------------------------

@dataclass
class Check:
    name: str
    status: str     # "pass" | "fail" | "n/a"
    detail: str


@dataclass
class Candidate:
    match: int      # file offset of the fingerprint's first byte in the new build
    offset: int     # match + len(fingerprint): the relocated hook offset
    rejected: list = field(default_factory=list)   # hard-check failures; non-empty => discarded
    checks: list = field(default_factory=list)
    confidence: str = "n/a"                         # HIGH / MEDIUM / LOW, or "rejected"
    via: str = "fingerprint"                        # "fingerprint" (the main one), or "anchor" (proposed by one)
    votes: list = field(default_factory=list)       # one Vote per anchor, once they have been counted
    note: str = ""                                  # why the votes changed the confidence, if they did


def _mnemonics(md, data, addr):
    """Mnemonic (None if undecodable) of each whole 4-byte word in `data`,
    which starts at `addr`. One word at a time, for the same reason as in
    build_fingerprint: md.disasm() on a run stops silently at the first
    undecodable word."""
    out = []
    for i in range(0, len(data) - len(data) % INSTR_LEN, INSTR_LEN):
        insn = next(md.disasm(data[i:i + INSTR_LEN], addr + i), None)
        out.append(insn.mnemonic if insn else None)
    return out


def _body_mnemonics(md, data, addr):
    """Mnemonics of a function body: from `addr` up to and including the first
    `ret` (or the first undecodable word, as None), one word at a time."""
    out = []
    for i in range(0, len(data) - len(data) % INSTR_LEN, INSTR_LEN):
        insn = next(md.disasm(data[i:i + INSTR_LEN], addr + i), None)
        out.append(insn.mnemonic if insn else None)
        if insn is None or insn.mnemonic in _FUNCTION_END:
            break
    return out


def _barrier_label(md, word, addr):
    """The label of the instruction that ended a fingerprint run - its
    mnemonic, or "<undecodable>" - or None if `word` is not a barrier
    (PC-relative / terminator / undecodable): then the run ended for another
    reason."""
    insn = next(md.disasm(word, addr), None)
    if insn is None:
        return "<undecodable>"
    return insn.mnemonic if is_barrier(insn) else None


_SOFT_CHECKS = ("after-decode", "before-anchor", "after-similarity", "body-similarity")


def _confidence(checks):
    status = {c.name: c.status for c in checks}
    soft_fails = [n for n, s in status.items() if s == "fail" and n in _SOFT_CHECKS]
    if "after-decode" in soft_fails or len(soft_fails) >= 2:
        return "LOW"
    # The one similarity check that applies to the mode ("before": the words after
    # the hook point; "after": the whole function body) has to pass for HIGH.
    similarity = status.get("after-similarity", status.get("body-similarity"))
    if not soft_fails and status.get("executable-section") == "pass" and similarity == "pass":
        return "HIGH"
    return "MEDIUM"


def validate_candidates(old_path, old_offset, new_path, fingerprint, matches,
                        context_words=CONTEXT_WORDS, proposed=()):
    """Turn raw byte matches (start offsets in the new build, from
    find_new_offset) into Candidates: hard checks decide `rejected`, soft
    checks and the confidence label describe the rest. See the module
    docstring for what each check is and why.

    `proposed` are hook offsets (not fingerprint matches) that an anchor points
    at - they go through the same checks, as candidates with `via == "anchor"`;
    the geometry of `fingerprint` (where its window sits relative to the hook
    point) is what the soft checks use for them too."""
    if not matches and not proposed:
        return []
    if not isinstance(fingerprint, Fingerprint):          # raw bytes: a mode "before" fingerprint
        fingerprint = Fingerprint.from_bytes(fingerprint)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    fp_len, hook_delta = len(fingerprint), fingerprint.hook_delta
    after_mode = fingerprint.mode == "after"
    window = INSTR_LEN * context_words

    # What the old build looked like around the hook point.
    with open(old_path, "rb") as f:
        f.seek(old_offset)
        old_code = f.read(max(window, INSTR_LEN * BODY_WORDS))
        old_after = _mnemonics(md, old_code[:window], old_offset)
        old_body = _body_mnemonics(md, old_code, old_offset)
        old_anchor = None
        fp_start = old_offset - hook_delta
        if fp_start >= INSTR_LEN:
            f.seek(fp_start - INSTR_LEN)
            old_anchor = _barrier_label(md, f.read(INSTR_LEN), fp_start - INSTR_LEN)

    # (match, hook point, first and one-past-last byte that must be code, who found it)
    items = [(m, m + hook_delta, m, max(m + fp_len, m + hook_delta + INSTR_LEN), "fingerprint")
             for m in matches]
    seen = {hook for _m, hook, _lo, _hi, _via in items}
    items += [(h - hook_delta, h, h, h + INSTR_LEN, "anchor") for h in dict.fromkeys(proposed) if h not in seen]

    candidates = []
    with open(new_path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        found = executable_ranges(mm)
        for m, hook, lo, hi, via in items:
            c = Candidate(match=m, offset=hook, via=via)
            what = "match starts" if via == "fingerprint" else "an anchor points"

            # -- hard: alignment ------------------------------------------
            if lo % INSTR_LEN:
                c.rejected.append(
                    f"{what} at 0x{lo:x}, not on a {INSTR_LEN}-byte boundary - AArch64 "
                    f"instructions can't start there, so this is data or a coincidence")
            else:
                c.checks.append(Check("alignment", "pass", f"0x{lo:x} is {INSTR_LEN}-byte aligned"))

            # -- hard: inside an executable region ---------------------------
            region = None
            if found is None:
                c.checks.append(Check("executable-section", "n/a",
                                      "file is not a recognised Mach-O/ELF - can't tell code from data"))
            else:
                fmt, ranges = found
                # The fingerprint and the hook point (and the word at it) must all be in
                # one region: for "before" the hook point is just past the fingerprint,
                # for "after" it is its first word.
                region = next((r for r in ranges if r[0] <= lo and hi <= r[1]), None)
                if region is None:
                    where = next((r for r in ranges if r[0] <= lo < r[1]), None)
                    c.rejected.append(
                        f"not inside an executable {fmt} region"
                        + (f" (fingerprint/hook point run past the end of {where[2]})" if where
                           else " - the bytes match, but in data or non-code"))
                else:
                    c.checks.append(Check("executable-section", "pass", f"inside {region[2]}"))

            if c.rejected:
                c.confidence = "rejected"
                candidates.append(c)
                continue

            # -- soft: what follows the hook point ---------------------------
            limit = region[1] if region else len(mm)
            new_after = _mnemonics(md, mm[c.offset:min(c.offset + window, limit)], c.offset)
            if after_mode:
                # The fingerprint IS the start of the function, so "do the words after
                # the hook point look right" would only re-check bytes already matched.
                # What it doesn't cover is the rest of the body: compare all of it.
                new_body = _body_mnemonics(
                    md, mm[c.offset:min(c.offset + INSTR_LEN * BODY_WORDS, limit)], c.offset)
                if not old_body or not new_body:
                    c.checks.append(Check("body-similarity", "n/a", "no function body to compare"))
                else:
                    ratio = SequenceMatcher(None, old_body, new_body, autojunk=False).ratio()
                    c.checks.append(Check(
                        "body-similarity", "pass" if ratio >= BODY_SIMILARITY_MIN else "fail",
                        f"the function body's mnemonic sequence is {ratio:.0%} alike "
                        f"({len(old_body)} instructions in the old build, {len(new_body)} in the new; "
                        f"need >= {BODY_SIMILARITY_MIN:.0%})"))
            elif not new_after:
                c.checks.append(Check("after-decode", "n/a", "no words after the hook point to examine"))
                c.checks.append(Check("after-similarity", "n/a", "no words after the hook point to compare"))
            else:
                bad_new, bad_old = new_after.count(None), old_after.count(None)
                c.checks.append(Check(
                    "after-decode", "pass" if bad_new <= bad_old else "fail",
                    f"{len(new_after) - bad_new}/{len(new_after)} words after the hook point decode "
                    f"(old build: {len(old_after) - bad_old}/{len(old_after)})"))
                pairs = list(zip(old_after, new_after))
                same = sum(1 for a, b in pairs if a is not None and a == b)
                if pairs:
                    ok = same / len(pairs) >= SIMILARITY_MIN
                    c.checks.append(Check(
                        "after-similarity", "pass" if ok else "fail",
                        f"{same}/{len(pairs)} mnemonics after the hook point match the old build "
                        f"(need >= {SIMILARITY_MIN:.0%})"))
                else:
                    c.checks.append(Check("after-similarity", "n/a", "nothing to compare in the old build"))

            # -- soft: the barrier in front of the fingerprint ---------------
            start = hook - hook_delta                 # where the fingerprint's window would begin
            if old_anchor is None:
                c.checks.append(Check(
                    "before-anchor", "n/a",
                    "the word before the hook point is not a function end in the old build, nothing to compare"
                    if after_mode else
                    "the old run ended at the lookback window, not at a barrier"))
            elif start < INSTR_LEN:
                c.checks.append(Check("before-anchor", "n/a", "match is at the start of the file"))
            else:
                new_label = (_barrier_label(md, bytes(mm[start - INSTR_LEN:start]), start - INSTR_LEN)
                             or "<not a barrier>")
                c.checks.append(Check(
                    "before-anchor", "pass" if new_label == old_anchor else "fail",
                    f"word before the fingerprint is {new_label} (old build: {old_anchor})"))

            c.confidence = _confidence(c.checks)
            candidates.append(c)
    return candidates


# --------------------------------------------------------------------------
# Several anchors: each is located on its own in the new build and votes
# --------------------------------------------------------------------------
#
# The main fingerprint is one witness. It can be fooled the same way a person
# can: two functions that start alike, a function whose first instructions
# changed but whose body did not, a copy of the function that nobody calls. So
# the old build is also cut into other windows that each point at the hook point
# by a different route - a window deeper in the body (it sits a known distance
# behind the hook point), and the code around a call site of the old function
# (its `bl` lands on the hook point) - and every one of them is searched for in
# the new build by itself. Where they point is a vote. The votes can only take
# confidence away (any anchor found in a single place that points elsewhere is a
# conflict -> LOW; a window of the function's code that is no longer where it
# should be -> at most MEDIUM) or settle a tie between candidates; they never
# make a result more certain than the soft checks already allowed.

@dataclass
class Located:
    """Where one anchor was found in the new build, and what that points at."""
    anchor: Fingerprint
    votes: list = field(default_factory=list)    # hook offsets it points at (sorted; code only)
    generic: bool = False                        # found in more than MAX_ANCHOR_HITS places: says nothing


@dataclass
class Vote:
    """What one anchor says about one candidate: `verdict` is
    agree (found in exactly one place, and that points at the candidate),
    agree-weak (found in several places, one of which does),
    conflict (found in exactly one place, which points somewhere else),
    elsewhere (found in several places, none pointing at the candidate),
    absent (not found) or generic (too common to count)."""
    anchor: Fingerprint
    verdict: str
    detail: str

    @property
    def is_code(self):
        return self.anchor.kind in CODE_KINDS


def build_body_anchors(insns, masks, entry, min_instrs, count=MAX_BODY_ANCHORS):
    """Windows of the function's own code deeper than the entry fingerprint: one
    at the end of the straight-line run, and (when there is room) one in the middle,
    each BODY_WINDOW_WORDS instructions with the same wildcards as the entry
    fingerprint. `insns` / `masks` are the straight run from the hook point
    (_straight_run, wildcard_masks) - taken over the whole run, so a window that
    starts after its `adrp` still knows which load carries a page offset. None when
    the entry fingerprint already is the whole function, or the rest is too short or
    too full of wildcards."""
    if entry.complete or count < 1:
        return []
    first, n, size = len(entry.words), len(insns), BODY_WINDOW_WORDS
    room = n - first
    if room < size:
        return []
    starts = [n - size]
    if count > 1 and room >= 3 * size:
        starts.insert(0, first + (room - size) // 2)
    anchors = []
    for p in starts:
        window = masks[p:p + size]
        if sum(1 for m in window if m == WORD_MASK) < min_instrs:
            continue
        anchors.append(Fingerprint("after", _masked_words(insns[p:p + size], window), -INSTR_LEN * p,
                                   kind="body", label=f"body +0x{INSTR_LEN * p:x}"))
    return anchors


_BL_TOP_BYTE = re.compile(rb"[\x94-\x97]")     # a `bl` is 100101 + imm26: its top byte is 0x94..0x97


def find_call_sites(data, ranges, target):
    """File offsets of every `bl` in `ranges` (the executable (start, end, label)
    ranges of `data`) whose destination is `target`. Tail calls (`b`) and calls
    through a register are not call sites here: a hook point reached only like that
    simply has no caller anchors."""
    sites = []
    for lo, hi, _label in ranges:
        lo += -lo % INSTR_LEN
        top = data[lo + 3:min(hi, len(data)):INSTR_LEN]       # the top byte of each little-endian word
        for m in _BL_TOP_BYTE.finditer(top):
            at = lo + INSTR_LEN * m.start()
            imm = struct.unpack_from("<I", data, at)[0] & 0x3FFFFFF
            if imm & 0x2000000:
                imm -= 0x4000000
            if at + INSTR_LEN * imm == target:
                sites.append(at)
    return sites


def _caller_window(md, data, site, lo_limit, hi_limit):
    """The straight-line instructions around the `bl` at `site`: up to
    CALLER_BEFORE_WORDS before it (not past a terminator or an undecodable word - the
    previous function ends there) and CALLER_AFTER_WORDS after it (up to and
    including a terminator). Returns (instructions, index of the `bl` in them)."""
    def decode(at):
        return next(md.disasm(data[at:at + INSTR_LEN], at), None)

    first = site
    for _ in range(CALLER_BEFORE_WORDS):
        at = first - INSTR_LEN
        insn = decode(at) if at >= lo_limit else None
        if insn is None or is_terminator(insn):
            break
        first = at
    insns = [decode(at) for at in range(first, site + INSTR_LEN, INSTR_LEN)]
    at = site
    for _ in range(CALLER_AFTER_WORDS):
        at += INSTR_LEN
        insn = decode(at) if at + INSTR_LEN <= hi_limit else None
        if insn is None:
            break
        insns.append(insn)
        if is_terminator(insn):
            break
    return insns, (site - first) // INSTR_LEN


def build_caller_anchors(old_path, old_offset, own_words, min_instrs, count=MAX_CALLERS):
    """Anchors from the places in the old build that call the function at
    `old_offset` (`bl old_offset`): the code around each call, with the `bl`'s own
    distance wildcarded like any other PC-relative operand. In the new build such a
    window is found by its surroundings and its vote is where its `bl` lands. They
    do not depend on the function's own code at all, which is what makes them a
    second opinion. Calls from inside the function itself (`own_words` words from the
    hook point) are skipped; of the rest the windows with the most fixed instructions
    are kept (at most `count`, no two alike)."""
    with open(old_path, "rb") as f:
        data = f.read()
    found = executable_ranges(data)
    ranges = found[1] if found else [(0, len(data), "file")]
    own_end = old_offset + INSTR_LEN * own_words
    sites = [s for s in find_call_sites(data, ranges, old_offset) if not old_offset <= s < own_end]

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    windows = {}
    for site in sites[:MAX_CALL_SITES_SCANNED]:
        lo, hi, _label = next(r for r in ranges if r[0] <= site < r[1])
        insns, at = _caller_window(md, data, site, lo, hi)
        masks = wildcard_masks(insns)
        fixed = sum(1 for m in masks if m == WORD_MASK)
        words = _masked_words(insns, masks)
        if fixed >= min_instrs and tuple(words) not in windows:
            windows[tuple(words)] = (fixed, site, at, words)
    best = sorted(windows.values(), key=lambda w: (-w[0], w[1]))[:count]
    return [Fingerprint("after", words, 0, kind="caller", label=f"call site 0x{site:x}", xref=at)
            for _fixed, site, at, words in best]


def build_anchors(old_path, old_offset, primary, min_instrs, lookahead, scope="all"):
    """The anchors that vote besides the main fingerprint `primary` (printed as
    they are built). `scope`: "none" - no anchors (only the main fingerprint, as before),
    "code" - windows of the function's own code, "all" - also the call sites of the
    old function (a scan of the whole old binary for `bl`s; skippable on a big one).
    For a hook point in the middle of a function the code after it is an anchor
    too (the main fingerprint is the code in front of it)."""
    if scope == "none":
        return []
    anchors = []
    entry = primary if primary.kind == "entry" else None
    if entry is None:
        try:
            entry = replace(build_entry_fingerprint(old_path, old_offset, min_instrs, lookahead, verbose=False),
                            kind="forward", label="forward")
            anchors.append(entry)
        except RelocateError:
            entry = None                       # nothing usable from the hook point forward
    run_words = 1
    if entry is not None:
        insns, _stopped_by = _straight_run(old_path, old_offset, BODY_SCAN_WORDS)
        anchors += build_body_anchors(insns, wildcard_masks(insns), entry, min_instrs)
        run_words = max(1, len(insns))
    if scope == "all" and primary.kind == "entry":
        anchors += build_caller_anchors(old_path, old_offset, run_words, min_instrs)

    if anchors:
        print(f"[+] Anchors that vote besides the main fingerprint: {len(anchors)}")
        for a in anchors:
            print(f"      {a.label}: {len(a.words)} instructions ({a.n_wildcarded} wildcarded)")
    else:
        print("[i] No anchors besides the main fingerprint (the function is short, or has no call "
              "sites to use): it decides alone.")
    return anchors


def locate_anchors(new_path, anchors):
    """Search the new build for each anchor and work out what it points at (a
    list of Located, same order). Only matches inside executable regions count
    (when the container is recognised). An anchor found in more than MAX_ANCHOR_HITS
    places is `generic` and says nothing."""
    if not anchors:
        return []
    with open(new_path, "rb") as f:
        data = f.read()
    found = executable_ranges(data)
    ranges = found[1] if found else None
    counts, located = {}, []
    for a in anchors:
        hits = masked_matches(data, a.words, limit=MAX_ANCHOR_HITS + 1, counts=counts)
        if len(hits) > MAX_ANCHOR_HITS:
            located.append(Located(a, [], generic=True))
            continue
        votes = set()
        for m in hits:
            if ranges is not None and not any(lo <= m and m + len(a) <= hi for lo, hi, _label in ranges):
                continue
            if a.xref is None:
                vote = m + a.hook_delta
            else:                              # where the `bl` in this window lands
                at = m + INSTR_LEN * a.xref
                imm = struct.unpack_from("<I", data, at)[0] & 0x3FFFFFF
                vote = at + INSTR_LEN * (imm - 0x4000000 if imm & 0x2000000 else imm)
            if 0 <= vote <= len(data) - INSTR_LEN:
                votes.add(vote)
        located.append(Located(a, sorted(votes)))
    return located


def judge(loc, offset):
    """(verdict, detail) of one anchor about the candidate hook offset `offset`
    (see Vote)."""
    a = loc.anchor
    if loc.generic:
        return "generic", f"found in more than {MAX_ANCHOR_HITS} places - too common to say anything"
    n = len(loc.votes)
    points = "its call lands" if a.kind == "caller" else "that puts the hook point"
    if n == 0:
        return "absent", ("this call site is not in the new build as it was" if a.kind == "caller"
                          else "not found in the new build")
    where = ", ".join(f"0x{v:x}" for v in loc.votes[:3]) + (", ..." if n > 3 else "")
    if offset in loc.votes:
        if n == 1:
            return "agree", f"found in one place only, and {points} here"
        return "agree-weak", f"found in {n} places, and in one of them {points} here"
    if n == 1:
        return "conflict", f"found in one place only, and {points} at {where} - not here"
    return "elsewhere", (f"found in {n} places ({where}), none of which "
                         f"{'lands' if a.kind == 'caller' else 'puts the hook point'} here")


def _vote_status(v):
    if v.verdict in ("agree", "agree-weak"):
        return "pass"
    if v.verdict == "conflict" or (v.is_code and v.verdict in ("absent", "elsewhere")):
        return "fail"
    return "n/a"        # a call site that is gone says something about the caller, not the function


_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def _cap(confidence, ceiling):
    return confidence if _RANK.get(confidence, 0) <= _RANK[ceiling] else ceiling


def vote_confidence(base, votes):
    """(confidence, why) from the grade the soft checks gave (`base`) and the
    votes (`votes[0]` is the main fingerprint's):
      - an anchor found in one place only that points elsewhere -> LOW;
      - the main fingerprint doesn't match here (the candidate was proposed by other
        anchors) -> at most MEDIUM, and LOW unless two anchors agree on it;
      - a window of the function's own code that is no longer where it should be
        (or not there at all) -> at most MEDIUM;
      - otherwise the grade stands. Votes never raise it."""
    conflicts = [v for v in votes if v.verdict == "conflict"]
    if conflicts:
        many = len(conflicts) > 1
        return "LOW", (f"{len(conflicts)} anchor{'s' if many else ''} found in one place only "
                       f"point{'' if many else 's'} somewhere else "
                       f"({', '.join(v.anchor.label for v in conflicts)}).")
    if base == "LOW":
        return "LOW", ""
    if votes[0].verdict in ("absent", "elsewhere"):
        agreeing = [v for v in votes[1:] if v.verdict == "agree"]
        if len(agreeing) < 2 or not any(v.is_code for v in agreeing):
            return "LOW", "the main fingerprint doesn't match here and no second anchor backs it."
        return _cap(base, "MEDIUM"), (f"the main fingerprint doesn't match here (the start of the function "
                                      f"changed?); {len(agreeing)} other anchors do.")
    misses = [v for v in votes if v.is_code and v.verdict in ("absent", "elsewhere")]
    if misses and base == "HIGH":
        return "MEDIUM", (f"{len(misses)} window{'s' if len(misses) > 1 else ''} of the function's code "
                          f"{'are' if len(misses) > 1 else 'is'} not where expected "
                          f"({', '.join(v.anchor.label for v in misses)}) - the body changed?")
    return base, ""


def cast_votes(candidates, primary, located):
    """Count what every anchor says about every surviving candidate: sets
    `c.votes`, adds one check per anchor and a summary (`anchor-vote`) to
    `c.checks`, and applies vote_confidence to `c.confidence`. `primary` is the
    main fingerprint; it votes too, for the candidates it found itself."""
    accepted = [c for c in candidates if not c.rejected]
    everyone = [Located(primary, sorted(c.offset for c in accepted if c.via == "fingerprint"))] + list(located)
    for c in accepted:
        c.votes = [Vote(loc.anchor, *judge(loc, c.offset)) for loc in everyone]
        for v in c.votes:
            c.checks.append(Check(f"anchor {v.anchor.label}", _vote_status(v), v.detail))
        tally = {}
        for v in c.votes:
            tally[v.verdict] = tally.get(v.verdict, 0) + 1
        agree = tally.get("agree", 0) + tally.get("agree-weak", 0)
        conflict = tally.get("conflict", 0)
        silent = tally.get("generic", 0) + sum(1 for v in c.votes if not v.is_code and v.verdict == "absent")
        c.confidence, c.note = vote_confidence(c.confidence, c.votes)
        c.checks.append(Check(
            "anchor-vote", "fail" if c.note else "pass",
            f"{agree} of {len(c.votes)} anchors agree, {conflict} conflict, "
            f"{len(c.votes) - agree - conflict - silent} do not confirm, {silent} silent"))


def propose_from_anchors(located):
    """Hook offsets to try when the main fingerprint found nothing usable: those
    a window of the function's own code points at, from an anchor found in exactly
    one place. Call sites never propose - they can confirm or contradict a
    candidate, but a call site only says what is called from there now, and a
    function that was rewritten is still called from the same places."""
    return sorted({v for loc in located
                   if loc.anchor.kind in CODE_KINDS and not loc.generic and len(loc.votes) == 1
                   for v in loc.votes})


def settle_by_votes(accepted):
    """Several candidates survived (the main fingerprint matched in more than one
    place). If exactly one of them is not contradicted by an anchor found in a single
    place, and such an anchor agrees with it, the anchors have chosen: returns
    ([winner], [the others]). Otherwise (accepted, []) - still ambiguous. A winner
    chosen by call sites alone is capped at MEDIUM (the code itself can't tell the
    candidates apart); one chosen by a window of the function's own code is not."""
    clear = [c for c in accepted if not any(v.verdict == "conflict" for v in c.votes)]
    if len(clear) != 1:
        return accepted, []
    (winner,) = clear
    deciding = [v for v in winner.votes[1:] if v.verdict == "agree"]
    if not deciding:
        return accepted, []
    by = ", ".join(v.anchor.label for v in deciding)
    if not any(v.is_code for v in deciding):
        winner.confidence = _cap(winner.confidence, "MEDIUM")
        winner.note = "the code can't tell the candidates apart; only call sites do."
    winner.checks.append(Check("anchor-tiebreak", "pass",
                               f"the only one of {len(accepted)} candidates no anchor contradicts; chosen by {by}"))
    return [winner], [c for c in accepted if c is not winner]


def call_site_lead(located):
    """(offset, n) - where `n` call-site anchors, each found in one place only,
    agree the old function is now called - or None. A lead to follow in Ghidra when
    the function's own code wasn't found, not an answer."""
    sites = [loc for loc in located if loc.anchor.kind == "caller" and not loc.generic and len(loc.votes) == 1]
    targets = {loc.votes[0] for loc in sites}
    return (targets.pop(), len(sites)) if len(targets) == 1 else None


# --------------------------------------------------------------------------
# File offset -> RVA
# --------------------------------------------------------------------------
# A profile's offsets are RVAs: addresses relative to Frida's `module.base`, which is
# where the module's first mapping starts (= Ghidra's address with Image Base = 0).

PAGE_MASK = ~0xFFF


def _macho_segments(buf, base):
    """(name, vmaddr, fileoff, filesize) of every LC_SEGMENT_64 of the thin Mach-O whose
    header sits at `base`; fileoff is relative to `base` (the slice). May raise struct.error."""
    _magic, _cputype, _sub, _ftype, ncmds, sizeofcmds = struct.unpack_from("<IiiIII", buf, base)
    off = base + 32
    cmds_end = off + sizeofcmds
    segs = []
    for _ in range(ncmds):
        if off + 8 > cmds_end:
            break
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmdsize < 8 or off + cmdsize > cmds_end:
            break
        if cmd == LC_SEGMENT_64:
            name = bytes(buf[off + 8:off + 24]).split(b"\0")[0].decode("ascii", "replace")
            vmaddr, _vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", buf, off + 24)
            segs.append((name, vmaddr, fileoff, filesize))
        off += cmdsize
    return segs


def _macho_rva(buf, base, offset):
    """RVA of file offset `offset` in the thin Mach-O at `base`, or None if it is in no segment."""
    rel = offset - base
    segs = _macho_segments(buf, base)
    text = next((s for s in segs if s[0] == "__TEXT" and s[3]), None) or next((s for s in segs if s[3]), None)
    if text is None:
        return None
    header_addr = text[1] - text[2]          # where the Mach-O header is mapped: vmaddr - fileoff of __TEXT
    for _name, vmaddr, fileoff, filesize in segs:
        if fileoff <= rel < fileoff + filesize:
            return vmaddr + (rel - fileoff) - header_addr
    return None


def _elf_rva(buf, offset):
    """RVA of file offset `offset` in a 64-bit little-endian ELF: p_vaddr + (offset - p_offset) of the
    PT_LOAD segment holding it, relative to the lowest mapped page."""
    e_phoff, = struct.unpack_from("<Q", buf, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", buf, 0x36)
    loads = []
    for i in range(e_phnum):
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from(
            "<IIQQQQ", buf, e_phoff + i * e_phentsize)
        if p_type == PT_LOAD:
            loads.append((p_offset, p_vaddr, p_filesz))
    if not loads:
        return None
    image_base = min(v for _o, v, _s in loads) & PAGE_MASK
    for p_offset, p_vaddr, p_filesz in loads:
        if p_offset <= offset < p_offset + p_filesz:
            return p_vaddr + (offset - p_offset) - image_base
    return None


def file_offset_to_rva(buf, offset):
    """The RVA (Frida `module.base`-relative, Ghidra Image Base = 0) of FILE offset `offset`
    in the binary `buf`, or None when it can't be told: a raw blob, an unrecognised or
    truncated container, an offset inside no loadable segment (headers, padding, debug
    info) or - in a fat Mach-O - in no arm64 slice. Callers must treat None as "unknown",
    never as 0."""
    try:
        head = bytes(buf[:4])
        if head == b"\x7fELF":
            if buf[4] != 2 or buf[5] != 1:
                return None
            return _elf_rva(buf, offset)
        if head == struct.pack("<I", MH_MAGIC_64):
            return _macho_rva(buf, 0, offset)
        magic, = struct.unpack(">I", head)
        if magic in (FAT_MAGIC, FAT_MAGIC_64):
            nfat, = struct.unpack_from(">I", buf, 4)
            if nfat == 0 or nfat > 32:
                return None
            for i in range(nfat):
                if magic == FAT_MAGIC:
                    cputype, _sub, start, size, _align = struct.unpack_from(">iiIII", buf, 8 + 20 * i)
                else:
                    cputype, _sub, start, size, _align, _res = struct.unpack_from(">iiQQII", buf, 8 + 32 * i)
                if cputype != CPU_TYPE_ARM64 or not start <= offset < start + size:
                    continue
                if bytes(buf[start:start + 4]) != struct.pack("<I", MH_MAGIC_64):
                    return None
                return _macho_rva(buf, start, offset)
    except (struct.error, IndexError):
        pass
    return None


def rva_of(path, offset):
    """file_offset_to_rva() for the binary at `path` (None if it can't be read or mapped)."""
    try:
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            return file_offset_to_rva(mm, offset)
    except (OSError, ValueError):
        return None


def _macho_file_offset(buf, base, rva):
    """FILE offset of `rva` in the thin Mach-O at `base` (the inverse of _macho_rva), or None if no
    segment has file bytes for it (zero-fill / .bss, or past the image)."""
    segs = _macho_segments(buf, base)
    text = next((s for s in segs if s[0] == "__TEXT" and s[3]), None) or next((s for s in segs if s[3]), None)
    if text is None:
        return None
    header_addr = text[1] - text[2]
    for _name, vmaddr, fileoff, filesize in segs:
        start = vmaddr - header_addr
        if start <= rva < start + filesize:
            return base + fileoff + (rva - start)
    return None


def _elf_file_offset(buf, rva):
    """FILE offset of `rva` in a 64-bit little-endian ELF (the inverse of _elf_rva), or None."""
    e_phoff, = struct.unpack_from("<Q", buf, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", buf, 0x36)
    loads = []
    for i in range(e_phnum):
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from(
            "<IIQQQQ", buf, e_phoff + i * e_phentsize)
        if p_type == PT_LOAD:
            loads.append((p_offset, p_vaddr, p_filesz))
    if not loads:
        return None
    image_base = min(v for _o, v, _s in loads) & PAGE_MASK
    for p_offset, p_vaddr, p_filesz in loads:
        start = p_vaddr - image_base
        if start <= rva < start + p_filesz:
            return p_offset + (rva - start)
    return None


def rva_to_file_offset(buf, rva):
    """The FILE offset of `rva` (Frida `module.base`-relative, Ghidra Image Base = 0) in the binary
    `buf` - what file_offset_to_rva() does the other way round - or None when it can't be told: a raw
    blob, an unrecognised or truncated container (PE included), an RVA no loadable segment has file
    bytes for. In a fat Mach-O the first arm64 slice that maps it answers. Never 0 for "unknown"."""
    try:
        head = bytes(buf[:4])
        if head == b"\x7fELF":
            if buf[4] != 2 or buf[5] != 1:
                return None
            return _elf_file_offset(buf, rva)
        if head == struct.pack("<I", MH_MAGIC_64):
            return _macho_file_offset(buf, 0, rva)
        magic, = struct.unpack(">I", head)
        if magic in (FAT_MAGIC, FAT_MAGIC_64):
            nfat, = struct.unpack_from(">I", buf, 4)
            if nfat == 0 or nfat > 32:
                return None
            for i in range(nfat):
                if magic == FAT_MAGIC:
                    cputype, _sub, start, size, _align = struct.unpack_from(">iiIII", buf, 8 + 20 * i)
                else:
                    cputype, _sub, start, size, _align, _res = struct.unpack_from(">iiQQII", buf, 8 + 32 * i)
                if cputype != CPU_TYPE_ARM64 or bytes(buf[start:start + 4]) != struct.pack("<I", MH_MAGIC_64):
                    continue
                found = _macho_file_offset(buf, start, rva)
                if found is not None and start <= found < start + size:
                    return found
    except (struct.error, IndexError):
        pass
    return None


# What to tell the user about using a FILE offset in each kind of container as
# an RVA (a profile offset), keyed by the format name executable_ranges()
# returns (None: not a recognised Mach-O / ELF).
_RVA_NOTES = {
    "Mach-O": "[i] Thin Mach-O: this file offset is also the RVA (__TEXT starts at file offset 0) - "
              "use it as a profile offset as is.",
    "fat Mach-O (arm64 slices)": (
        "[!] This is a FILE offset, not an RVA: in a fat Mach-O the RVA is this minus the arm64 "
        "slice's file offset (`lipo -detailed_info`) - the NEW RVA line above already did that. "
        "Profile offsets are RVAs."),
    "ELF64": (
        f"[!] This is a FILE offset, not an RVA: in an ELF (e.g. {profiles.PLATFORM_MODULES['android']}) find the PT_LOAD segment "
        "containing it (`readelf -lW`); the RVA is offset - p_offset + p_vaddr (Image Base 0) - the "
        "NEW RVA line above already did that. Profile offsets are RVAs."),
    None: "[i] Unrecognised container format, so this can't tell whether the file offset equals the RVA "
          "(it only does for a thin Mach-O slice). Profile offsets are RVAs.",
}


def rva_note(path):
    """One `[i]`/`[!]` line saying whether a FILE offset in the binary at `path`
    can be used as a profile offset (which is an RVA) unchanged."""
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        found = executable_ranges(mm)
    return _RVA_NOTES[found[0] if found else None]


REPORT_VERSION = 1


def _candidate_report(c, new_binary):
    rva = rva_of(new_binary, c.offset)
    return {
        "file_offset": hex(c.offset),
        "rva": hex(rva) if rva is not None else None,     # None: this container can't be converted - say so, don't guess
        "confidence": c.confidence,
        "via": c.via,
        "note": c.note or None,
        "checks": [{"name": k.name, "status": k.status, "detail": k.detail} for k in c.checks],
        "votes": [{"anchor": v.anchor.label, "verdict": v.verdict, "detail": v.detail} for v in c.votes],
    }


def write_report(path, args, fingerprint, result, accepted, candidates, outvoted):
    """The outcome as JSON for the next step (retk verify): see the module docstring.
    `old` is null and `mode` is "name" for a run that had no OLD_BINARY (name lookup only); a
    `name` block says what the name lookup did, whenever --name was given."""
    outvoted_ids = {id(c) for c in outvoted}
    report = {
        "version": REPORT_VERSION,
        "old": ({"binary": args.old_binary, "file_offset": hex(args.old_offset)}
                if args.old_binary else None),
        "new": {"binary": args.new_binary},
        "mode": fingerprint.mode if fingerprint is not None else "name",
        "result": result,
        "candidates": [_candidate_report(c, args.new_binary) for c in accepted],
        "rejected": [{"file_offset": hex(c.offset), "reasons": list(c.rejected)} for c in candidates if c.rejected],
        "outvoted": [{"file_offset": hex(c.offset),
                      "reasons": [f"{v.anchor.label} {v.detail}" for v in c.votes if v.verdict == "conflict"]}
                     for c in candidates if id(c) in outvoted_ids],
    }
    if getattr(args, "name_info", None):
        report["name"] = args.name_info
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[i] Wrote {path} ({result}: {len(accepted)} candidate{'s' if len(accepted) != 1 else ''}) - "
          f"hand it to retk verify to check it against the running app.")


def print_checks(c, indent="      "):
    for chk in c.checks:
        print(f"{indent}[{chk.status:>4}] {chk.name}: {chk.detail}")


def find_candidates(args, say=print):
    """The byte-fingerprint half of main(): fingerprint the old hook point, search the new build, validate,
    let the anchors vote. Returns (fingerprint, candidates, located) - every candidate, rejected ones
    included - and raises RelocateError / OSError for bad input. `say` takes the progress lines (main() prints
    them; the name cross-check discards them)."""
    old_offset = args.old_offset
    check_architecture(args.old_binary, "old")
    check_architecture(args.new_binary, "new")
    fingerprint = choose_fingerprint(args.old_binary, old_offset, args.mode, args.min_instrs,
                                     args.lookback, args.lookahead)
    matches = find_matches(args.new_binary, fingerprint)
    say(f"\n[+] Matches found in the new build: {len(matches)}")
    located = []
    if args.no_validate:
        say("[i] --no-validate: accepting raw byte matches without checking them.")
        candidates = [Candidate(match=m, offset=m + fingerprint.hook_delta, confidence="unvalidated")
                      for m in matches]
    else:
        candidates = validate_candidates(args.old_binary, old_offset, args.new_binary,
                                         fingerprint, matches)
        if args.anchors != "none":
            anchors = build_anchors(args.old_binary, old_offset, fingerprint, args.min_instrs,
                                    args.lookahead, args.anchors)
            located = locate_anchors(args.new_binary, anchors)
            if not any(not c.rejected for c in candidates):
                # The main fingerprint found nothing usable: let the windows of the
                # function's own code that were found in one place each propose.
                candidates += validate_candidates(args.old_binary, old_offset, args.new_binary,
                                                  fingerprint, [], proposed=propose_from_anchors(located))
            cast_votes(candidates, fingerprint, located)
    return fingerprint, candidates, located


# --------------------------------------------------------------------------
# Looking the hook point up by name (--name / --new-metadata): see the module docstring
# --------------------------------------------------------------------------

@dataclass
class NameOutcome:
    """What the metadata dump says about a name, checked against the new binary. Exactly one of
    `failure` (why the name does not give an answer) and `file_offset` is set."""
    spec: object
    entry: object = None
    file_offset: Optional[int] = None
    checks: list = field(default_factory=list)
    failure: Optional[str] = None
    kind: Optional[str] = None       # not_found | ambiguous | not_mapped | not_code


def resolve_by_name(spec, index, new_binary):
    """Look `spec` up in `index` (il2cpp_names.MethodIndex) and place the answer in `new_binary`:
    RVA -> file offset, then the checks a name allows - the RVA is in a loadable segment, the code
    there is executable, and (AArch64) the address is 4-byte aligned. Never raises for a name the
    dump cannot settle: that is a NameOutcome with `failure`."""
    try:
        entry = index.lookup(spec)
    except il2cpp_names.NameLookupError as e:
        return NameOutcome(spec, failure=str(e), kind=e.kind)
    checks = [Check("name in dump", "pass", f"{entry} is at RVA 0x{entry.rva:x} "
                                           f"({index.format}, {len(index)} methods read)")]
    with open(new_binary, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        offset = rva_to_file_offset(mm, entry.rva)
        ranges = executable_ranges(mm)
        arch = detect_architecture(mm[:0x10000])
    if offset is None:
        return NameOutcome(spec, entry, checks=checks, kind="not_mapped", failure=(
            f"{entry} is at RVA 0x{entry.rva:x} in the dump, but no loadable segment of {new_binary} has file "
            f"bytes there (or it is a container this cannot read: a raw blob, a PE). Is the dump of this build?"))
    checks.append(Check("loadable segment", "pass", f"RVA 0x{entry.rva:x} is file offset 0x{offset:x}"))
    if arch is not None and arch[2]:
        ok = offset % INSTR_LEN == 0
        checks.append(Check("alignment", "pass" if ok else "fail",
                            f"0x{offset:x} is {'' if ok else 'not '}{INSTR_LEN}-byte aligned"))
        if not ok:
            return NameOutcome(spec, entry, offset, checks, kind="not_code", failure=(
                f"{entry}: RVA 0x{entry.rva:x} (file offset 0x{offset:x}) is not {INSTR_LEN}-byte aligned - "
                f"AArch64 code cannot start there, so the dump is not of this build"))
    if ranges is None:
        checks.append(Check("executable section", "n/a", "the container's sections could not be read"))
    else:
        inside = any(lo <= offset < hi for lo, hi, _label in ranges[1])
        checks.append(Check("executable section", "pass" if inside else "fail",
                            "inside executable code" if inside else "not inside any executable section"))
        if not inside:
            return NameOutcome(spec, entry, offset, checks, kind="not_code", failure=(
                f"{entry}: RVA 0x{entry.rva:x} (file offset 0x{offset:x}) is not in executable code of "
                f"{new_binary} - the dump is probably of another build"))
    return NameOutcome(spec, entry, offset, checks)


def _name_info(spec, args, index, outcome, how):
    info = {"spec": str(spec), "metadata": args.new_metadata, "format": index.format if index else None,
            "found": outcome.failure is None, "how": how}
    if outcome.entry is not None:
        info["rva"] = hex(outcome.entry.rva)
    if outcome.failure:
        info["failure"] = outcome.failure
    return info


def run_name_mode(args):
    """The --name half of main(). Returns an exit status when the name settled the matter - or failed with
    no OLD_BINARY to fall back on - and None to go on with the byte fingerprint (the name could not be used)."""
    try:
        spec = il2cpp_names.parse_method_spec(args.name, "--name")
        index = il2cpp_names.load_metadata(args.new_metadata)
    except (il2cpp_names.SpecError, il2cpp_names.MetadataError) as e:
        raise RelocateError(str(e)) from e
    print(f"\n[+] Looking up {spec} in {args.new_metadata} ({index.format}, {len(index)} methods)")
    outcome = resolve_by_name(spec, index, args.new_binary)

    if outcome.failure:
        args.name_info = _name_info(spec, args, index, outcome, "failed")
        print(f"[!] By name: {outcome.failure}")
        if args.old_binary is None:
            if args.json:
                write_report(args.json, args, None, "none", [], [], [])
            return 1
        print("[i] Falling back to the byte fingerprint.")
        return None

    # The name gave an offset. Cross-check it against the bytes when the old build is at hand.
    found, bytes_note, located = [], None, []
    if args.old_binary is not None:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                _fingerprint, cands, located = find_candidates(args)
            found = [c for c in cands if not c.rejected]
            if len(found) > 1 and located:
                found, _outvoted = settle_by_votes(found)
        except RelocateError as e:
            bytes_note = f"the byte cross-check could not run: {e}"
    else:
        bytes_note = "no OLD_BINARY was given, so there is nothing to compare the name's answer with"

    at = outcome.file_offset
    same = [c for c in found if c.offset == at]
    others = [c for c in found if c.offset != at]
    name_cand = Candidate(match=at, offset=at, via="name", checks=list(outcome.checks))
    if same:
        name_cand.confidence = "HIGH"
        name_cand.checks += same[0].checks
        name_cand.votes = same[0].votes
        name_cand.note = ("the name and the byte fingerprint agree" if not others else
                          f"the name settles it: the fingerprint alone found {len(found)} places "
                          f"({', '.join(hex(c.offset) for c in found)})")
        results, shown = "unique", [name_cand]
    elif found:
        name_cand.confidence = "MEDIUM"
        name_cand.note = ("the byte fingerprint points somewhere else (" +
                          ", ".join(f"file offset 0x{c.offset:x}" for c in found) +
                          ") - one of them is wrong: the dump may not be of this build, or the function was "
                          "rewritten and something that looks like it is still there")
        for c in found:
            c.confidence = _cap(c.confidence, "MEDIUM")
            c.note = (c.note + "; " if c.note else "") + f"the name {spec} says file offset 0x{at:x} instead"
        results, shown = "ambiguous", [name_cand] + found
    else:
        name_cand.confidence = "MEDIUM"
        name_cand.note = bytes_note or ("the byte fingerprint found nothing - the function was probably rewritten, "
                                        "or the dump is of another build; the name is the only witness")
        results, shown = "unique", [name_cand]

    args.name_info = _name_info(spec, args, index, outcome, "name" if results == "unique" else "conflict")
    if args.json:
        write_report(args.json, args, None, results, shown, shown, [])
    if results == "unique":
        print(f"\n[+] NEW FILE OFFSET: 0x{at:x}  (confidence: {name_cand.confidence}, found by name)")
        print_checks(name_cand, indent="    ")
        print(f"[+] NEW RVA: 0x{outcome.entry.rva:x}  (what a profile `offsets` entry / --offset takes)")
        print(rva_note(args.new_binary))
        print(f"[i] {name_cand.confidence} confidence - {name_cand.note}.")
        return 0
    print("[!] The name and the byte fingerprint disagree - not an answer:")
    for c in shown:
        rva = rva_of(args.new_binary, c.offset)
        print(f"      candidate file offset: 0x{c.offset:x}" + (f"  (RVA 0x{rva:x})" if rva is not None else "")
              + f"  (confidence: {c.confidence}, via {c.via})")
        print(f"          {c.note}")
    if args.json:
        print("[i] Every candidate is in the --json file: retk verify can run them and say which "
              "one the app really calls.")
    return 1


def main(argv=None, prog=None):
    prog = prog or "retk relocate"
    ap = argparse.ArgumentParser(
        prog=prog,
        usage=f"{prog} OLD_BINARY OLD_OFFSET_HEX NEW_BINARY [options]\n"
              f"       {prog} NEW_BINARY --name Namespace.Class::Method[/N] --new-metadata DUMP [options]",
        description="Re-locate a hook point in a new build. Offsets here are FILE offsets, "
                    "not the RVAs that a profile's `offsets` hold - see the module docstring.")
    ap.add_argument("paths", nargs="*", metavar="ARG",
                    help="OLD_BINARY OLD_OFFSET_HEX NEW_BINARY - OLD_OFFSET is a FILE offset in OLD_BINARY, hex, "
                         "e.g. 0xab68fc8 (see module docstring); or just NEW_BINARY when --name finds it")
    ap.add_argument("--name", metavar="NS.CLASS::METHOD[/N]",
                    help="find the hook point by name in the new build's metadata (--new-metadata) instead of "
                         "by its bytes; /N picks the overload with N parameters. With OLD_BINARY the byte "
                         "fingerprint still runs, as a cross-check (see \"Looking a method up by name\" above)")
    ap.add_argument("--new-metadata", metavar="DUMP",
                    help="the NEW build's metadata: Il2CppDumper's dump.cs or script.json, or a symbol map "
                         "with one `NAME ADDRESS` per line (needed by --name)")
    ap.add_argument("--mode", choices=("auto", "before", "after"), default="auto",
                    help="what to fingerprint: 'after' = the function's own code from the hook point "
                         "forward (the hook point is a function entry); 'before' = the instructions in "
                         "front of it (the hook point is mid-function); 'auto' (default) picks "
                         "'after' for what looks like a function entry, else 'before'")
    ap.add_argument("--min-instrs", type=int, default=4,
                    help="fully fixed (non-wildcarded) instructions the fingerprint needs (default 4)")
    ap.add_argument("--lookback", type=int, default=64,
                    help="mode 'before': how many bytes in front of the hook point to scan (default 64)")
    ap.add_argument("--lookahead", type=int, default=64,
                    help="mode 'after': how many bytes from the hook point on to fingerprint, at most; "
                         "it ends earlier at the first ret/br/b/brk (default 64)")
    ap.add_argument("--no-validate", action="store_true",
                    help="skip the alignment / executable-section / context checks and the anchor "
                         "votes, and accept a unique raw byte match (the pre-validation behaviour)")
    ap.add_argument("--json", metavar="PATH",
                    help="also write the outcome - every accepted candidate with its file offset, RVA and "
                         "confidence - to PATH, for retk verify (see the module docstring)")
    ap.add_argument("--anchors", choices=ANCHOR_SCOPES, default="all",
                    help="which anchors vote besides the main fingerprint: 'all' (default) = windows "
                         "of the function's code and the call sites of the old function (scans the "
                         "whole old binary for `bl`s); 'code' = only windows of the function's code; "
                         "'none' = the main fingerprint alone")
    args = ap.parse_args(argv)

    # Positionals: OLD_BINARY OLD_OFFSET NEW_BINARY - or just NEW_BINARY when --name is the way in.
    if len(args.paths) == 3:
        args.old_binary, old_text, args.new_binary = args.paths
        try:
            args.old_offset = parse_offset(old_text)
        except argparse.ArgumentTypeError as e:
            ap.error(f"argument OLD_OFFSET_HEX: {e}")
    elif len(args.paths) == 1 and args.name:
        args.old_binary, args.old_offset, args.new_binary = None, None, args.paths[0]
    else:
        ap.error("expected OLD_BINARY OLD_OFFSET_HEX NEW_BINARY - or, with --name, just NEW_BINARY")
    if args.name and not args.new_metadata:
        ap.error("--name needs --new-metadata DUMP: the NEW build's dump.cs / script.json / symbol map")
    if args.new_metadata and not args.name:
        ap.error("--new-metadata is only used with --name")

    args.name_info = None

    try:
        if args.name:
            status = run_name_mode(args)
            if status is not None:
                sys.exit(status)
        fingerprint, candidates, located = find_candidates(args)
    except (RelocateError, OSError) as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(2)

    if not candidates:
        if args.json:
            write_report(args.json, args, fingerprint, "none", [], [], [])
        print("[!] No matches - the code may have genuinely changed logic (not just moved).")
        lead = call_site_lead(located)
        if lead:
            print(f"[i] Lead, not an answer: {lead[1]} call site{'s' if lead[1] > 1 else ''} of the old "
                  f"function now call{'' if lead[1] > 1 else 's'} file offset 0x{lead[0]:x}, but the code "
                  f"there is not the old function's - it was probably rewritten. Compare it in Ghidra.")
        sys.exit(1)

    accepted = [c for c in candidates if not c.rejected]
    for c in candidates:
        if c.rejected:
            print(f"      rejected file offset 0x{c.offset:x}: {'; '.join(c.rejected)}")
    if not args.no_validate:
        print(f"[+] Surviving validation: {len(accepted)} of {len(candidates)}")
    if any(c.via == "anchor" for c in accepted):
        print("[i] The main fingerprint was not found in the new build (or only outside code); the "
              "candidate below was proposed by the anchors that match the function's own code.")

    outvoted = []
    if len(accepted) > 1 and located:
        accepted, outvoted = settle_by_votes(accepted)
    for c in outvoted:
        reasons = "; ".join(f"{v.anchor.label} {v.detail}" for v in c.votes if v.verdict == "conflict")
        print(f"      outvoted file offset 0x{c.offset:x}: {reasons}")

    if not accepted:
        if args.json:
            write_report(args.json, args, fingerprint, "none", [], candidates, outvoted)
        print("[!] Every byte match was rejected as not-code (see above) - the code may have "
              "genuinely changed logic, or the executable-region parser misjudged this binary "
              "(--no-validate skips the check).")
        sys.exit(1)
    elif len(accepted) > 1:
        if args.json:
            write_report(args.json, args, fingerprint, "ambiguous", accepted, candidates, outvoted)
        print("[!] More than one match - the fingerprint isn't specific enough yet, try a higher --min-instrs or a larger "
              + ("--lookahead." if fingerprint.mode == "after" else "--lookback.")
              + (" The anchors could not settle it either." if located else ""))
        for c in accepted:
            rva = rva_of(args.new_binary, c.offset)
            print(f"      candidate file offset: 0x{c.offset:x}"
                  + (f"  (RVA 0x{rva:x})" if rva is not None else "") + f"  (confidence: {c.confidence})")
            print_checks(c, indent="          ")
        if args.json:
            print("[i] Every candidate is in the --json file: retk verify can run them and say which "
                  "one the app really calls.")
        sys.exit(1)
    else:
        c = accepted[0]
        if args.json:
            write_report(args.json, args, fingerprint, "unique", accepted, candidates, outvoted)
        print(f"\n[+] NEW FILE OFFSET: 0x{c.offset:x}  (confidence: {c.confidence})")
        print_checks(c, indent="    ")
        rva = rva_of(args.new_binary, c.offset)
        if rva is not None:
            print(f"[+] NEW RVA: 0x{rva:x}  (what a profile `offsets` entry / --offset takes)")
        print(rva_note(args.new_binary))
        if c.confidence == "LOW":
            print("[!] LOW confidence - " + (c.note or "the bytes match but the surrounding code doesn't "
                  "look like the old build's.") + " Check this one in Ghidra before hooking it.")
        elif c.note:
            print(f"[i] {c.confidence} confidence - {c.note}")


if __name__ == "__main__":
    main()
