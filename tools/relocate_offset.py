"""
relocate_offset.py

Automatically re-locates a hook point in a NEW build of UnityFramework,
based on its known location in an OLD build - no Ghidra and no
symbol/export name required.

How it works:
  1. Disassemble backwards from old_offset in the old build, collecting
     consecutive instructions that do NOT depend on an absolute address
     (skipping adrp/adr/bl/b/cbz/cbnz - these instructions encode a
     relative offset, which changes if the function moves). An undecodable
     word (literal pool, jump table) also ends the run.
  2. Concatenate those "safe" instructions into a byte string fingerprint.
  3. Search for that exact byte string in the new build.
  4. Validate every raw byte match before believing it (a byte string alone
     can't tell code from data or from a literal pool that happens to hold the
     same bytes):
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
         - the words after the hook point decode at least as cleanly as they
           did in the old build (data/literal-pool bytes usually don't);
         - their mnemonic sequence resembles the old build's;
         - the word just before the fingerprint is the same kind of barrier
           (same mnemonic, or undecodable) that ended the run in the old build.
     Disassembling the fingerprint bytes themselves is deliberately not a
     check: they are the same bytes that were decoded in the old build, so
     the result would be the same by construction.
  5. If exactly ONE candidate survives, print the new FILE offset = match
     position + fingerprint length, with the checks and the confidence label,
     then a note on whether that number can be used as the RVA (`--offset` /
     FRIDA_OFFSET) as is or has to be converted first (see below).
     --no-validate skips step 4 (the raw behaviour: unique byte string =
     accepted) if the format parser misjudges an unusual binary.

What this is NOT: it does not build a control-flow graph, find function
boundaries or use symbols. It is still fingerprint matching with sanity
checks around it. Treat HIGH as "very likely", not "proved", and verify the
result once in Ghidra or with a hook before relying on it.

OFFSETS ARE FILE OFFSETS. OLD_OFFSET_HEX is a position in the file passed as
OLD_BINARY (that's what gets `seek`ed/searched), and NEW OFFSET is a position
in NEW_BINARY - not an RVA / Ghidra address / vmaddr, even though the rest of
the repo (config.py, --offset, Frida's `module.base + offset`) speaks RVA. The
two coincide for a thin Mach-O slice (its __TEXT segment starts at file offset
0), so for the iOS `UnityFramework` case you can pass the RVA straight in. They
do NOT coincide for a fat/universal Mach-O (add the arch slice's file offset)
or for an ELF such as Android's `libil2cpp.so` (depends on the PT_LOAD
segment's p_offset vs p_vaddr - check with `readelf -lW`). Convert first in
those cases, in both directions. The note printed after each result says which
case the new build looks like; the tool does not do the conversion itself.

Assumption: the algorithm/struct layout hasn't changed between the two
builds, only the code has moved due to a rebuild (true for most
minor/patch updates, may not hold for a major update that changes the
logic itself).

Usage:
    python relocate_offset.py OLD_BINARY OLD_OFFSET_HEX NEW_BINARY [--min-instrs N]
                              [--lookback BYTES] [--no-validate]

Example:
    python relocate_offset.py UnityFramework_old 0xab68fc8 UnityFramework_new
"""
import os
import sys
import argparse
import mmap
import struct
from dataclasses import dataclass, field
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

from _common import parse_offset  # same hex parsing as the drivers' --offset

INSTR_LEN = 4  # AArch64: every instruction is a fixed 4 bytes

# Validation (see the module docstring). CONTEXT_WORDS is how many words after
# the hook point are compared between builds; SIMILARITY_MIN is the fraction of
# them whose mnemonic must match for that soft check to pass. Both are
# heuristics, not derived from anything - the raw counts are printed so you can
# judge a result yourself.
CONTEXT_WORDS = 8
SIMILARITY_MIN = 0.5

# Binary-format constants used by executable_ranges().
CPU_TYPE_ARM64 = 0x0100000C          # arm64 and arm64e share this cputype
MH_MAGIC_64 = 0xFEEDFACF             # thin 64-bit Mach-O, little-endian
FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF   # big-endian on disk
LC_SEGMENT_64 = 0x19
VM_PROT_EXECUTE = 0x4
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
PT_LOAD, PF_X = 1, 1


class RelocateError(RuntimeError):
    """A problem with the inputs or with what the fingerprint found - as
    opposed to a bug. main() reports these as one `[!]` line, no traceback.
    (Subclasses RuntimeError so callers that already catch that keep working.)"""


def check_offset(path, offset):
    """Reject an `offset` that can't be a fingerprint anchor in `path`, with a
    message that names the real problem. Without this, a bad offset just
    produced "found 0 safe instructions - try a larger lookback", which is the
    wrong advice: no lookback window fixes an offset that's out of range or
    misaligned."""
    if offset % INSTR_LEN:
        raise RelocateError(
            f"offset 0x{offset:x} is not {INSTR_LEN}-byte aligned - AArch64 code is "
            f"fixed-width, so a function can't start here. Is it the right kind of "
            f"offset? (This tool takes FILE offsets - see the module docstring.)")
    size = os.path.getsize(path)  # OSError (missing file) is handled by main()
    if offset > size:
        raise RelocateError(
            f"offset 0x{offset:x} is past the end of {path} (0x{size:x} bytes). This "
            f"tool takes FILE offsets; if 0x{offset:x} is an RVA / Ghidra address, it "
            f"only equals the file offset for a thin Mach-O slice - for a fat "
            f"Mach-O or an ELF (libil2cpp.so) convert it first.")
    if offset < INSTR_LEN:
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


def build_fingerprint(old_path, old_offset, min_instrs, lookback_window=64):
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
    # soon as a PC-relative instruction OR an undecodable word is hit.
    # AArch64 is fixed-width, so decode one word at a time: md.disasm() on the
    # whole chunk silently stops at the first undecodable word (literal pool,
    # jump table, ...), and the bytes after it - never checked for
    # PC-relative instructions - would end up in the fingerprint.
    safe_insns = []
    for addr in range(old_offset - INSTR_LEN, base - 1, -INSTR_LEN):
        word = chunk[addr - base:addr - base + INSTR_LEN]
        insn = next(md.disasm(word, addr), None)
        if insn is None or is_pc_relative(insn):
            break
        safe_insns.insert(0, insn)

    if len(safe_insns) < min_instrs:
        raise RelocateError(
            f"Only found {len(safe_insns)} consecutive safe instructions right "
            f"before the offset (need >= {min_instrs}). Try a larger lookback_window or a lower --min-instrs."
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


def _barrier_label(md, word, addr):
    """The label of the instruction that ended a fingerprint run - its
    mnemonic, or "<undecodable>" - or None if `word` is neither a barrier
    (PC-relative / undecodable): then the run ended for another reason."""
    insn = next(md.disasm(word, addr), None)
    if insn is None:
        return "<undecodable>"
    return insn.mnemonic if is_pc_relative(insn) else None


def _confidence(checks):
    status = {c.name: c.status for c in checks}
    soft_fails = [n for n, s in status.items()
                  if s == "fail" and n in ("after-decode", "before-anchor", "after-similarity")]
    if "after-decode" in soft_fails or len(soft_fails) >= 2:
        return "LOW"
    if (not soft_fails and status.get("executable-section") == "pass"
            and status.get("after-similarity") == "pass"):
        return "HIGH"
    return "MEDIUM"


def validate_candidates(old_path, old_offset, new_path, fingerprint, matches,
                        context_words=CONTEXT_WORDS):
    """Turn raw byte matches (start offsets in the new build, from
    find_new_offset) into Candidates: hard checks decide `rejected`, soft
    checks and the confidence label describe the rest. See the module
    docstring for what each check is and why."""
    if not matches:
        return []
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    fp_len = len(fingerprint)
    window = INSTR_LEN * context_words

    # What the old build looked like around the hook point.
    with open(old_path, "rb") as f:
        f.seek(old_offset)
        old_after = _mnemonics(md, f.read(window), old_offset)
        old_anchor = None
        fp_start = old_offset - fp_len
        if fp_start >= INSTR_LEN:
            f.seek(fp_start - INSTR_LEN)
            old_anchor = _barrier_label(md, f.read(INSTR_LEN), fp_start - INSTR_LEN)

    candidates = []
    with open(new_path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        found = executable_ranges(mm)
        for m in matches:
            c = Candidate(match=m, offset=m + fp_len)

            # -- hard: alignment ------------------------------------------
            if m % INSTR_LEN:
                c.rejected.append(
                    f"match starts at 0x{m:x}, not on a {INSTR_LEN}-byte boundary - AArch64 "
                    f"instructions can't start there, so this is data or a coincidence")
            else:
                c.checks.append(Check("alignment", "pass", f"0x{m:x} is {INSTR_LEN}-byte aligned"))

            # -- hard: inside an executable region ---------------------------
            region = None
            if found is None:
                c.checks.append(Check("executable-section", "n/a",
                                      "file is not a recognised Mach-O/ELF - can't tell code from data"))
            else:
                fmt, ranges = found
                region = next((r for r in ranges if r[0] <= m and c.offset + INSTR_LEN <= r[1]), None)
                if region is None:
                    where = next((r for r in ranges if r[0] <= m < r[1]), None)
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
            if not new_after:
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
            if old_anchor is None:
                c.checks.append(Check("before-anchor", "n/a",
                                      "the old run ended at the lookback window, not at a barrier"))
            elif m < INSTR_LEN:
                c.checks.append(Check("before-anchor", "n/a", "match is at the start of the file"))
            else:
                new_label = _barrier_label(md, bytes(mm[m - INSTR_LEN:m]), m - INSTR_LEN) or "<not a barrier>"
                c.checks.append(Check(
                    "before-anchor", "pass" if new_label == old_anchor else "fail",
                    f"word before the fingerprint is {new_label} (old build: {old_anchor})"))

            c.confidence = _confidence(c.checks)
            candidates.append(c)
    return candidates


# What to tell the user about using a FILE offset in each kind of container as
# an RVA (--offset / FRIDA_OFFSET), keyed by the format name executable_ranges()
# returns (None: not a recognised Mach-O / ELF).
_RVA_NOTES = {
    "Mach-O": "[i] Thin Mach-O: this file offset is also the RVA (__TEXT starts at file offset 0) - "
              "use it as --offset / FRIDA_OFFSET as is.",
    "fat Mach-O (arm64 slices)": (
        "[!] This is a FILE offset, not an RVA: in a fat Mach-O the RVA is this minus the arm64 "
        "slice's file offset (`lipo -detailed_info`). --offset / FRIDA_OFFSET take the RVA."),
    "ELF64": (
        "[!] This is a FILE offset, not an RVA: in an ELF (e.g. libil2cpp.so) find the PT_LOAD segment "
        "containing it (`readelf -lW`); the RVA is offset - p_offset + p_vaddr (Image Base 0). "
        "--offset / FRIDA_OFFSET take the RVA."),
    None: "[i] Unrecognised container format, so this can't tell whether the file offset equals the RVA "
          "(it only does for a thin Mach-O slice). --offset / FRIDA_OFFSET take the RVA.",
}


def rva_note(path):
    """One `[i]`/`[!]` line saying whether a FILE offset in the binary at `path`
    can be passed to `--offset` / FRIDA_OFFSET (which take an RVA) unchanged."""
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        found = executable_ranges(mm)
    return _RVA_NOTES[found[0] if found else None]


def print_checks(c, indent="      "):
    for chk in c.checks:
        print(f"{indent}[{chk.status:>4}] {chk.name}: {chk.detail}")


def main():
    ap = argparse.ArgumentParser(
        description="Re-locate a hook point in a new build. Offsets here are FILE offsets, "
                    "not the RVAs that --offset / FRIDA_OFFSET take - see the module docstring.")
    ap.add_argument("old_binary")
    ap.add_argument("old_offset", type=parse_offset,
                    help="FILE offset in old_binary, hex, e.g. 0xab68fc8 (see module docstring)")
    ap.add_argument("new_binary")
    ap.add_argument("--min-instrs", type=int, default=4)
    ap.add_argument("--lookback", type=int, default=64)
    ap.add_argument("--no-validate", action="store_true",
                    help="skip the alignment / executable-section / context checks and accept a "
                         "unique raw byte match (the pre-validation behaviour)")
    args = ap.parse_args()

    old_offset = args.old_offset

    try:
        fingerprint = build_fingerprint(args.old_binary, old_offset, args.min_instrs, args.lookback)
        matches = find_new_offset(args.new_binary, fingerprint)
        print(f"\n[+] Matches found in the new build: {len(matches)}")
        if args.no_validate:
            print("[i] --no-validate: accepting raw byte matches without checking them.")
            candidates = [Candidate(match=m, offset=m + len(fingerprint), confidence="unvalidated")
                          for m in matches]
        else:
            candidates = validate_candidates(args.old_binary, old_offset, args.new_binary,
                                             fingerprint, matches)
    except (RelocateError, OSError) as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(2)

    if len(matches) == 0:
        print("[!] No matches - the code may have genuinely changed logic (not just moved).")
        sys.exit(1)

    accepted = [c for c in candidates if not c.rejected]
    for c in candidates:
        if c.rejected:
            print(f"      rejected file offset 0x{c.offset:x}: {'; '.join(c.rejected)}")
    if not args.no_validate:
        print(f"[+] Surviving validation: {len(accepted)} of {len(matches)}")

    if not accepted:
        print("[!] Every byte match was rejected as not-code (see above) - the code may have "
              "genuinely changed logic, or the executable-region parser misjudged this binary "
              "(--no-validate skips the check).")
        sys.exit(1)
    elif len(accepted) > 1:
        print("[!] More than one match - the fingerprint isn't specific enough yet, try a higher --min-instrs or a larger --lookback.")
        for c in accepted:
            print(f"      candidate file offset: 0x{c.offset:x}  (confidence: {c.confidence})")
            print_checks(c, indent="          ")
        sys.exit(1)
    else:
        c = accepted[0]
        print(f"\n[+] NEW FILE OFFSET: 0x{c.offset:x}  (confidence: {c.confidence})")
        print_checks(c, indent="    ")
        print(rva_note(args.new_binary))
        if c.confidence == "LOW":
            print("[!] LOW confidence - the bytes match but the surrounding code doesn't look like the "
                  "old build's. Check this one in Ghidra before hooking it.")


if __name__ == "__main__":
    main()
