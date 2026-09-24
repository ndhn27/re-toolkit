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
  4. If it matches EXACTLY ONCE, print the new offset = match position +
     fingerprint length.

OFFSETS ARE FILE OFFSETS. OLD_OFFSET_HEX is a position in the file passed as
OLD_BINARY (that's what gets `seek`ed/searched), and NEW OFFSET is a position
in NEW_BINARY - not an RVA / Ghidra address / vmaddr, even though the rest of
the repo (config.py, --offset, Frida's `module.base + offset`) speaks RVA. The
two coincide for a thin Mach-O slice (its __TEXT segment starts at file offset
0), so for the iOS `UnityFramework` case you can pass the RVA straight in. They
do NOT coincide for a fat/universal Mach-O (add the arch slice's file offset)
or for an ELF such as Android's `libil2cpp.so` (depends on the PT_LOAD
segment's p_offset vs p_vaddr - check with `readelf -lW`). Convert first in
those cases, in both directions.

Assumption: the algorithm/struct layout hasn't changed between the two
builds, only the code has moved due to a rebuild (true for most
minor/patch updates, may not hold for a major update that changes the
logic itself).

Usage:
    python relocate_offset.py OLD_BINARY OLD_OFFSET_HEX NEW_BINARY [--min-instrs N]

Example:
    python relocate_offset.py UnityFramework_old 0xab68fc8 UnityFramework_new
"""
import os
import sys
import argparse
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

from _common import parse_offset  # same hex parsing as the drivers' --offset

INSTR_LEN = 4  # AArch64: every instruction is a fixed 4 bytes


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
    mnemonic list elsewhere as a plain set/tuple; a previous such constant
    here went unused and, worse, was wrong (missed most b.<cond> variants
    and couldn't tell literal-pool ldr from base-register ldr - the exact
    distinction handled below)."""
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("old_binary")
    ap.add_argument("old_offset", type=parse_offset,
                    help="FILE offset in old_binary, hex, e.g. 0xab68fc8 (see module docstring)")
    ap.add_argument("new_binary")
    ap.add_argument("--min-instrs", type=int, default=4)
    ap.add_argument("--lookback", type=int, default=64)
    args = ap.parse_args()

    old_offset = args.old_offset

    try:
        fingerprint = build_fingerprint(args.old_binary, old_offset, args.min_instrs, args.lookback)
        matches = find_new_offset(args.new_binary, fingerprint)
    except (RelocateError, OSError) as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(2)

    print(f"\n[+] Matches found in the new build: {len(matches)}")
    if len(matches) == 0:
        print("[!] No matches - the code may have genuinely changed logic (not just moved).")
        sys.exit(1)
    elif len(matches) > 1:
        print("[!] More than one match - the fingerprint isn't specific enough yet, try a higher --min-instrs or a larger --lookback.")
        for m in matches:
            print(f"      candidate: 0x{m + len(fingerprint):x}")
        sys.exit(1)
    else:
        new_offset = matches[0] + len(fingerprint)
        print(f"\n[+] NEW OFFSET: 0x{new_offset:x}")


if __name__ == "__main__":
    main()
