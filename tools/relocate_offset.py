"""
relocate_offset.py

Automatically re-locates a hook point in a NEW build of UnityFramework,
based on its known location in an OLD build - no Ghidra and no
symbol/export name required.

How it works:
  1. Disassemble backwards from old_offset in the old build, collecting
     consecutive instructions that do NOT depend on an absolute address
     (skipping adrp/adr/bl/b/cbz/cbnz - these instructions encode a
     relative offset, which changes if the function moves).
  2. Concatenate those "safe" instructions into a byte string fingerprint.
  3. Search for that exact byte string in the new build.
  4. If it matches EXACTLY ONCE, print the new offset = match position +
     fingerprint length.

Assumption: the algorithm/struct layout hasn't changed between the two
builds, only the code has moved due to a rebuild (true for most
minor/patch updates, may not hold for a major update that changes the
logic itself).

Usage:
    python relocate_offset.py OLD_BINARY OLD_OFFSET_HEX NEW_BINARY [--min-instrs N]

Example:
    python relocate_offset.py UnityFramework_old 0xab68fc8 UnityFramework_new
"""
import sys
import argparse
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

PC_RELATIVE = {"adrp", "adr", "bl", "b", "cbz", "cbnz", "tbz", "tbnz", "b.eq",
               "b.ne", "b.gt", "b.lt", "b.ge", "b.le", "ldr"}  # the literal-pool form of ldr can also be PC-relative
INSTR_LEN = 4  # AArch64: every instruction is a fixed 4 bytes


def is_pc_relative(insn):
    if insn.mnemonic in ("adrp", "adr", "bl", "cbz", "cbnz", "tbz", "tbnz"):
        return True
    if insn.mnemonic == "b" or insn.mnemonic.startswith("b."):
        return True
    # "ldr xN, #imm" (literal pool) is PC-relative; "ldr wN, [xM, #imm]" is not.
    if insn.mnemonic in ("ldr", "ldrsw") and "[" not in insn.op_str:
        return True
    return False


def build_fingerprint(old_path, old_offset, min_instrs, lookback_window=64):
    with open(old_path, "rb") as f:
        f.seek(max(0, old_offset - lookback_window))
        chunk = f.read(lookback_window)

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    insns = list(md.disasm(chunk, max(0, old_offset - lookback_window)))
    insns = [i for i in insns if i.address < old_offset]  # only keep the part before old_offset

    if not insns:
        raise RuntimeError("Could not disassemble anything before old_offset - increase lookback_window.")

    # Walk backwards from the instruction closest to the offset, stopping
    # as soon as a PC-relative instruction is hit.
    safe_insns = []
    for insn in reversed(insns):
        if is_pc_relative(insn):
            break
        safe_insns.insert(0, insn)

    if len(safe_insns) < min_instrs:
        raise RuntimeError(
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
    ap.add_argument("old_offset", help="hex, e.g. 0xab68fc8")
    ap.add_argument("new_binary")
    ap.add_argument("--min-instrs", type=int, default=4)
    ap.add_argument("--lookback", type=int, default=64)
    args = ap.parse_args()

    old_offset = int(args.old_offset, 16)

    fingerprint = build_fingerprint(args.old_binary, old_offset, args.min_instrs, args.lookback)
    matches = find_new_offset(args.new_binary, fingerprint)

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
