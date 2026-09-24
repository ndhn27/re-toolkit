"""
Tiny builders for Mach-O / fat Mach-O / ELF64 files, for tests that need
`relocate_offset.executable_ranges()` to see a real container around some
AArch64 words. Only what the parser reads is populated (load commands,
section/program headers); everything is laid out from the struct definitions
in <mach-o/loader.h>, <mach-o/fat.h> and <elf.h>.

test_relocate_offset.py's format tests are independent of these builders'
correctness only as far as the builders are right, so they were cross-checked
against a second parser (LIEF) once, by hand, rather than trusted on their
own; that check isn't part of the suite (LIEF isn't a dependency).
"""
import struct

CPU_ARM64 = 0x0100000C
CPU_X86_64 = 0x01000007

S_REGULAR = 0x0
S_CSTRING_LITERALS = 0x2
CODE = 0x80000400        # S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
NOT_CODE = S_REGULAR


def _align(n, a):
    return (n + a - 1) // a * a


def build_macho(segments, cputype=CPU_ARM64):
    """segments: [(segname, initprot, [(sectname, sflags, data_bytes), ...]), ...]

    Returns (blob, layout) where layout maps "SEG,sect" -> (start, end) file
    offsets of that section's data, so a test can drop bytes into a known
    section."""
    cmdsize = sum(72 + 80 * len(secs) for _n, _p, secs in segments)
    pos = _align(32 + cmdsize, 16)
    layout, cmds, body = {}, b"", b""
    vm = 0x100000000
    for segname, initprot, secs in segments:
        seg_start = pos
        sec_hdrs = b""
        for sectname, sflags, data in secs:
            start = pos
            sec_hdrs += (sectname.encode().ljust(16, b"\0") + segname.encode().ljust(16, b"\0")
                         + struct.pack("<QQIIIIIIII", vm + start, len(data), start, 2, 0, 0,
                                       sflags, 0, 0, 0))
            body += data
            pos += len(data)
            layout[f"{segname},{sectname}"] = (start, pos)
        cmds += (struct.pack("<II", 0x19, 72 + 80 * len(secs))
                 + segname.encode().ljust(16, b"\0")
                 + struct.pack("<QQQQiiII", vm + seg_start, pos - seg_start, seg_start,
                               pos - seg_start, initprot, initprot, len(secs), 0)
                 + sec_hdrs)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, cputype, 0, 2, len(segments), len(cmds), 0, 0)
    blob = header + cmds
    blob += b"\0" * (_align(len(blob), 16) - len(blob)) + body
    return blob, layout


def build_fat(slices):
    """slices: [(cputype, thin_macho_bytes), ...] -> (blob, [slice_file_offset, ...])."""
    n = len(slices)
    table = struct.pack(">II", 0xCAFEBABE, n)
    offsets, pos = [], _align(8 + 20 * n, 0x4000)
    body = b""
    for cputype, data in slices:
        offsets.append(pos)
        table += struct.pack(">iiIII", cputype, 0, pos, len(data), 14)
        body += b"\0" * (pos - 8 - 20 * n - len(body)) + data
        pos = _align(pos + len(data), 0x4000)
    return table + body, offsets


def build_elf64(segments):
    """segments: [(p_type, p_flags, data_bytes), ...] -> (blob, [(start, end), ...])."""
    phnum = len(segments)
    pos = _align(64 + 56 * phnum, 16)
    phdrs, body, spans = b"", b"", []
    for p_type, p_flags, data in segments:
        phdrs += struct.pack("<IIQQQQQQ", p_type, p_flags, pos, 0x400000 + pos, 0x400000 + pos,
                             len(data), len(data), 0x1000)
        body += data
        spans.append((pos, pos + len(data)))
        pos += len(data)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0, 64, 0, 0, 64, 56, phnum, 64, 0, 0)
    blob = ehdr + phdrs
    blob += b"\0" * (_align(len(blob), 16) - len(blob)) + body
    return blob, spans
