"""
Which build is this binary? Its own identity, read from the headers of a FILE:

    macho-uuid      the LC_UUID of a 64-bit Mach-O, as a lower-case 8-4-4-4-12 UUID
                    (what `dwarfdump --uuid` / `otool -l` print). A fat binary is read at its
                    arm64 slice, the one the toolkit works on.
    gnu-build-id    the NT_GNU_BUILD_ID note of an ELF64, as lower-case hex
                    (what `readelf -n` prints as "Build ID").

scripts/_buildid.js reads the same two things from a LOADED module in the target; tests/test_buildid.py
holds them to agreeing on the same bytes. A UUID / build-id is made from the contents, so a rebuild changes
it and a re-sign or a re-package does not: the same value means the same code, hence the same RVAs
(retk builds keys what a verified run learned by it).

    retk builds key libil2cpp.so        # print one

A binary with neither (a PE, a stripped ELF, a 32-bit image) has no build id here: `from_bytes` returns None.
"""
import re
import struct
import uuid
from dataclasses import dataclass

KIND_MACHO = "macho-uuid"
KIND_ELF = "gnu-build-id"
KINDS = (KIND_MACHO, KIND_ELF)

_MH_MAGIC_64 = 0xFEEDFACF
_FAT_MAGIC = 0xCAFEBABE
_FAT_MAGIC_64 = 0xCAFEBABF
_CPU_TYPE_ARM64 = 0x0100000C
_LC_UUID = 0x1B
_PT_NOTE = 4
_NT_GNU_BUILD_ID = 3
_MAX_LOAD_COMMANDS = 512
_MAX_PROGRAM_HEADERS = 256
_MAX_NOTES = 64


@dataclass(frozen=True)
class BuildId:
    kind: str
    id: str

    @property
    def text(self):
        """"kind:id", how a build is named in params and in the cache."""
        return f"{self.kind}:{self.id}"

    @property
    def filename(self):
        """A file name for it - no ':', which Windows does not allow in one."""
        return f"{self.kind}_{self.id}"


def valid_id(kind, ident):
    """Is `ident` the shape of an id of `kind`? (The cache refuses anything else, e.g. a path.)"""
    if kind == KIND_MACHO:
        return bool(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", ident))
    if kind == KIND_ELF:
        return bool(re.fullmatch(r"(?:[0-9a-f]{2}){1,64}", ident))
    return False


def _macho(data, at=0):
    if len(data) < at + 32 or struct.unpack_from("<I", data, at)[0] != _MH_MAGIC_64:
        return None
    ncmds, sizeofcmds = struct.unpack_from("<II", data, at + 16)
    if not 0 < ncmds <= _MAX_LOAD_COMMANDS or sizeofcmds > 0x100000:
        return None
    pos = at + 32
    for _ in range(ncmds):
        if pos + 8 > len(data):
            return None
        cmd, size = struct.unpack_from("<II", data, pos)
        if size < 8 or size % 4 or pos + size > at + 32 + sizeofcmds:
            return None
        if cmd == _LC_UUID:
            if size < 24 or pos + 24 > len(data):
                return None
            return BuildId(KIND_MACHO, str(uuid.UUID(bytes=bytes(data[pos + 8:pos + 24]))))
        pos += size
    return None


def _fat(data):
    magic = struct.unpack_from(">I", data, 0)[0]
    wide = magic == _FAT_MAGIC_64
    nfat = struct.unpack_from(">I", data, 4)[0]
    if nfat == 0 or nfat > 16:
        return None
    entry = 32 if wide else 20
    slices = []
    for i in range(nfat):
        at = 8 + i * entry
        if at + entry > len(data):
            return None
        cputype = struct.unpack_from(">I", data, at)[0]
        offset = struct.unpack_from(">Q" if wide else ">I", data, at + 8)[0]
        slices.append((cputype, offset))
    for cputype, offset in slices:
        if cputype == _CPU_TYPE_ARM64:
            return _macho(data, offset)
    return None


def _elf(data):
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:     # ELF64, little-endian
        return None
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    if not 0 < phnum <= _MAX_PROGRAM_HEADERS or phentsize < 56:
        return None
    for i in range(phnum):
        at = phoff + i * phentsize
        if at + 56 > len(data):
            return None
        ptype = struct.unpack_from("<I", data, at)[0]
        offset, _vaddr, _paddr, filesz = struct.unpack_from("<QQQQ", data, at + 8)
        if ptype != _PT_NOTE or filesz < 12 or offset + filesz > len(data):
            continue
        pos, end = offset, offset + filesz
        for _ in range(_MAX_NOTES):
            if pos + 12 > end:
                break
            namesz, descsz, ntype = struct.unpack_from("<III", data, pos)
            name_at = pos + 12
            desc_at = name_at + (namesz + 3) // 4 * 4
            nxt = desc_at + (descsz + 3) // 4 * 4
            if nxt > end:
                break
            if ntype == _NT_GNU_BUILD_ID and namesz == 4 and data[name_at:name_at + 4] == b"GNU\0" and 0 < descsz <= 64:
                return BuildId(KIND_ELF, bytes(data[desc_at:desc_at + descsz]).hex())
            pos = nxt
    return None


def from_bytes(data):
    """The BuildId of a Mach-O / ELF64 image held in `data`, or None."""
    data = memoryview(bytes(data)) if not isinstance(data, (bytes, bytearray, memoryview)) else data
    if len(data) < 8:
        return None
    head = bytes(data[:4])
    if head in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        return _fat(data)
    if head == b"\xcf\xfa\xed\xfe":
        return _macho(data)
    if head == b"\x7fELF":
        return _elf(data)
    return None


def from_file(path):
    """The BuildId of the binary at `path`, or None. Raises OSError when it cannot be read."""
    with open(path, "rb") as f:
        return from_bytes(f.read())
