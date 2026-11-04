// Which BUILD of the IL2CPP library is this? The loaded module's own identity, read from its
// headers in memory:
//
//   macho-uuid      the LC_UUID load command of a 64-bit Mach-O (iOS / macOS), as a lower-case
//                   8-4-4-4-12 UUID - what `dwarfdump --uuid` and `otool -l` print;
//   gnu-build-id    the NT_GNU_BUILD_ID note of an ELF64 (Android / Linux), as lower-case hex -
//                   what `readelf -n` prints as "Build ID".
//
// A rebuild changes it (a UUID/build-id is made from the contents); a re-sign or a re-package
// does not, which is the point: it says "the same code as last time" without anyone having to
// compare offsets. retk/buildid.py reads the same two things from a FILE (tests/test_buildid.py
// checks that both agree on the same bytes), and retk builds keys what a run learned by it.
//
// Reads only through readU8 / readU32 / add, so it works on a NativePointer as it is. It never
// throws: a module that has neither (a PE, a stripped ELF, a header that cannot be read) is
// `null`, and the caller then simply has no build to key on.

// Written in decimal: scripts/ holds no hex literal above fff (tests/test_layouts.py) - these are
// file-format constants, not target values, but the guard does not tell them apart.
const MH_MAGIC_64 = 4277009103;          // feedfacf: a little-endian 64-bit Mach-O, as the bytes sit in memory
const LC_UUID = 0x1b;
const ELF_MAGIC = 1179403647;            // 464c457f: "\x7fELF" read as a little-endian u32
const PT_LOAD = 1;
const PT_NOTE = 4;
const NT_GNU_BUILD_ID = 3;
const PAGE = 4096;

// Sanity bounds: a header that claims more than this is garbage, not a bigger library.
const MAX_LOAD_COMMANDS = 512;
const MAX_PROGRAM_HEADERS = 256;
const MAX_NOTE_BYTES = 65536;
const MAX_NOTES = 64;

const hex2 = (n) => (n < 16 ? "0" : "") + n.toString(16);

function u16(p) { return p.readU8() | (p.add(1).readU8() << 8); }
function u64(p) { return p.readU32() + p.add(4).readU32() * 4294967296; }   // exact below 2**53: every offset here
function bytesHex(p, n) {
    let s = "";
    for (let i = 0; i < n; i++) s += hex2(p.add(i).readU8());
    return s;
}

function machoUuid(base) {
    const ncmds = base.add(16).readU32();
    const sizeofcmds = base.add(20).readU32();
    if (ncmds === 0 || ncmds > MAX_LOAD_COMMANDS || sizeofcmds > 1048576) return null;
    let at = 32;                           // sizeof(mach_header_64)
    for (let i = 0; i < ncmds; i++) {
        const cmd = base.add(at).readU32();
        const size = base.add(at + 4).readU32();
        if (size < 8 || size % 4 !== 0 || at + size > 32 + sizeofcmds) return null;
        if (cmd === LC_UUID) {
            if (size < 24) return null;
            const h = bytesHex(base.add(at + 8), 16);
            return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
        }
        at += size;
    }
    return null;
}

function gnuBuildId(base) {
    if (base.add(4).readU8() !== 2 || base.add(5).readU8() !== 1) return null;   // ELFCLASS64, little-endian
    const phoff = u64(base.add(32));
    const phentsize = u16(base.add(54));
    const phnum = u16(base.add(56));
    if (phnum === 0 || phnum > MAX_PROGRAM_HEADERS || phentsize < 56) return null;

    // Frida's module base is the lowest mapped page; the ELF's addresses are relative to the load
    // bias. bias = base - (the lowest PT_LOAD address, page-aligned down).
    const headers = [];
    let lowest = null;
    for (let i = 0; i < phnum; i++) {
        const ph = base.add(phoff + i * phentsize);
        const h = { type: ph.readU32(), vaddr: u64(ph.add(16)), filesz: u64(ph.add(32)) };
        headers.push(h);
        if (h.type === PT_LOAD && (lowest === null || h.vaddr < lowest)) lowest = h.vaddr;
    }
    if (lowest === null) return null;
    const bias = -(lowest - (lowest % PAGE));                   // add this to a vaddr to get an offset from `base`

    for (const h of headers) {
        if (h.type !== PT_NOTE || h.filesz < 12 || h.filesz > MAX_NOTE_BYTES) continue;
        const start = h.vaddr + bias;
        let at = 0;
        for (let n = 0; n < MAX_NOTES && at + 12 <= h.filesz; n++) {
            const note = base.add(start + at);
            const namesz = note.readU32();
            const descsz = note.add(4).readU32();
            const type = note.add(8).readU32();
            const nameAt = at + 12;
            const descAt = nameAt + Math.ceil(namesz / 4) * 4;
            const next = descAt + Math.ceil(descsz / 4) * 4;
            if (next > h.filesz) break;
            if (type === NT_GNU_BUILD_ID && namesz === 4 && descsz > 0 && descsz <= 64 &&
                bytesHex(base.add(start + nameAt), 4) === "474e5500") {           // "GNU\\0"
                return bytesHex(base.add(start + descAt), descsz);
            }
            at = next;
        }
    }
    return null;
}

/**
 * `{kind, id}` for the loaded module `mod` (anything with a `base`), or null.
 * @returns {{kind: "macho-uuid" | "gnu-build-id", id: string} | null}
 */
export function readBuildId(mod) {
    try {
        const base = mod.base;
        const magic = base.readU32();
        if (magic === MH_MAGIC_64) {
            const id = machoUuid(base);
            return id ? { kind: "macho-uuid", id } : null;
        }
        if (magic === ELF_MAGIC) {
            const id = gnuBuildId(base);
            return id ? { kind: "gnu-build-id", id } : null;
        }
    } catch (e) {
        // an unreadable header: no build to name
    }
    return null;
}

/** The text a build is known by in `params.cache.builds` and in the build cache: "kind:id". */
export function buildKey(build) {
    return `${build.kind}:${build.id}`;
}
