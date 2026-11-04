"""
A synthetic AArch64 "build" for the relocate tests: N functions, each a few dozen
instructions long (prologue, a body mixing plain ALU / load / store words with
`bl`, `cbz`, `b.cond` and adrp+ldr / adrp+add data references, epilogue, `ret`),
laid out one after another in a Mach-O `__TEXT,__text` section.

Why not a handful of hand-written words like the other fixtures: the failure this
exists for - a hook at a function ENTRY, where the words in front of the hook point
belong to the previous function - only shows up when there are real neighbours, and
when a "rebuild" really re-encodes every PC-relative operand (new `bl` distances,
new adrp pages, new lo12 offsets) the way a linker does. `assemble()` therefore
works from symbolic ops and resolves them against whatever layout it is given, so
the same function bodies can be laid out in a different order, with a new function
in between, or with the data section moved - and the bytes of every call, adrp and
data load change accordingly, while the function bodies stay "the same code".

Deterministic: everything comes from `random.Random(seed)`.
"""
import random
import struct

from binfmt_fixtures import CODE, build_macho

# Fixed words ---------------------------------------------------------------
STP_FP_LR = 0xA9BF7BFD      # stp x29, x30, [sp, #-0x10]!
MOV_FP_SP = 0x910003FD      # mov x29, sp
LDP_FP_LR = 0xA8C17BFD      # ldp x29, x30, [sp], #0x10
RET = 0xD65F03C0            # ret
NOP = 0xD503201F            # nop

DATA_BASE = 0x4000000       # where the synthetic data section lives (outside the image)


# Encoders ------------------------------------------------------------------
def add_imm(rd, rn, imm):   return 0x91000000 | (imm & 0xFFF) << 10 | rn << 5 | rd
def sub_imm(rd, rn, imm):   return 0xD1000000 | (imm & 0xFFF) << 10 | rn << 5 | rd
def mov_reg(rd, rm):        return 0xAA0003E0 | rm << 16 | rd
def and_reg(rd, rn, rm):    return 0x8A000000 | rm << 16 | rn << 5 | rd
def eor_reg(rd, rn, rm):    return 0xCA000000 | rm << 16 | rn << 5 | rd
def mul(rd, rn, rm):        return 0x9B007C00 | rm << 16 | rn << 5 | rd
def csel(rd, rn, rm, cond): return 0x9A800000 | rm << 16 | cond << 12 | rn << 5 | rd
def cmp_imm(rn, imm):       return 0xF100001F | (imm & 0xFFF) << 10 | rn << 5
def cmp_reg(rn, rm):        return 0xEB00001F | rm << 16 | rn << 5
def movz(rd, imm16):        return 0xD2800000 | (imm16 & 0xFFFF) << 5 | rd
def ldr_x(rt, rn, off8):    return 0xF9400000 | (off8 & 0xFFF) << 10 | rn << 5 | rt
def str_x(rt, rn, off8):    return 0xF9000000 | (off8 & 0xFFF) << 10 | rn << 5 | rt
def ldr_w(rt, rn, off4):    return 0xB9400000 | (off4 & 0xFFF) << 10 | rn << 5 | rt
def ldrb(rt, rn, off):      return 0x39400000 | (off & 0xFFF) << 10 | rn << 5 | rt
def ldur(rt, rn, imm9):     return 0xF8400000 | (imm9 & 0x1FF) << 12 | rn << 5 | rt
def fadd_d(rd, rn, rm):     return 0x1E602800 | rm << 16 | rn << 5 | rd


def adrp(rd, pc, target):
    pages = (target >> 12) - (pc >> 12)
    return 0x90000000 | (pages & 3) << 29 | ((pages >> 2) & 0x7FFFF) << 5 | rd


def bl(pc, target):          return 0x94000000 | ((target - pc) >> 2) & 0x3FFFFFF
def cbz(rt, skip_words):     return 0xB4000000 | (skip_words & 0x7FFFF) << 5 | rt
def b_cond(cond, skip_words): return 0x54000000 | (skip_words & 0x7FFFF) << 5 | cond


# Function bodies -----------------------------------------------------------
# An op is a tuple: ("raw", word) | ("bl", func_id) | ("cbz", reg, skip) |
# ("bcond", cond, skip) | ("data_ldr" | "data_add" | "data_ldrb", slot, reg).
# The data_* ops are two words (adrp + the instruction that adds the page offset).
_SIZE = {"raw": 1, "bl": 1, "cbz": 1, "bcond": 1, "data_ldr": 2, "data_add": 2, "data_ldrb": 2}


def _safe_word(rng):
    def r():
        return rng.randrange(0, 29)           # x0..x28: never sp/fp/lr/zr

    return rng.choice([
        lambda: add_imm(r(), r(), rng.randrange(1, 0x400)),
        lambda: sub_imm(r(), r(), rng.randrange(1, 0x400)),
        lambda: mov_reg(r(), r()),
        lambda: and_reg(r(), r(), r()),
        lambda: eor_reg(r(), r(), r()),
        lambda: mul(r(), r(), r()),
        lambda: csel(r(), r(), r(), rng.randrange(14)),
        lambda: cmp_imm(r(), rng.randrange(0x100)),
        lambda: cmp_reg(r(), r()),
        lambda: movz(r(), rng.randrange(0x10000)),
        lambda: ldr_x(r(), r(), rng.randrange(0x40)),
        lambda: str_x(r(), r(), rng.randrange(0x40)),
        lambda: ldr_w(r(), r(), rng.randrange(0x40)),
        lambda: ldrb(r(), r(), rng.randrange(0x40)),
        lambda: ldur(r(), r(), rng.randrange(-0x80, 0x80)),
        lambda: fadd_d(rng.randrange(0, 32), rng.randrange(0, 32), rng.randrange(0, 32)),
    ])()


def gen_function(rng, n_funcs, n_slots, body_ops=None, tail_safe=4):
    """One function as a list of ops. `n_funcs`/`n_slots` bound the call targets
    and data slots it may reference. The last `tail_safe` body ops are plain ALU /
    load / store words, so the tail (`... ldp; ret`) is a run of position-independent
    instructions - the shape that makes a backward scan from the NEXT function's
    entry produce a perfectly valid-looking fingerprint of the wrong function."""
    ops = [("raw", STP_FP_LR), ("raw", MOV_FP_SP)]
    for _ in range(body_ops or rng.randrange(8, 28)):
        roll = rng.random()
        if roll < 0.62:
            ops.append(("raw", _safe_word(rng)))
        elif roll < 0.74:
            ops.append(("bl", rng.randrange(n_funcs)))
        elif roll < 0.86:
            ops.append((rng.choice(["data_ldr", "data_add", "data_ldrb"]),
                        rng.randrange(n_slots), rng.randrange(0, 29)))
        else:
            # a forward branch over exactly `skip - 1` words that follow it, so it
            # lands inside the function
            skip = rng.randrange(2, 5)
            ops.append(("cbz", rng.randrange(0, 29), skip) if rng.random() < 0.5
                       else ("bcond", rng.randrange(14), skip))
            ops += [("raw", _safe_word(rng)) for _ in range(skip - 1)]
    ops += [("raw", _safe_word(rng)) for _ in range(tail_safe)]
    ops += [("raw", LDP_FP_LR), ("raw", RET)]
    return ops


def func_words(ops):
    return sum(_SIZE[op[0]] for op in ops)


def _emit(op, pc, func_addr, data_base):
    """The words one op assembles to at address `pc`."""
    kind = op[0]
    if kind == "raw":
        return [op[1]]
    if kind == "bl":
        return [bl(pc, func_addr[op[1]])]
    if kind == "cbz":
        return [cbz(op[1], op[2])]
    if kind == "bcond":
        return [b_cond(op[1], op[2])]
    slot_addr = data_base + op[1] * 8
    reg = op[2]
    first = adrp(reg, pc, slot_addr)
    lo12 = slot_addr & 0xFFF
    if kind == "data_ldr":
        return [first, ldr_x(reg, reg, lo12 // 8)]
    if kind == "data_add":
        return [first, add_imm(reg, reg, lo12)]
    return [first, ldrb(reg, reg, lo12)]            # data_ldrb


class Image:
    """`functions`: {func_id: ops}. `order`: the func ids in layout order.
    `data_base`: where the data slots live. `padding`: nops between functions."""

    def __init__(self, functions, order, data_base=DATA_BASE, padding=0):
        self.functions, self.order = functions, list(order)
        self.data_base, self.padding = data_base, padding
        self._assemble()

    def _assemble(self):
        sizes = [func_words(self.functions[f]) for f in self.order]
        total = sum(sizes) + self.padding * len(self.order)
        # The section's file offset depends only on the header, not on its content.
        _dummy, lay = build_macho([("__TEXT", 5, [("__text", CODE, b"\0" * (4 * total))])])
        self.text_start = lay["__TEXT,__text"][0]
        self.entry, pos = {}, self.text_start
        for f, n in zip(self.order, sizes):
            self.entry[f] = pos
            pos += 4 * (n + self.padding)
        words = []
        for f in self.order:
            pc = self.entry[f]
            for op in self.functions[f]:
                out = _emit(op, pc, self.entry, self.data_base)
                words += out
                pc += 4 * len(out)
            words += [NOP] * self.padding
        self.words = words
        self.blob, lay = build_macho([("__TEXT", 5, [("__text", CODE, struct.pack(f"<{len(words)}I", *words))])])
        assert lay["__TEXT,__text"][0] == self.text_start

    def function_words(self, func_id):
        start = (self.entry[func_id] - self.text_start) // 4
        return self.words[start:start + func_words(self.functions[func_id])]

    def write(self, path):
        with open(path, "wb") as f:
            f.write(self.blob)
        return str(path)


def make_functions(seed=7, n_funcs=300, n_slots=64):
    rng = random.Random(seed)
    return {i: gen_function(rng, n_funcs, n_slots) for i in range(n_funcs)}
