[← Back to README](../README.md)

# Relocating and verifying offsets

## Relocating an offset

When the app ships a new binary and offsets shift, `retk relocate` re-locates a known offset in the
new build by instruction fingerprinting, instead of re-deriving it by hand in Ghidra every time.

```bash
retk relocate UnityFramework_old 0xab68fc8 UnityFramework_new --json relocate_new.json
```

- **Input and output.** It takes and prints *file* offsets, and prints the matching **RVA** on a
  `NEW RVA` line - the number a profile's `offsets` entry takes. Thin Mach-O, fat Mach-O and ELF64 are
  converted; for anything else it says it cannot (see [File offset to RVA conversion](#file-offset-to-rva-conversion)).
- **AArch64 only.** It refuses anything else by name.
- **What gets fingerprinted.** A hook point is normally a function *entry*, so by default
  (`--mode auto`) the fingerprint is the function's own first instructions, with the operands that move
  in a rebuild (call targets, adrp pages and their lo12 offsets, branch offsets) wildcarded - not the
  words in front of it, which at an entry are the tail of the *previous* function. For a hook point in
  the middle of a function, `--mode before` fingerprints the instructions in front of it instead, never
  past a `ret`.
- **Confidence.** Each candidate is checked (alignment, inside an executable section, how the
  surrounding code or the rest of the function compares to the old build) and reported as
  HIGH / MEDIUM / LOW. That is a sanity check around a fingerprint, not control-flow analysis, so
  verify the result once before trusting it (next section).

### Anchors: more than one witness

The fingerprint is not the only witness. With `--anchors` (on by default) the old build is also cut
into windows deeper in the function and into the code around each call site of it. Each window is
searched for on its own, and where it points is a vote:

- An anchor found in one place that points somewhere else drops the answer to **LOW**.
- A window of the function's code that is no longer where it should be caps it at **MEDIUM**.
- Votes settle a tie between identical-looking candidates (call sites alone: **MEDIUM**) and can find
  a function whose first instructions changed but whose body did not.
- Votes never raise a grade, and call sites never nominate a candidate.

### When it cannot answer

A rewritten function is reported as "no match" (plus where its old call sites point now, as a lead for
Ghidra). Two identical functions nobody can tell apart are reported as "more than one match" - not as an
answer.

### By name instead of bytes

With the new build's metadata dump, the hook point can be looked up by `Class::Method` instead (and a
rewritten function found that way), with the fingerprint as the cross-check: see
[Looking things up by name](NAME_LOOKUP.md).

### File offset to RVA conversion

`retk relocate` works in *file offsets*; everything else (a profile's `offsets`, `--offset`,
`retk verify --candidate`) takes *RVAs*. The two numbers are defined side by side in the README's
[RVA vs file offset](../README.md#rva-vs-file-offset). How the conversion works:

They coincide for code in a thin Mach-O slice such as the iOS
`UnityFramework` (its `__TEXT` segment starts at file offset 0). They do not
for a fat Mach-O (RVA = file offset minus the arch slice's offset, see `lipo
-detailed_info`) or an ELF such as Android's `libil2cpp.so` (per-segment
`p_offset` vs `p_vaddr`, see `readelf -lW`). `retk relocate` does the
conversion for its *result*: next to `NEW FILE OFFSET` it prints `NEW RVA`
(Mach-O: the segment's `vmaddr` minus `__TEXT`'s, per arm64 slice in a fat
file; ELF: `p_vaddr` minus the lowest page-aligned load address, which is what
Frida calls `module.base`), and an ambiguous result lists an RVA per
candidate. Its *input*, the old offset, is still a file offset, so convert a
Ghidra address (an RVA) of the old build before handing it in. When it cannot
convert (a container it does not read) it says so instead of printing a
guess.

## Verifying a relocated offset

`retk relocate` answers "where is the code that looks like the old
function?". It cannot answer "is that what the app calls, and does it still hand
over a record of this layout?" - a byte match says the instructions are alike,
nothing more. `retk verify` runs the candidate:

```bash
retk relocate UnityFramework_old 0xab68fc8 UnityFramework_new --json relocate_new.json
retk verify --profile myapp --from-relocate relocate_new.json
retk verify --profile myapp --candidate 0xab68fc8 --candidate 0xab69100   # RVAs
retk verify --profile myapp          # does the profile's own table_a still work here?
```

It spawns the app, loads `dist/verify_hook.js` (`npm run build`), hooks every
candidate and lets you use the app until each has been called `--min-records`
times (default 3), `--wait` seconds have passed (default 90, `0` = until you
press Enter) or you press Enter. For every call the agent does what the dump
agents do - take the record from `args[0]`, and when the call succeeded read it
through the profile's layout - and feeds it to the same [layout check](LAYOUT_CHECK.md)
(class word, string sanity, `expect`, shift probe). The driver then judges the
counts per candidate:

```text
[+] VERIFIED  c0 RVA 0xab68fc8 (HIGH): called 24 times, 6 records read through the layout, all of them valid
      + class word a valid pointer in all 6 and identical
      + id: varies and keeps its `expect`
      + name: 6 readable strings
[?] NOT EXERCISED  c1 RVA 0xab69100 (MEDIUM): was never called
      note: either the code path did not run in the time given - use the app so it does (open the screen that loads the table) - or this is not a function the app calls
[!] REJECTED  c2 RVA 0xab6a000 (LOW): fired, but what it returned contradicts the layout
      - TableARecord: the word at +0 is not a valid class pointer in 9 of 9 (100%) records - is args[0] the object the layout describes, and is the object header what the layout assumed?
[+] VERIFIED - the app calls it, and what it hands back fits the profile's layout.
```

(The shape of the report, produced from the unit tests' hand-written counts, not
from a device.)

| Status | Meaning |
|---|---|
| `VERIFIED` | the hook fired, enough records came back, none of them contradicts the layout, and at least one field that could have told right from wrong (a string, a numeric `expect`) was among them |
| `WEAK` | fired and nothing contradicts the layout, but too few records, or only fields that cannot tell - not enough to say |
| `REJECTED` | fired and the records contradict the layout, or the candidate was refused unhooked: not 4-byte aligned, beyond the module, in memory that is not executable. When the whole layout fits shifted, the report says the *layout* moved, not that the candidate is wrong |
| `NOT EXERCISED` | never called in the time given (use the app so the code path runs), or every call returned a failure |
| `CRASHED` | the app died with the hooks installed; with several candidates the crash cannot be attributed - rerun them one at a time with `--candidate` |

Exit status: **0** verified, **3** every candidate rejected or crashed (the same
code as a failed layout check), **4** nothing could be confirmed, **5** ambiguous:
more than one candidate verified. Two verified candidates are never a quiet tie -
that is what a function and its sibling taking the same record type look like,
and the tool will not pick one for you. `--json PATH` writes the verdict
(`verify*.json` is git-ignored: it names real offsets).

What *verified* is, and is not: the candidate is called by the running app, and
what it receives and returns is a record of this layout. It is **not** proof of
it being the function you meant - a sibling that takes the same record type
verifies just as well - and a field with no `expect` is only checked
structurally. It assumes the dump agents' convention (the record is `args[0]`,
success is a zero low 32 bits of the return value); a hook point that hands the
record back some other way is not covered. A candidate in a container
`retk relocate` cannot convert has no RVA in its report, and the driver
says so instead of hooking a guess.
