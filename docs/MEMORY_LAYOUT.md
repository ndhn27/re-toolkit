[← Back to README](../README.md)

# Memory layout notes (example)

How the **example** records in this repo are laid out, and the rules the
layouts follow. The target is made up (`ExampleNamespace.ExampleTableA` /
`ExampleTableB`): a real build's layouts are build-specific, must be
re-verified on every new build (offsets in particular will drift - see
`retk relocate`), and live in your profile, not here - see
[Profiles](PROFILES.md). [`METHODOLOGY.md`](METHODOLOGY.md) explains how to work a layout
out for your own target.

A layout is data: the `layouts` section of a profile JSON
([`profile.example.json`](../profile.example.json) for this example), checked
by `retk/layouts.py` and handed to the agents at runtime. Nothing here is
compiled into `scripts/`. The listings below are the verbatim output of

```bash
retk profile layout profile.example.json
```

(`tests/test_layouts.py` fails if they drift from the example profile.)

## IL2CPP object header

Standard 64-bit IL2CPP objects have a 16-byte header (`klass` pointer +
`monitor` pointer), and the example uses exactly that (`headerSize: 16`). The
header size is a property of the build, not a constant of IL2CPP: the profile
carries it as `headerSize`, every field offset is relative to the object
pointer, and a wrong value shifts every offset in every record by the same
amount. Treat it as the first thing to verify on a new target
(`docs/METHODOLOGY.md`, "Check the header size first").

## Field placement rule

Fields are laid out in declaration order with **natural alignment**: a field
starts at the next offset that is a multiple of its own size, and any gap
before it is padding. Fields are *not* padded to 8-byte slots individually.
`layouts.validate()` rejects a layout that breaks the rule (a misaligned,
overlapping or out-of-order field). The two records below show both effects:

- `TableARecord` mixes `uint32`/`int32` values, an `int8` and pointers, so
  padding appears after the `int8`, up to the next 8-byte boundary where the
  first pointer sits.
- `TableBRecord` packs `uint32`/`int32` fields back to back at a 4-byte
  stride, with no padding between them.

## `System.String`

An object header, then an `int32` length (not padded to 8 bytes), then the
UTF-16LE characters starting immediately after it, no gap. The profile's
`il2cppString` gives the two offsets (`lengthOffset`, `charsOffset`), and
`layouts.validate()` insists the characters follow the length directly.

When a string cannot be read (its pointer is unmapped, or its length is
negative or over the runaway-read cap in `scripts/_lib.js`), `readIl2CppString()`
returns a placeholder (`<read error: ...>` / `<unexpected len: N>`) instead of
throwing, so one bad string cannot abort the rest of a record. The layout
self-check counts those placeholders (below), but they never reach the export:
the dump agents store the field as `null` and give the record
`_unreadable: ["field", ...]`. `null` alone is ambiguous - a null string pointer
is a legitimate, unset value and reads as `null` too - so `_unreadable` is what
says "this one failed". `_unreadable` is therefore reserved: `layouts.validate()`
refuses a field of that name. (One residue: a genuine string that itself starts
with `<read error` or `<unexpected len` is indistinguishable from a failure.)

## `TableARecord`

```text
TableARecord  key=id
  One entry of ExampleNamespace.ExampleTableA, as read from a hooked
  `...$$unpack` call. A flat table: `id` is unique on its own.

+0x00  klass     object header (16 bytes)
+0x10  id        uint32          numeric record id  [expect: >= 1]
+0x14  weight    int32           example signed value
+0x18  enabled   int8            example on/off flag (0 or 1)  [expect: one of 0, 1]
+0x19  (padding, 7 bytes)
+0x20  name      System.String*  example string field  [expect: non-empty, <= 64 chars]
+0x28  rawBytes  (not read; 8 bytes)

rawBytes (+0x28..0x2f): byte[]* - an example of a region the agent does not read; the readable text is the System.String in `name`.
```

The pointers land on 8-byte boundaries because pointers must be 8-aligned,
which is why the small fields look like they occupy full slots here.

## `TableBRecord`

```text
TableBRecord  key=kind+id
  One entry of ExampleNamespace.ExampleTableB, as read from a hooked
  `...$$unpack` call. `id` is only unique within a `kind`, so records are
  keyed on both.

+0x00  klass     object header (16 bytes)
+0x10  id        uint32          numeric record id
+0x14  kind      uint32          record kind discriminator
+0x18  reserved  (not read; 8 bytes)
+0x20  lo1       int32
+0x24  hi1       int32
+0x28  lo2       int32
+0x2c  hi2       int32
+0x30  level     uint32
+0x34  flagA     uint32          example 0/1 flag
+0x38  flagB     uint32          example 0/1 flag
+0x3c  mode      uint32
+0x40  valueA    uint32
+0x44  valueB    uint32
+0x48  label     System.String*  example string field

reserved (+0x18..0x1f): 8-byte region left unread in this example. It is 8-aligned and sits before the first int32 run, which is consistent with a pointer field, but nothing here confirms that - treat an unidentified region as unknown until you read it on your own build.
```

Field names in a layout are whatever you want the agents' JSON output to
call them; the agents never name a field themselves, so renaming one is a
profile edit only. `key` lists the field(s) that identify a record in the
agent's store: `id` alone for `TableARecord`, `kind` + `id` for
`TableBRecord`, where `id` is only unique within a `kind`.

## Checking a layout at run time

A layout is a hypothesis about one build, worked out by eye (`docs/METHODOLOGY.md`)
and checked by nothing. When a build moves a field, or the object header is not
what the layout assumed, the agents would still read - the wrong bytes, at the
right addresses - and write plausible-looking garbage. So every record an agent
reads is also checked against the layout (`scripts/_canary.js`), and
`retk dump` judges the counts (`retk/layout_check.py`) when it exports:

| Check | Catches |
|---|---|
| the word at `+0` is an aligned, mapped pointer, and the same one in every record (`klass: "constant"`, the default; `"pointer"` for a table of several subclasses) | `args[0]` is not the record, or the header is not what `headerSize` assumed |
| a `string` field is null or a readable string without control characters or broken surrogates | a wrong `il2cppString` offset, a field that is not a string pointer |
| the field's `expect` (`min` / `max` / `oneOf` on a number, `nonEmpty` / `maxLength` on a string) | a numeric offset that is off - the part only you can supply, because only you saw the data |
| a read that throws | an offset that lands in unmapped memory |
| the same `key` re-sent with different contents, in most reads | a `key` that does not identify a record, or a wrong offset under it |

A string that could not be read counts against its field's tolerance like any
other violation, and is *also* named in the export (see `System.String` above),
which is what tells you which records to distrust when the count stays under
the tolerance and the verdict is `ok`.

The `expect` lines in the listings above are the example profile's. A check
fails when more than `--layout-tolerance` (default 5 %) of the reads it applied
to violated it; the exit status is then 3, and `meta.layout_check` in the
exported file records the verdict either way, so a dump read with the wrong
layout cannot be mistaken for a good one later.

### Which way it moved, and failing early

When the declared offsets read wrong, the agent also says *where the fields would
be*. For the first `sample` records (16 by default) it re-reads every field as if
the whole layout had shifted by -32..+32 bytes (steps of 8; the object header is
the part that usually grows), and counts per shift how many reads were valid: a
non-null readable string, or a nonzero number that keeps its `expect`. Zero,
null and a field with no `expect` prove nothing either way and are not counted.
`retk/layout_check.py` (`measure_drift`) turns the counts into a sentence:

- exactly one shift reads right and the declared offsets read wrong: *"LAYOUT MAY
  HAVE CHANGED - the fields fit when read 8 bytes further in - the object header
  would be 24 bytes, not the 16 the layout assumes"*. Field offsets in a profile
  are relative to the object pointer, not to the end of the header, so a header
  that grew by 8 means `headerSize` *and* every field offset move by 8 (see
  "IL2CPP object header"); the report's "header would be N" is the declared size
  plus the shift;
- several shifts fit equally, or none does (one field moved, `args[0]` is not the
  record): said as such, with no number;
- the declared offsets are *not* contradicted, or the word at `+0` is not a class
  pointer (the layout is not "shifted", the object is not the record): no drift is
  claimed.

The sentence is a measurement. Nothing is applied to a profile; confirm it by
reading the record once (`docs/METHODOLOGY.md`, step 1) and then edit `headerSize`.
It is blind where the checks are: a layout with no string and no `expect` has no
field that can tell a right shift from a wrong one, and it does not see a field
that moved on its own.

The same counts also feed an early gate. After the first `sample` records
(`retk dump --layout-gate N`, default 16; the driver passes it to the agent as
the `check.sample` / `check.gate` parameters) the agent sends a
`{type: "layout-sample", sample, health}` message once, failed reads included, and
the driver judges it with the rules above at a looser line,
`layout_check.GATE_TOLERANCE` = 25 % instead of `--layout-tolerance`: the gate is
for a layout wrong about nearly everything, so that an hour of play is not spent
on it. `--on-drift stop` (the default) ends the run and writes what was read to
`OUT.suspect.json`, never `OUT`; `warn` reports and leaves the verdict to the
export-time check. `meta.layout_gate` records what the gate saw either way.

The `verify_hook.js` agent (`retk verify`) uses the same counts to
judge a candidate address instead of a whole table; see
[Verifying a relocated offset](RELOCATE_AND_VERIFY.md#verifying-a-relocated-offset).

What it cannot see: a layout wrong in a way that keeps every value plausible
(two `uint32` fields swapped that both hold small numbers), and anything in a
field with no `expect` beyond the structural checks. A pass means "not
contradicted", never "correct", and the report's notes list the fields that
have no `expect`, constant fields, and small samples.

## Lookup entry points

Two functions can be hooked directly (`scripts/trace_lookup.js`), instead of
only reading the static tables, to observe the live selection algorithm:

- `LookupByPattern(key, ?, kind)` -> a `TableBRecord*`, or `NULL` if no
  pattern matched `key`.
- `ResolveDefault()` -> the top-level entry point; returns the final chosen
  record.

Both names are placeholders for whatever your target calls its equivalents.
Their RVAs (`offsets.lookup_by_pattern`, `offsets.resolve_default` in the
profile) are located via static analysis (Image Base = 0). The profile's
`LookupResult` subset names the few `TableBRecord` fields worth printing live.
