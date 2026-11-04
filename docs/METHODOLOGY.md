[← Back to README](../README.md)

# Methodology: working out an unknown record layout

A worked procedure for reading a record whose layout you don't know, by
hooking the function that fills it in and looking at memory around the
pointer you're handed. It is written against the **example** target in this
repo (`ExampleNamespace.ExampleTableA` / `ExampleTableB`); the same steps
apply to any IL2CPP record. What you find for a *real* target - its class
names, field names, offsets and header size - goes into a private profile
([Profiles](PROFILES.md)), never into this repo.

The symptoms below are the usual ways a first guess goes wrong. Each one cost
someone a debugging session; none is specific to one app.

## 0. Prerequisites

- The IL2CPP binary, its `global-metadata.dat`, and a `dump.cs` / symbol map
  from an IL2CPP dumper, all loaded in Ghidra.
- The RVA of the `...$$unpack` (or equivalent) function that fills the record
  (Ghidra address with Image Base = `0`). See [RVA vs file offset](../README.md#rva-vs-file-offset).
- A device or simulator running the target with `frida-server` reachable.

## 1. Check the header size first

IL2CPP objects start with a header, and every field offset is relative to
the object pointer, so a wrong header size shifts *every* field by the same
amount. Stock 64-bit IL2CPP uses 16 bytes (`klass` + `monitor`). The profile's
`headerSize` records what your build actually does; don't assume it.

| Symptom | Likely cause |
|---|---|
| Every field you expect to hold a small integer holds something that looks like a pointer, or the reverse | header size off by 8 |
| The first declared field reads as `NULL` although the dumper says it is a non-null reference | same - the slot you're reading is really the one before it |
| Several different records produce the same string length | the string's length field isn't where you think; see step 4 |

Settle this with one record before reading anything else: find a field you
can identify independently (a small integer `id` you can see in the app, or a
string you can read) and see which header size puts it at the offset the
declared member order predicts.

## 2. Dump raw bytes, don't decode yet

Build `scripts/probe_record.js`, point it at your RVA and read the hexdump of
the first few records. It prints the raw record plus 48 raw bytes behind every
slot that *could* be a pointer. Nothing is decoded: a "possible pointer" is a
non-null value inside a readable range, which an integer can satisfy too.

## 3. Read the layout by eye, in declaration order

IL2CPP lays fields out in the class's declared member order with natural
alignment - not reordered, and not padded to 8-byte slots one by one. So the
dumper's member list is your map; the hexdump tells you where each member
landed.

- Count hexdump rows carefully: a row is 16 bytes, i.e. two 8-byte slots.
  Miscounting by one row puts a "string pointer" 8 bytes from where it is.
- Padding after a small field (an `int8`, say) explains why it looks like it
  occupies a whole 8-byte slot.
- A region you can't account for is a result too: record it under `unread` in
  your profile's layout, with what you tried, instead of guessing a type for it.

## 4. Strings: dump raw bytes at each *new* pointer

If distinct records give the same string length, or garbage, stop guessing
offsets inside `System.String`. Dump raw hex at each *new* string pointer
(deduplicated) and read the length and the UTF-16 characters by eye. Put what
you find in the profile's `il2cppString` block (`lengthOffset`, `charsOffset`).
Cross-check against `readIl2CppString` in `scripts/_lib.js` before trusting it.

## 5. Write it into your profile

Put the confirmed layout in your profile's `layouts` section (field name,
offset, type; `key` says which field(s) identify a record) and the RVA in its
`offsets`. `retk profile layout <profile>` validates it and prints
the listing, so a misaligned or overlapping field is caught before it costs a
dump. Rebuilding is not needed: the agents receive the layout when the driver
starts them ([Profiles](PROFILES.md)). `tests/test_layouts.py` shows how to
check a layout against an independent decoder over a fake process image.

Then write down what you *observed*, so the next build can contradict it: an
`expect` on every field whose values you actually looked at (`"expect":
{"oneOf": [0, 1]}` for a flag you saw as 0 or 1, `{"min": 1}` for an id,
`{"nonEmpty": true, "maxLength": 64}` for a name). The agents check each record
they read against these, and `retk dump` fails the dump when the data
contradicts the layout - which is the only thing that tells you a layout has
gone stale on a build you haven't looked at by eye (docs/MEMORY_LAYOUT.md,
"Checking a layout at run time"). Without them the check is only structural,
and says so in its notes.

## 6. Reuse what you learned

The header size and string layout are properties of the build, so they carry
over to every other record in it. The second table usually needs only a
probe run, not another round of header and string archaeology.

## 7. When the build updates

Offsets move; layouts usually don't. Three steps, each answering a different
question, and each one only as strong as what it says:

1. **Where is it now?** `retk relocate OLD OLD_OFFSET NEW --json
   relocate_new.json` re-locates the function by instruction fingerprint,
   cross-checked by other windows of the same function and by the code that calls
   it (the label drops to LOW when they disagree), and prints the result as an
   RVA beside the file offset. That is a *match*: the code looks like the old
   function's.
2. **Is that what the app calls?** `retk verify --profile NAME
   --from-relocate relocate_new.json` hooks the candidate(s) in the running app and
   reads what comes back through the layout. `VERIFIED` means it fired and the
   records were valid; `NOT EXERCISED` means "use the app so the code path runs",
   not "wrong"; `REJECTED` with "the fields fit only shifted by +8" means the
   *layout* moved, not the address (go to step 3). Two `VERIFIED` candidates are
   `AMBIGUOUS` - decide by what the functions do. Verified is not proof it is the
   function you meant, only that the app calls it and hands it records of this
   layout.
3. **Does the layout still hold?** Re-verify the header size and one record before
   trusting an old layout on a new build - or let the dump do it. The first 16
   records are judged while you play (`--layout-gate`): a layout that is wrong
   about nearly everything ends the run with "LAYOUT MAY HAVE CHANGED" and the
   header size the data would fit, instead of a long dump of garbage; a run that
   ends with "Layout check passed" has at least not been contradicted by the data,
   and one that ends with "LAYOUT CHECK FAILED" (exit status 3) has been, whatever
   the records look like. A suggested header size is a measurement: confirm it
   with step 1 of this file before editing the profile.
