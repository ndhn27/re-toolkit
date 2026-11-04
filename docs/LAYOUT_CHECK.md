[← Back to README](../README.md)

# Checking a layout against the build

A layout is a hypothesis about one build, found by reading memory. When an update
moves a field, an unchecked agent keeps reading the wrong bytes and writes
plausible-looking garbage to `records.json` without a word. So the dump agents
count, for every record they read, how often the data contradicted the layout,
and `retk dump` judges the counts when it exports:

```text
[!] LAYOUT CHECK FAILED - the layout may have changed: what the agent read contradicts the profile's layout, so this dump is probably garbage:
      - TableARecord.id: 62 of 62 (100%) reads break the profile's `expect` (0 is below min 100)
      - TableARecord.enabled: 62 of 62 (100%) reads break the profile's `expect` (96 is not one of 0, 1)
      - TableARecord.name: 62 of 62 (100%) reads break the profile's `expect` (empty string, expected a non-empty one)
      - TableARecord: 60 of 62 (97%) reads re-sent a key with different contents - an update from the app, or `key` does not identify a record
    Re-derive the layout for this build (see docs/METHODOLOGY.md), or - if the checks are wrong for this table, not the layout - correct `expect` / `klass` in the profile or relax --layout-tolerance.
    note: TableARecord.weight: 0 in all 62 records - fine if the field really never varies, but a misplaced offset often reads as a constant
    note: TableARecord: no `expect` for weight [0] - these are only checked structurally, so a wrong offset that still yields plausible values would pass
```

(Real output, from a test program on Linux: the layout was the right one shifted
by 8 bytes, as if a build had grown the object header.) The verdict is also
recorded in the export's `meta.layout_check`, the file is still written - so
nothing is lost - and the exit status is **3**.

What is checked: the class word at `+0` (a valid, aligned, mapped pointer - the
same one in every record, unless the record says `"klass": "pointer"`), string
fields (readable, no control characters or broken surrogates), reads that
throw, a `key` that doesn't identify records, and **`expect`**: what *you*
observed about a field, which is the only thing that catches a numeric offset
that is merely off. A check fails when more than `--layout-tolerance` (default
0.05) of the reads it applied to violate it; `--no-layout-check` skips it.

**Saying what moved, not just that something did.** Beside the usual counts the
agent probes the first records again as if the whole layout had shifted: every
offset moved by -32..+32 bytes in steps of 8, counting at each shift how many
reads would have been valid (a readable string, a number that keeps its
`expect`). When the declared offsets read wrong and exactly one shift reads
right, the report says so, and what that would mean for the header:

```text
      - TableARecord: LAYOUT MAY HAVE CHANGED - the fields fit when read 8 bytes further in - the object header would be 24 bytes, not the 16 the layout assumes. At the declared offsets 16 of 16 informative reads in the first 16 record(s) are wrong; at +8 only 0 of 16 are. If so, `headerSize` and every offset move by +8; this is a measurement, nothing was applied - confirm it in the layout (docs/METHODOLOGY.md) before using it
```

It is a measurement, never a patch: nothing is written to the profile. If no
uniform shift explains the data (one field moved, or `args[0]` is not the
record), or several fit equally, it says that instead of picking one. It needs at
least one field that can tell right from wrong - a string, or a number with an
`expect` - and says nothing when there is none.

**Failing early (`--layout-gate`).** A table is dumped while someone plays the
app for minutes; learning at the Enter key that the layout was wrong from record
1 wastes all of it. So once the agent has read the first N records
(`--layout-gate N`, default 16, `0` turns it off, and `--no-layout-check` turns
it off too) it sends one snapshot of its counts and the driver judges it at
once, by the same rules with a looser line (a quarter of the reads, not 5 %:
the gate is for a layout that is wrong about nearly everything, one odd record
is the export-time check's business). Failed reads count, so a layout that
points into unmapped memory trips it as well. What happens next is
`--on-drift`:

- `stop` (the default) ends the run there, writes the records read so far to
  `OUT.suspect.json` (`records.json` becomes `records.suspect.json`; `meta.suspect`
  is true) and exits **3** - never to `OUT`, so a file with the name you asked
  for is always a dump that passed;
- `warn` prints the same verdict, keeps going, and leaves the decision to the
  export-time check.

A gate that passes prints one line (`the first 16 records fit the profile's
layout`), is recorded in `meta.layout_gate`, and means no more than the full
check does: not contradicted so far.

The honest limits: a pass means "not contradicted", never "correct". A layout
that is wrong in a way that keeps every value plausible (two `u32` fields
swapped that both hold small numbers) passes, and so does zeroed memory read
through a layout that misses the data - unless an `expect` says otherwise. The
report's notes list the fields without an `expect`, fields that never varied and
tables too small to prove anything, so a pass tells you how blind it was. The
rules, the schema and the tests that pin them are in
[`MEMORY_LAYOUT.md`](MEMORY_LAYOUT.md) ("Checking a layout at run
time"). `trace_lookup.js` and the probe don't run the check. The shift probe
only sees a *uniform* move: an object header that grew or shrank, not a build in
which one field was reordered.
