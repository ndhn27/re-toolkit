[← Back to README](../README.md)

# Comparing two builds

`retk diff` compares two exports of the same table - dumped from two builds - at
the level of **records**, and says whether the two still have the same **shape**:

```bash
retk diff records_old.json records_new.json
retk diff records_old.json records_new.json --profile myapp --record TableARecord
retk diff records_old.json records_new.json --key kind,id --json diff_records_1.json
```

Records are matched by **key**, never by position: `--key`, else the profile's layout (`--profile`),
else a field - or pair of fields - unique in both dumps and shared by the most records (it says
"inferred"). The diff lists the records **added**, **removed** and **changed** (field by field,
old -> new). A field a dump could not read (`_unreadable`) is never a change - it is counted as
compared only in part, because "the string became unreadable" is a statement about memory, not
about the table. A key that does not identify a record is reported, not silently diffed.

**Schema drift** is the part a text diff cannot give. A table that "changed" in every record, or
whose strings turned to junk, is usually not a table that changed but a layout that no longer
fits its build. Status **3** (like a failed layout check) says the record diff is to be read with
suspicion; the findings say why:

| finding | meaning |
|---|---|
| `field_removed` / `field_added` | the records do not have the same fields (a layout changed between dumps) |
| `type_changed`, `null_rate` | a field's values changed kind / became mostly null |
| `garbled_strings` | strings turned into non-printable junk - the look of a wrong offset |
| `domain_shift` | a field with a few distinct values now holds mostly other ones |
| `field_moved` | the old values of field A are now in field B: columns swapped or a layout shifted |
| `all_fields_changed` | every field changed in nearly every shared record |
| `suspect_dump` | a dump's own `meta` says its layout check failed or its layout gate stopped it |

and these, worth a look but not drift: `systematic_change` (one field changed almost everywhere),
`magnitude_shift`, `new_values` (a new enum member), `count_shift`, `low_key_overlap`. The thresholds
are constants at the top of `src/retk/diff_records.py` with what each means, and `tests/test_diff_records.py`
pins them - including the near-misses that must **not** raise a finding (a ratio over four
records, an unchanged or constant column). `meta` is compared too: offsets, module, and whether a
dump was hooked or read by `--snapshot`.

Exit status: **0** the dumps hold the same records, **1** they differ with the same shape, **3** schema
drift, **2** bad input. `--json PATH` writes everything (every record of every category); it holds
real data, so the repo's `.gitignore` covers `diff_records*.json`, and the tool warns if you name it
something that is not ignored.
