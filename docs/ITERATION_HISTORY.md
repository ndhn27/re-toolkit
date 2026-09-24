# Iteration history

The `legacy/` folder keeps the earlier versions of
`dump_hd_quality_list.js` for reference — the debugging process is a decent
worked example of reverse-engineering an unfamiliar IL2CPP record layout by
hooking a native function and reading memory around the observed pointer.
Short version of what happened at each step:

1. **v1** — First guess at the record layout, based purely on the class's
   declared member order (from static analysis) and assuming a standard
   16-byte IL2CPP object header. Printed a hexdump of the first 5 records
   for manual verification.

2. **v2** — `+0x10` (the guessed name pointer) was consistently `NULL`.
   Hypothesized that `+0x18` was the real pointer instead, and that
   the class's declared `szName_ByteArray` / `szName` fields might be
   adjacent.
   Tried reading both `+0x10` and `+0x18` under both a `byte[]`
   interpretation and a `System.String` interpretation, printing all four
   results side by side to compare by eye.

3. **v3** — Realized the hexdump rows had been miscounted: the field with
   real string data is at `+0x20`, not `+0x18`. It turned out IL2CPP
   wasn't reordering fields at all — every field, including the
   single-byte `enabled` flag, simply occupies a full 8-byte slot, which
   matches the class's declared member order exactly.

4. **v4** — Multiple different `id`s were producing the *same* string
   length repeatedly, suggesting either shared/interned strings or (more
   likely) a wrong length-field offset within `System.String` itself.
   Stopped guessing offsets and instead dumped raw hex at each *new*
   `namePtr` value (deduplicated) to read the actual `String` layout by
   eye.

5. **v5 / current** (`scripts/dump_hd_quality_list.js`) — Confirmed the
   root cause: this build uses an 8-byte IL2CPP object header everywhere
   (just `klass`, no separate `monitor` word) instead of the standard
   16-byte header. Once that was accounted for, both the record layout and
   the `System.String` layout resolved correctly. See
   [`MEMORY_LAYOUT.md`](./MEMORY_LAYOUT.md) for the final, confirmed
   layouts.

The same 8-byte-header finding was then reused directly when reading
`DeviceRecommendConfig` (`dump_recommend_config.js`), which is why that
script didn't need its own multi-version debugging cycle — it started from
`dump_recommend_config_probe.js`, a generic raw-hex-dump probe reused from
the same technique.
