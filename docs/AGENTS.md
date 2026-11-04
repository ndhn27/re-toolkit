[← Back to README](../README.md)

# Agents and repository layout

```
profile.example.json  The profile template: made-up target, every offset 0x0,
                      synthetic layouts. Copy it, fill it in, keep the copy
                      outside git — see PROFILES.md.
scripts/    Frida agent sources (.js) — attach to a running iOS app process
            and hook into the IL2CPP module. _lib.js and _canary.js hold
            helpers shared between them, not standalone agents. Bundle with
            `npm run build` before use — see INSTALL.md.
dist/       Bundled agents (build output of `npm run build`, git-ignored) —
            this is what Frida and retk actually load, not scripts/
            directly. A built wheel carries them inside the package.
src/retk/   The Python package behind the `retk` command (see the README command table): the drivers that spawn the app via frida and drive the
            bundled agents (run_dump.py, list_exports.py, verify_offset.py),
            the profile loader/validator (profiles.py, layouts.py), the layout
            self-check verdict (layout_check.py), the offset relocator
            (relocate_offset.py), the Class::Method name specs and
            metadata-dump lookup behind NAME_LOOKUP.md
            (il2cpp_names.py), the semantic diff of two dumps
            (diff_records.py), the verdict on a trial hook (verification.py),
            the per-build cache (buildcache.py) and cli.py, the dispatcher.
tools/      The repo's own scripts, not part of the package: the name checker
            (check_identifiers.py, stdlib only) and its digest list.
setup.py    The wheel build: runs `npm run build` and puts the bundles and
            profile.example.json into the wheel — see INSTALL.md.
docs/       Guides and reference notes (this folder), indexed in the README
CHANGELOG.md  Release notes, newest first.
tests/      pytest suite: the drivers, profiles and layouts, the real agents
            run under Node against a fake process image, and
            retk relocate (tiny in-memory AArch64 fixtures — no
            device or real binary needed), and the `retk` command itself
.githooks/  pre-commit hook for the name checker
```

| Script | Purpose |
|---|---|
| `scripts/dump_table_a.js` | Dumps `ExampleNamespace.ExampleTableA`: a flat table keyed by `id`. Needs `offsets.table_a`. |
| `scripts/dump_table_b.js` | Dumps `ExampleNamespace.ExampleTableB`: a table whose `id` is only unique within a `kind`, so it is keyed on both. Needs `offsets.table_b`. |
| `scripts/probe_record.js` | Generic raw-hex probe used to work out an unknown record layout by hand. Needs `offsets.probe`. Prints only: run it with `frida -P` (see [Usage](USAGE.md)), not `retk dump`. |
| `scripts/trace_lookup.js` | Hooks `LookupByPattern` / `ResolveDefault` directly, to watch the live selection algorithm instead of just reading static tables. Needs `offsets.lookup_by_pattern` and `offsets.resolve_default`. Prints only: run it with `frida -P` (see [Usage](USAGE.md)), not `retk dump`. |
| `scripts/list_il2cpp_exports.js` | Lists the IL2CPP module's exports/symbols — used to relocate `il2cpp_init` and other entry points in a build. Sends `{event: "scan-complete"}` when finished so `retk exports` can detach as soon as the scan is done, instead of sleeping a fixed number of seconds. Needs only `module`. |
| `scripts/verify_hook.js` | Trial-hooks candidate RVAs (what `retk relocate` found in a new build) and checks the records each one hands back against the profile's layout, so a candidate can be called *verified*, not just "the bytes matched". Stores nothing; `retk verify` asks it for counts and judges them. Needs `verify.record` and `verify.candidates` (the driver builds them) plus the profile's `module` and layouts. See [Verifying a relocated offset](RELOCATE_AND_VERIFY.md#verifying-a-relocated-offset). |
| `scripts/snapshot_records.js` | Reads the table out of an app that is **already running** - from a static field that holds it and/or the live instances of its class - instead of hooking the unpack and waiting for a call that will not come again. Serves the same rpc exports as the dump agents, so `retk dump --attach --snapshot` exports it unchanged. Needs `snapshot.record` (the driver builds it from `names.snapshot`) plus the profile's `module` and layouts. See [Snapshot](SNAPSHOT.md). |
| `scripts/_lib.js` | Shared helpers (`parseParams`, `readRecord`, `readIl2CppString`, `waitForModule`, `createRecordStore`) used by the agents above — not a standalone agent on its own. |
| `scripts/_resolve.js` | Finds what an agent hooks **by name** (`Namespace.Class::Method`), asking the IL2CPP runtime for it, with the profile's RVA as the fallback; also reads the offsets the runtime gives the layout's fields. Not an agent; see [Looking things up by name](NAME_LOOKUP.md). |
| `scripts/_snapshot.js` | What `snapshot_records.js` does: walk a static array / `List<T>`, scan the heap for the class pointer, keep the candidates that fit the layout. Not an agent either. |
| `scripts/_canary.js` | The layout self-check the dump agents (and `verify_hook.js`) use: counts, per record read, how often the data contradicted the profile's layout, probes where the fields would be if the whole layout had shifted, and sends an early snapshot after the first N records (`createCanary`, `healthExport`). Not an agent either; see [Checking a layout against the build](LAYOUT_CHECK.md). |

The agents never spell out an offset, a package id **or a field name**: each
asks for the offsets it needs by name and refuses to hook at `0`, reads a
record through the layout it was given and logs it as JSON. That is what lets
a profile supply a real target's values without any agent source changing.
