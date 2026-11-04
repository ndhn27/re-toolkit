[← Back to README](../README.md)

# Adapting this template to your own target

This won't run against anything as-is — it's a worked example to copy the
*method* from. Rough order of operations (the details and the usual ways a
first guess goes wrong are in [`METHODOLOGY.md`](METHODOLOGY.md)):

1. **Get the binary + metadata.** Pull the IL2CPP binary (`UnityFramework`
   on iOS, `libil2cpp.so` on Android) and generate `dump.cs` / a symbol
   map for it with an IL2CPP dumper, then load both into Ghidra.
2. **Find your target function's RVA.** Locate the class/method you
   care about in `dump.cs`, find its `...$$unpack` (or whatever function
   you're hooking) in Ghidra's Symbol Table, and note its address with
   Image Base set to `0` - that's the RVA the agents and `--offset` take.
   (An RVA is not a *file offset*, and `retk relocate` works in
   file offsets - it also prints the RVA, but see [RVA vs file offset](../README.md#rva-vs-file-offset)
   before mixing the two.)
   `scripts/list_il2cpp_exports.js` can help locate `il2cpp_init` and other
   entry points if the binary is stripped.
3. **Work out the record layout.** Point `scripts/probe_record.js` at your RVA
   (`--offset probe=0x...`) to hexdump raw records, then read the layout by eye
   — field sizes, string encoding, and the object header size (don't assume the
   standard IL2CPP header size, it is a property of the build).
4. **Write it into your profile, not into this repo.** Copy
   `profile.example.json` to a profile outside git (`retk profile init NAME`, see [Profiles](PROFILES.md#profiles)), fill in
   the target, the RVAs and the confirmed layout (field name, offset, type,
   `key`). `retk profile layout <profile>` validates it and prints
   each record's listing. No rebuild is needed: the layout reaches the agents at
   run time. They are the same `Interceptor.attach` + `readRecord(ptr, layout)`
   pattern for any record; reuse `readRecord` / `readIl2CppString` /
   `waitForModule` / `createRecordStore` from `scripts/_lib.js` rather than
   re-copying them. Add an `expect` to every field whose values you actually
   looked at (`{"oneOf": [0, 1]}`, `{"min": 1}`, `{"nonEmpty": true}`): it is
   what lets the next run notice that the layout no longer matches the build.
5. **Run it.** `retk dump --profile <name>` (see [Usage](USAGE.md)), or
   attach manually with the Frida CLI.
6. **Carry offsets forward across updates.** `retk relocate` re-locates a known offset in the new
   build by instruction fingerprinting, instead of re-deriving it by hand in Ghidra every time. It takes file
   offsets and prints the file offset plus the **RVA** (`NEW RVA`, the number a profile takes); it handles
   AArch64 binaries only. Every candidate is graded HIGH / MEDIUM / LOW - a sanity check around a fingerprint,
   not proof. Modes, anchors and failure cases: [Relocating an offset](RELOCATE_AND_VERIFY.md#relocating-an-offset).
   With the new build's metadata dump the hook point can be looked up by `Class::Method` instead:
   [Looking things up by name](NAME_LOOKUP.md).
7. **Verify it by running it.** A byte match is still only a match. `--json
   relocate_new.json` writes every candidate (file offset, RVA, grade) and
   `retk verify --profile myapp --from-relocate
   relocate_new.json` hooks them in the running app and answers VERIFIED only
   when the hook fired and what it handed back is valid under the profile's
   layout - see [Verifying a relocated offset](RELOCATE_AND_VERIFY.md#verifying-a-relocated-offset).
