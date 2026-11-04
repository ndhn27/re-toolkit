[← Back to README](../README.md)

# Looking things up by name

An RVA goes stale with every build. The IL2CPP runtime knows where each method
is, so an agent can ask it - by `Namespace.Class::Method` - instead of trusting
a Ghidra address, and fall back to the RVA only when it cannot. A profile opts
in with an optional `names` section (the example profile has one, with made-up
names):

```jsonc
"names": {
  "methods": {                          // an `offsets` key -> the method it is
    "table_a": "ExampleNamespace.ExampleTableA::Unpack/1",      // /1: the overload with 1 parameter
    "resolve_default": { "class": "ExampleNamespace.ExampleTableB", "method": "ResolveDefault",
                         "args": 0, "assembly": "Assembly-CSharp" }   // the object form can name the assembly
  },
  "fields": {                           // layout field -> the IL2CPP field it is
    "TableARecord": { "class": "ExampleNamespace.ExampleTableA", "map": { "id": "id", "name": "label" } }
  },
  "exports": { "il2cpp_class_from_name": "renamed_export" }     // only if the build renamed an IL2CPP export
}
```

**Methods.** Class -> method -> `MethodInfo` -> its first word is the method
pointer; minus the module's base that is the RVA, taken from the running build.
An overload the name does not pick (`Unpack` with two of them and no `/N`), a
class that exists in two assemblies, a method with no code pointer, a pointer
outside the module: each is an error, never a pick - the agent falls back
instead of guessing. The lookup needs the runtime to be initialised, so a
spawned app ("early") has `il2cpp_init` hooked and the names looked up in its
`onLeave`, before anything else runs; attaching to a running app ("late") asks
`il2cpp_domain_get()` at once. Nothing is called in the target before that.

**Fields.** For each `names.fields` entry the agent asks the runtime for the
field's offset (class -> `il2cpp_class_get_field_from_name` ->
`il2cpp_field_get_offset`) and compares it with the layout. That is not a
sample: the runtime states the offset, so one mismatch **fails the layout check**
(exit 3) whatever `--layout-tolerance` says, and a match is noted as confirmed
directly. A field the runtime could not be asked about is a note, never a verdict.
Instance fields only (a static field's offset is into the class's static storage).

**What happens when.** `--resolve MODE` (on `retk dump`; `retk profile params
--resolve MODE` for the agents that have no driver):

| | `auto` (default) | `names` | `rva` |
|---|---|---|---|
| name resolves | hooks the name's address | same | name never looked up |
| profile RVA differs | the name wins, and the run says the RVA is stale | same | the RVA |
| name does not resolve | falls back to the RVA, says why | **nothing is hooked** | the RVA |
| exports hidden or stripped | falls back to the RVA, says why | nothing is hooked | the RVA |
| no name for a key | the RVA | the RVA | the RVA |

`--offset KEY=HEX` is an explicit choice for that key: its name is not looked up.
A key with a name needs no RVA in the profile; without one there is nothing to
fall back to, and a failed lookup hooks nothing (the console says
`NOTHING WAS HOOKED`, and `retk dump` exits **4** after writing what it has).
Hidden exports are the usual reason for a fallback: `names.exports` maps an IL2CPP
function to the name the module really exports it as, when the build only renamed it.

`meta.offsets` in the export records the RVAs that were actually hooked (the
name's, when it differs from the profile's) and `meta.resolution` the evidence:
per hook point where it came from, the name's RVA, the profile's, whether they
agree, and why a fallback happened; per field, the layout's offset against the
runtime's.

**In `retk relocate`.** With the *new* build's metadata - the `dump.cs` or
`script.json` an IL2CPP dumper wrote for it, or a plain `NAME ADDRESS` symbol map
(`Namespace.Class$$Method 0x1a2b30`) - the hook point can be found by name
instead of by its bytes:

```bash
retk relocate OLD_BINARY 0xab68fc8 NEW_BINARY \
    --name ExampleNamespace.ExampleTableA::Unpack/1 --new-metadata dump_new.cs
retk relocate NEW_BINARY --name ExampleNamespace.ExampleTableA::Unpack/1 \
    --new-metadata dump_new.cs                       # no old build at all
```

The dump says where the method was compiled to; the tool places that RVA in the
binary (it must lie in a loadable segment, in executable code, 4-byte aligned on
AArch64) and prints the usual `NEW FILE OFFSET` / `NEW RVA`. A name finds a
function that was **rewritten**, which no fingerprint can; what it cannot prove
is that the dump is of the same build as the binary, so with an `OLD_BINARY` the
byte fingerprint still runs as the cross-check:

| the fingerprint | result |
|---|---|
| finds the same place | **HIGH** (the name also settles a fingerprint that alone found several look-alikes) |
| finds nothing | **MEDIUM** (rewritten - or the dump is of another build) |
| finds somewhere else | **both candidates, exit 1** - not an answer; `retk verify --from-relocate` runs them |
| no `OLD_BINARY` (name only) | **MEDIUM** (nothing to compare it with) |

A name the dump does not settle (absent, or two addresses) falls back to the byte
fingerprint when there is an `OLD_BINARY` and fails (exit 1) when there is not.
Against a binary that is not AArch64 only the name is used.

Limits, so they are not discovered the hard way: generic methods and classes are
not covered (a shared generic body has no single method pointer, and no dump format
names an instantiation); `MethodInfo`'s first word is read as the method pointer,
which every Unity version this toolkit has met satisfies; a nested class is
matched as `Outer.Inner` in a dump and walked with `il2cpp_class_get_nested_types`
at run time, which is the less-tested path. The runtime half is tested against a
small native library that exports the real IL2CPP signatures over a made-up
metadata model (`tests/native/fake_il2cpp.c`, run under real Frida) - not against
a real Unity player, which still needs one run on the real app.
