[← Back to README](../README.md)

# Snapshot

`retk dump` normally spawns the app, hooks its unpack function and waits for the
app to call it. If you attach *after* the app has unpacked everything, that call
never comes again and the dump stays empty. `--snapshot` reads the table out of the
running app instead: no hook, no waiting, no restart.

```bash
retk dump --profile myapp --attach TheGame --snapshot      # a process name or a pid
retk dump --profile myapp --attach 4242 --snapshot TableBRecord   # when the profile has several
```

The app is never spawned, resumed or killed (it is attached to, and detached from at the
end), and the export is the same `records.json` a hooked dump writes - the layout check
runs on it, and `retk diff` compares it with one - plus `meta.snapshot`, which says
how the table was found. The profile says where it lives (`names.snapshot`, the example
profile has one):

```jsonc
"names": {
  "snapshot": {
    "TableARecord": {
      "static": { "class": "ExampleNamespace.ExampleTableB", "field": "all", "container": "list" },
      "heap": true                      // or { "class": "...", "max": 100000, "budget_ms": 60000 }
    }
  }
}
```

**`static`** names a static field that holds the table: `container` says what it holds - a
single record (`object`), an `array` of them, or a `System.Collections.Generic.List<T>`
(`list`: its `_items` and `_size` are looked up through the runtime, so only the entries in
use are read). The pointers are exact, so the records are taken as they are and every one is
shown to the layout canary: a layout that no longer fits fails the layout check like any
dump, instead of being filtered away. Dictionaries are not walked (their entry layout depends
on the key type), nor are lists of value types.

**`heap`** lists the *live instances* of a class: the heap is scanned for the class pointer
at `+0` of an object. That finds every object of the class the GC has not collected yet -
reachable or not - plus the odd piece of memory that merely holds the class pointer, so each
candidate is read against the layout and kept only if it breaks none of its checks (no
unreadable string, no violated `expect`). A layout with few `expect`s rejects little: the
status says how many candidates there were and how many fit, and that is the number to read.
The scan covers private read-write memory, 16 MiB at a time, and stops at `max` candidates or
`budget_ms` and says so. It assumes the collector does not move objects (Boehm, as in every
Unity version this toolkit has met).

`static` is tried first; `heap` when it is absent, unresolved or empty. A snapshot that finds
**no record** writes nothing and exits **5**, so an empty result can never replace a good file.

Things worth knowing before you run it on something you care about:

- Both ways go through the IL2CPP API, so they need the exports (or `names.exports` for a
  renamed set - see [Looking things up by name](NAME_LOOKUP.md)); without them the snapshot fails and says so.
- `il2cpp_field_static_get_value` may **initialise the class** (run its type initializer) if
  the app has not used it yet. That is the one place this toolkit can make the app execute
  code of its own; attach after the table has been built and it never happens.
- The snapshot is a moment, not a stream: a table the app keeps changing is read as it was
  while the scan ran. Take it twice and `retk diff` the two.
- Tested against a native library that exports the real IL2CPP signatures over a made-up
  metadata model (`tests/native/fake_il2cpp.c`), under real Frida - static list / array /
  object, the heap scan, the fallbacks, attaching late and asking before the runtime is up. Not
  against a real Unity player.
