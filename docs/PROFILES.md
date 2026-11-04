[← Back to README](../README.md)

# Profiles and builds

## Profiles

A **profile** is one JSON file with everything specific to a real target —
[`profile.example.json`](../profile.example.json) is the annotated template:

```jsonc
{
  "target":  "com.example.unitygame",   // package/bundle id to spawn
  "remote":  "127.0.0.1:27042",         // frida-server address (optional)
  "module":  "UnityFramework",          // the IL2CPP module to hook in (required: this, or "platform", or --module / --platform)
  "platform": "ios",                    // optional: ios | android | windows = that platform's usual module name; `module` beats it
  "offsets": { "table_a": "0x0", ... }, // RVAs, Ghidra addresses with Image Base = 0
  "names":   { ... },                   // optional: the same hook points BY NAME - see "Looking things up by name"
  "layouts": { ... }                    // header size, String layout, records, subsets
}
```

Each agent asks for the offsets it needs by name (see the [agent table](AGENTS.md)) and
**refuses to run at `0`** (unless the profile also names that hook point, in which
case the name is looked up - see [Looking things up by name](NAME_LOOKUP.md)), so the template can't hook a wrong address; a
profile may hold offsets for several agents, the rest are ignored. `layouts`
must define the record and subset names the agents ask for — `TableARecord`,
`TableBRecord` and the `LookupResult` subset — but everything inside them is
yours: field names, offsets, types, `key` (which field(s) identify a record),
`headerSize`, the string layout and the descriptions.
`retk profile layout <profile>` validates a layout (alignment,
overlaps, a `key` naming a missing field, …) and prints it.

The file lives **outside this repo**, so it can't be committed by accident:
`--profile NAME` means `NAME.json` in the `profiles/` folder of your user data
directory, the standard one for your operating system (the `platformdirs`
package decides, for an app called `re-toolkit`):

| OS | data directory |
|---|---|
| Linux | `~/.local/share/re-toolkit` (`$XDG_DATA_HOME/re-toolkit` when set) |
| macOS | `~/Library/Application Support/re-toolkit` |
| Windows | `%LOCALAPPDATA%\re-toolkit` |

```bash
retk builds where           # prints the profiles folder on this machine
retk profile init myapp     # creates myapp.json there from the example (it never overwrites: --force does)
# edit it; `retk profile layout myapp` checks it; then: --profile myapp
```

Two environment variables move things: `$RE_DATA_DIR` the whole data directory
(CI, a shared machine, a USB stick) and `$RE_PROFILES_DIR` only the profiles
(it wins for profiles). A path (anything ending in `.json` or
containing a `/`) is used as it is. A profile in the repo's git-ignored
`profiles/` folder is read too, with a warning to move it, unless
`$RE_PROFILES_DIR` is set; one in the data directory always wins.

Two things are worth keeping next to the profile (in the same private
directory, not in this repo):

- The real class/method/field names, one per line, to feed
  `python tools/check_identifiers.py --add-file names.txt`. Only SHA-256
  digests of the normalized names go into `tools/identifier_denylist.txt`, so
  the list can be committed without publishing what is on it.
- Your own investigation notes (what you tried, wrong guesses, confirmed
  findings). [`METHODOLOGY.md`](METHODOLOGY.md) is the generic version of that; the
  target-specific one doesn't belong here.

## Builds the toolkit has seen

`retk dump` remembers what a verified run learned about each **build** of the
IL2CPP module, so the next run on the same build skips the lookup and a rebuilt
app is looked up again by itself - nothing to switch, nothing to re-enter.

- **A build is named by the module's own identity**, read by the agent from the
  headers of the loaded module: the **Mach-O `LC_UUID`** (iOS/macOS; what
  `dwarfdump --uuid` prints) or the ELF **GNU build-id** (Android/Linux; what
  `readelf -n` prints). A rebuild changes it; a re-sign or a re-package does not.
  `retk builds key libil2cpp.so` prints the same value from a file.
  A module with neither (a PE such as `GameAssembly.dll`, a stripped ELF) has no
  build to key on: the run behaves as it always did and says so.
- **Run 1 on a build the cache has not seen:** the addresses are found as
  before (names asked of the IL2CPP runtime, else the profile's RVA - see
  [Looking things up by name](NAME_LOOKUP.md)). If the dump then **passes its layout check**,
  they are recorded for that build.
- **Run 2 on the same build:** the agent is handed them and hooks them as they
  are - no lookup, and no waiting for the runtime to come up. The console says
  `build ...: seen before - table_a taken from the build cache`.
- **A new build:** nothing is recorded for it, so it is looked up afresh - by
  name, if the profile has names. Without names, the profile's RVAs are used
  and the console warns that they belong to whichever build they were written
  for.

What it never does: record a dump that did not verify (the layout check failed,
was skipped with `--no-layout-check`, or the run was stopped); replace an
address you gave (`--offset KEY=HEX`, `--resolve names|rva` switch the cache
off for that run); or believe an address outside the module. `--build-cache
auto|rescan|off` (default `auto`) is the only switch: `rescan` ignores what is
known but records the result, `off` neither reads nor writes.

Records are JSON files under the data directory (`builds/<target>/<kind>_<id>.json`;
`retk builds list` shows them), one per build:

```json
{
  "schema_version": 1,
  "build":    {"kind": "gnu-build-id", "id": "8e9fd827446c..."},
  "target":   "com.example.game",
  "module":   "libil2cpp.so",
  "offsets":  {"table_a": "0x1c2a4f0"},
  "sources":  {"table_a": "name"},
  "recorded": {"at": "2026-11-02T10:11:12+00:00", "tool": "run_dump.py", "profile": "game",
               "records": 41, "layout_check": "ok"}
}
```

`schema_version` is how the format can change later without breaking what is
already on disk: an older file is migrated when read (`MIGRATIONS` in
`src/retk/buildcache.py`); a file written by a **newer** toolkit is left alone -
not read, never overwritten - and the run proceeds as if the build were
unknown; a damaged file, or one that does not describe the build its name says,
is ignored with a note. Files are written atomically, and one build holds the
keys of every agent that ran on it. Delete a file to forget a build.
