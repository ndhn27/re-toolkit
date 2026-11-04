[← Back to README](../README.md)

# Usage

1. Build the agents (see [Building the agents](INSTALL.md#building-the-agents)) and write your profile.
2. Run the driver. It reads the profile, prints every resolved value and where
   it came from, spawns the app, loads the bundled agent, hands it the profile's
   values through `rpc.exports.init()` *before* the app is resumed, and lets you
   export the collected table to JSON by pressing Enter:

   ```bash
   retk dump --profile myapp                       # dump_table_a.js
   retk dump --profile myapp --agent dump_table_b.js
   retk exports --profile myapp                   # needs only target/remote/module
   ```

   Which driver takes which agent: `retk dump` is for the two agents that
   *collect* a table (`dump_table_a.js`, `dump_table_b.js`), `retk exports`
   for `list_il2cpp_exports.js`. `probe_record.js` and `trace_lookup.js` only
   print, so there is nothing for a driver to export: attach them with the Frida
   CLI (step 3). Pointed at one of them, `retk dump` says so right after
   loading it, kills the still-suspended app and exits non-zero, rather than
   letting you use the app and fail when you press Enter.

   Any value can be overridden for one run, which is what you want while
   probing offsets — no need to edit the profile between attempts:

   | Flag | Overrides | Notes |
   | --- | --- | --- |
   | `--target ID` | `target` | package/bundle id |
   | `--remote HOST:PORT` | `remote` | frida-server address |
   | `--module NAME` | `module` | the IL2CPP module (`UnityFramework` on iOS, `libil2cpp.so` on Android, `GameAssembly.dll` on Windows); there is no default |
   | `--platform P` | `platform` | `ios`, `android` or `windows`: stands for that platform's usual module name, so `--platform android` = `--module libil2cpp.so`; `--module` beats it. Said, never guessed - with neither (and no `module` / `platform` in the profile) the driver refuses |
   | `--offset KEY=HEX` | `offsets.KEY` | repeatable; hex, `0x` optional (`table_a=ab68fc8` = `table_a=0xab68fc8`); not on `retk exports`, which hooks no address; beats the profile's `names` entry for that key |
   | `--attach PROCESS` | attach to a running app | a name or a pid; the app is never spawned, resumed or killed; only `retk dump` |
   | `--snapshot [RECORD]` | read the table out of the running app | needs `--attach`; see [Snapshot](SNAPSHOT.md); exit 5 when it finds nothing; `--snapshot-timeout SECONDS` (default 120) |
   | `--resolve MODE` | how a hook point is found | `auto` (default: the profile's `names` first, the RVA as the fallback), `names`, `rva`; `retk dump` only - see [Looking things up by name](NAME_LOOKUP.md) |

   (`0xab68fc8`, wherever it appears in these docs, in the docstrings of
   `src/retk/` and in the fixtures under `tests/`, is one fictional value reused
   for illustration — not an offset from any investigation.) With no profile at
   all, `--target` and `--module` (or `--platform`) are enough for `retk exports`. If the agent refuses
   its parameters (an offset that is `0`, a record the profile doesn't define),
   the driver kills the still-suspended app and prints which key is missing;
   `retk exports` also takes `--wait SEC` — how long to wait for the module
   to load (the agent sends `scan-complete` when it is done, so a fast scan
   detaches immediately). A module that is still missing after 20 s is called
   out by the agent, with the loaded modules that look like an IL2CPP runtime -
   a wrong `module` otherwise looks exactly like an app that loads late.

   `retk dump` also judges the layout while the table is still being collected
   (`--layout-gate N`, `--on-drift stop|warn`; [Checking a layout against the build](LAYOUT_CHECK.md)): when the first 16 records already contradict the layout it
   stops the run instead of letting you play on until the Enter key.

   The export is wrapped as `{"meta": {...}, "records": [...]}`, with `meta`
   recording the profile, target, module, agent, the non-zero offsets (the RVAs
   that were hooked), where each came from (`resolution`), the
   layout check's verdict (`layout_check`), the early gate's (`layout_gate`,
   `suspect`) and a timestamp,
   so a `records.json` from one run can't get silently mixed up with one from a
   different build/offset later. `--out PATH` picks where the JSON goes (default
   `records.json`) — give each attempt its own `--out` when probing several
   offsets, otherwise the next run overwrites the last dump. Keep the name
   matching `records*.json`: that's what `.gitignore` covers, and the export's
   `meta` holds the real target and offsets (the driver warns at startup if your
   `--out` isn't git-ignored).

   **A string the agent could not read** (an unmapped pointer, an absurd length)
   is `null` in its record, and the record gains `_unreadable: ["field", ...]`
   naming it: a read error can never pass for a value. A record with nothing
   wrong has no `_unreadable` key. The driver prints those records by key and
   `meta.unreadable_count` / `meta.unreadable_records` list them (the first 100;
   the count is exact), whether or not the layout check passed or ran: a stray
   one is under the check's tolerance on purpose, so the check alone would not
   have told you which records to distrust. `null` by itself is not proof of a
   failure (an unset string field reads as `null` too); `_unreadable` is.
3. Or attach with the Frida CLI, passing the same values as `init()`
   parameters; `retk profile params` prints them as JSON. This is also how
   `probe_record.js` and `trace_lookup.js` are run, and `retk profile params`
   takes the same `--offset KEY=HEX` (repeatable) and `--module NAME` /
   `--platform P` overrides as the drivers, so an RVA can be tried without editing the profile:

   ```bash
   frida -R -f com.example.unitygame -l dist/dump_table_a.js \
         -P "$(retk profile params myapp)"

   frida -R -f com.example.unitygame -l dist/probe_record.js \
         -P "$(retk profile params myapp --offset probe=0xab68fc8)"

   frida -R -f com.example.unitygame -l dist/trace_lookup.js \
         -P "$(retk profile params myapp \
               --offset lookup_by_pattern=0xab68fc8 --offset resolve_default=0xab68fd0)"
   ```

   The Frida CLI ignores an `init` that throws, so a refusing agent logs
   `[!] init failed: ...` to the console instead — look for that line if
   nothing is hooked.
4. Use the app until it loads the relevant data (usually at app start or when
   the screen that needs it opens) and watch the console output.

(See step 6 of [Adapting this template](ADAPTING.md) for carrying an offset
forward when the app updates.)
