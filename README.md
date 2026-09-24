# IL2CPP Render-Quality Research (Generic Template)

Frida-based tooling and methodology notes for inspecting how a Unity +
IL2CPP mobile game (`com.example.unitygame` — replace with your own
target's package name) decides which devices are eligible for HD render
quality and which graphics preset gets recommended for a given device.
Everything here is **read-only instrumentation** — the scripts hook the
target app's own unpack/lookup functions at runtime and read memory;
nothing patches the binary or writes back into the process.

This is a **generalized template**, distilled from a real investigation
against one specific app. The package name, the memory offsets found in
that build, and the top-level namespace have been replaced with
placeholders (`com.example.unitygame`, `ExampleNamespace`,
`FRIDA_OFFSET = 0x0`, etc.) so this can be reused as a starting point for
research on **your own** target, rather than being usable as-is against
any particular app.

**Note:** the specific class/method/field names below the namespace
(`DeviceQualityAllowList`, `DeviceRecommendConfig`,
`GetConfigMatchingDevicePattern`, `GetRecommendedQualityPreset`,
`szName_ByteArray`, and the struct layout in `docs/MEMORY_LAYOUT.md`)
have **not** been genericized — they're left as-is from the worked
example so the methodology notes in `docs/ITERATION_HISTORY.md` stay
internally consistent. Don't assume they're safe boilerplate: re-derive
and rename the class/method/field names, in addition to the offsets, for
whatever app you're actually studying, using Ghidra or similar, following
the methodology in `docs/ITERATION_HISTORY.md`.

> **Note on platform:** this template was derived from an iOS
> (`UnityFramework`) investigation — the scripts as-is only look for a
> module named `UnityFramework`. Adapting to Android/`libil2cpp.so` is
> possible in principle (IL2CPP's internals are largely the same across
> platforms) but hasn't been tested here; you'd need to point
> `waitForModule()` in `scripts/_lib.js` at `libil2cpp.so` instead and
> re-derive the record layouts against the Android binary from scratch.

> **Note on scope:** this is reverse-engineering of a third-party mobile
> game's client at runtime, done for research/educational purposes. It
> likely conflicts with the target app's Terms of Service — check those,
> and the laws that apply where you live, before using or distributing
> anything built from this. Nothing here modifies gameplay-affecting
> behavior; it only reads device-tier/graphics-quality configuration data.
> Please don't use this template to build or distribute tooling aimed at
> a specific named app or its userbase — keep it at the level of a
> general Frida/IL2CPP methodology example.

## What's here

```
scripts/    Frida agent sources (.js) — attach to a running iOS app process
            and hook into UnityFramework. _lib.js holds helpers shared
            between them, not a standalone agent. Bundle with
            `npm run build` before use — see "Building the agents" below.
dist/       Bundled agents (build output of `npm run build`, git-ignored) —
            this is what Frida and tools/ actually load, not scripts/
            directly.
tools/      Python drivers that spawn/attach via frida-tools and drive the
            bundled agents in dist/
            (config.py holds the default target/offset; override per run
            with --target/--remote/--offset or env vars — not by editing
            the drivers. records.py holds the TypedDict schemas for the
            records those drivers pull over RPC — see "Record shapes"
            below.)
legacy/     Earlier, superseded versions of dump_hd_quality_list.js, kept
            for reference — see docs/ITERATION_HISTORY.md
docs/       Struct layout notes and the debugging history
tests/      pytest unit tests for tools/relocate_offset.py (tiny in-memory
            AArch64 fixtures - no device or real binary needed) and for
            tools/check_placeholders.py
.githooks/  pre-commit hook wired to tools/check_placeholders.py - see
            "Keeping real offsets out of git" below
```

| Script | Purpose |
|---|---|
| `scripts/dump_hd_quality_list.js` | Dumps `ExampleNamespace.DeviceQualityAllowList`: which device names have HD render quality enabled. |
| `scripts/dump_recommend_config.js` | Dumps `ExampleNamespace.DeviceRecommendConfig`: the full table of graphics presets per device tier. |
| `scripts/dump_recommend_config_probe.js` | Generic raw-hex probe used to work out an unknown record layout by hand. |
| `scripts/dump_selection_logic.js` | Hooks `GetConfigMatchingDevicePattern` / `GetRecommendedQualityPreset` directly, to watch the live selection algorithm instead of just reading static tables. |
| `scripts/list_il2cpp_exports.js` | Lists `UnityFramework` exports/symbols — used to relocate `il2cpp_init` and other entry points in a build. |
| `scripts/_lib.js` | Shared helpers (`readIl2CppString`, `waitForModule`, `createRecordStore`) used by the agents above — not a standalone agent on its own. |

## Adapting this template to your own target

This won't run against anything as-is — it's a worked example to copy the
*method* from. Rough order of operations:

1. **Get the binary + metadata.** Pull the IL2CPP binary (`UnityFramework`
   on iOS, `libil2cpp.so` on Android) and generate `dump.cs` / a symbol
   map for it with an IL2CPP dumper, then load both into Ghidra.
2. **Find your target function's offset.** Locate the class/method you
   care about in `dump.cs`, find its `...$$unpack` (or whatever function
   you're hooking) in Ghidra's Symbol Table, and note its file offset with
   Image Base set to `0`. `scripts/list_il2cpp_exports.js` can help locate
   `il2cpp_init` and other entry points if the binary is stripped.
3. **Work out the record layout.** Point a copy of
   `scripts/dump_recommend_config_probe.js` at your offset to hexdump raw
   records, then read the layout by eye — field sizes, string encoding,
   and (per `docs/MEMORY_LAYOUT.md`) don't assume the standard IL2CPP
   object header size, it varies by build. `docs/ITERATION_HISTORY.md`
   walks through this process end to end, wrong guesses included.
4. **Write your hook.** Once the layout is confirmed, adapt
   `scripts/dump_hd_quality_list.js` / `dump_recommend_config.js` — same
   `Interceptor.attach` + field-offset pattern, just with your own offsets
   and field names. Reuse `readIl2CppString` / `waitForModule` /
   `createRecordStore` from `scripts/_lib.js` rather than re-copying them.
5. **Build, then set your config and run.** Bundle the agents
   (`npm run build` — see "Building the agents" below), put your
   package/bundle id and offset in `tools/config.py` (or pass them per run
   — see Usage below), then use the driver
   scripts (or attach manually with the Frida CLI — see Usage below).
6. **Carry offsets forward across updates.** When the app ships a new
   binary and offsets shift, `tools/relocate_offset.py` can re-locate a
   known offset in the new build via instruction fingerprinting, instead
   of re-deriving it by hand in Ghidra every time.

## Requirements

- A jailbroken iOS device or simulator running your target app, with
  `frida-server` running and reachable (scripts assume it's forwarded to
  `127.0.0.1:27042` — adjust `REMOTE_ADDR` in `tools/config.py`, or pass `--remote`, if yours
  differs). This template was built and tested against iOS
  (`UnityFramework`) only — see the platform note near the top for
  adapting it to Android.
- Node.js 18+ and npm, to bundle the agents in `scripts/` into `dist/` via
  `frida-compile` (see "Building the agents" below).
- Python 3.8+ with the packages in `requirements.txt`.
- The Frida CLI (`frida`, `frida-ps`, etc.) if you want to attach manually
  instead of via the provided Python drivers.
- Ghidra (or similar) with the IL2CPP binary + `dump.cs` loaded, to find
  function offsets for new builds — `tools/relocate_offset.py` can then
  carry a known offset forward from one build to the next without
  re-opening Ghidra every time.

```bash
pip install -r requirements.txt
npm install
```

## Building the agents

`scripts/*.js` import shared helpers from `scripts/_lib.js` as ES modules
(see the "What's here" table above), so they need bundling into a single
self-contained file before Frida — or the Python drivers in `tools/` — can
load them:

```bash
npm run build
```

This writes one bundled file per agent to `dist/` (e.g.
`dist/dump_hd_quality_list.js`) — point Frida or the drivers in `tools/` at
that, not at the files in `scripts/` directly. Re-run `npm run build` (or
e.g. `npm run watch:hd-quality-list` for just that one agent) after any
edit to `scripts/*.js` or `scripts/_lib.js`.

## Usage

1. Build the agents (see "Building the agents" above) — re-run after any
   edit to `scripts/*.js` or `scripts/_lib.js`.
2. Set the target: put `TARGET` (your app's package/bundle id), `REMOTE_ADDR`
   and `FRIDA_OFFSET` (the offset you found, see above) in `tools/config.py`
   as your defaults. For one-off runs — especially when trying several
   offsets in a row while working out a layout — you can skip editing the
   file and override any of them from the command line or the environment
   instead:

   | CLI flag | Env var | `config.py` | Notes |
   | --- | --- | --- | --- |
   | `--target ID` | `FRIDA_TARGET` | `TARGET` | package/bundle id |
   | `--remote HOST:PORT` | `FRIDA_REMOTE_ADDR` | `REMOTE_ADDR` | frida-server address |
   | `--offset HEX` | `FRIDA_OFFSET` | `FRIDA_OFFSET` | hex, `0x` optional (`ab68fc8` = `0xab68fc8`) |

   Precedence is CLI flag > environment variable > `config.py`. Each driver
   prints the resolved value and where it came from at startup, so a stale
   `FRIDA_OFFSET` exported in your shell can't quietly win without you
   seeing it. (`list_exports.py` takes `--target`/`--remote` only — it has
   no offset.)
3. Either:
   - Run the matching driver in `tools/` (e.g. `python run_hd_quality_dump.py
     --offset 0xab68fc8`, from inside the `tools/` directory), which spawns
     the app, loads the bundled agent from `dist/` — injecting the offset
     into the agent's `FRIDA_OFFSET` constant automatically — and lets you
     export the collected table to JSON by
     pressing Enter. The export is wrapped as `{"meta": {...}, "records":
     [...]}`, with `meta` recording the target, agent, offset, and
     timestamp used for that dump, so a `records.json` from one run can't
     get silently mixed up with one from a different build/offset later.
     `--agent PATH` picks which bundled agent to load (default
     `../dist/dump_hd_quality_list.js`) and `--out PATH` where the JSON goes
     (default `records.json`) — give each attempt its own `--out` when
     probing several offsets, otherwise the next run overwrites the last
     dump. Example: `python run_hd_quality_dump.py --offset ab68fc8 --out
     records_ab68fc8.json`; or
   - Attach manually with the Frida CLI, having set `FRIDA_OFFSET` directly
     in the script's own `const` line before building instead:
     `frida -R -f com.example.unitygame -l dist/dump_hd_quality_list.js`
4. Play through to the point where the iOS app loads the relevant data
   (usually the graphics settings screen or app start) and watch the
   console output.

(See step 6 of "Adapting this template" above for carrying an offset
forward when the app updates.)

## Keeping real offsets out of git

**Note:** `0xab68fc8`, wherever you see it in this README, in the
docstrings/usage examples of `tools/_common.py`, `tools/relocate_offset.py`,
and `tools/run_hd_quality_dump.py`, and in the fixtures under `tests/`, is
the same fictional example value reused for illustration only — it is not
a real offset from the original investigation. Unlike `scripts/*.js` and
`tools/config.py`, `check_placeholders.py` does not scan the README, the
`tools/` docstrings, or `tests/` (see "Checks exactly what README.md tells
you to edit" in its own docstring), so don't mistake its presence in those
files for something that's been placeholder-checked - it's just a
made-up number used consistently in usage examples and test data.

The placeholders described above (`com.example.unitygame`, `FRIDA_OFFSET =
0x0`, etc.) only stay placeholders if nobody forgets to reset them before
committing. Beyond the runtime `if (OFFSET === 0x0) throw ...` guards
already in `scripts/*.js` — which only catch it at *run* time, and only for
whoever runs it — `tools/check_placeholders.py` checks the same two things
(`scripts/*.js` / `legacy/*.js` offset constants, and `tools/config.py`'s
`TARGET` / `FRIDA_OFFSET`) *before* a real value can land in git history:

- **Locally**, as a pre-commit hook. Install once per clone (from the repo
  root):

  ```bash
  git config core.hooksPath .githooks
  ```

- **In CI**, via `.github/workflows/check-placeholders.yml`, which runs the
  same script on every push/PR — a backstop for a clone that never
  installed the hook, or a commit made with `--no-verify`.

Both call `tools/check_placeholders.py` directly, so there's one source of
truth; see that file's docstring for exactly what it checks (and, just as
importantly, what it doesn't — a renamed class/namespace like
`ExampleNamespace` isn't caught, since there's no fixed placeholder string
to diff it against).

## Tests

`tools/relocate_offset.py` is the trickiest logic in the repo (backward
disassembly + fingerprint matching), so it has unit tests in `tests/`. They
build tiny AArch64 byte fixtures in memory - no device, no Frida and no real
`UnityFramework` binary needed:

```bash
pip install -r requirements-dev.txt   # the tests only need capstone + pytest
pytest
```

What's covered: which instructions count as PC-relative (`is_pc_relative`),
how `build_fingerprint` picks the safe run in front of the offset (barrier
instructions, undecodable words, `--min-instrs`, `--lookback`, start/end of
file) and how `find_new_offset` / `main` behave with 0, 1 and several matches.

`tests/` also covers two smaller things, both dependency-free (no capstone
needed): `test_check_placeholders.py` exercises the pre-commit/CI check
from "Keeping real offsets out of git" above against fixture files, and
`test_records_schema.py` diffs the JSDoc/`TypedDict` record shapes from
"Record shapes" below against each other.

## Record shapes

Both "dump the whole table" agents (`dump_hd_quality_list.js`,
`dump_recommend_config.js`) hand back plain JS objects over RPC, and the
Python drivers in `tools/` receive them as plain `dict`s in turn — nothing
enforces a shape on either side at runtime. For a reader trying to figure
out what fields to expect without digging through `docs/MEMORY_LAYOUT.md`,
each record's shape is documented as a JSDoc `@typedef` right next to
where it's built:

| Record | JSDoc typedef | Python `TypedDict` |
|---|---|---|
| `ExampleNamespace.DeviceQualityAllowList` entry | `DeviceQualityRecord` in `scripts/dump_hd_quality_list.js` | `DeviceQualityRecord` in `tools/records.py` |
| `ExampleNamespace.DeviceRecommendConfig` entry | `RecommendConfigRecord` in `scripts/dump_recommend_config.js` | `RecommendConfigRecord` in `tools/records.py` |
| 5-field subset of the above, from the live selection hooks | `SelectionResult` in `scripts/dump_selection_logic.js` | *(none — see `records.py`'s docstring)* |

These are documentation, not enforcement — this project has no
TS/`checkJs` build step and nothing runs mypy/pyright over `records.py` —
but `tests/test_records_schema.py` does diff the JS `@typedef` fields
against the matching Python `TypedDict` on every test run, so the two
sides can't silently drift apart the way a comment easily could.

## Findings

See [`docs/MEMORY_LAYOUT.md`](docs/MEMORY_LAYOUT.md) for the confirmed
struct layouts, and [`docs/ITERATION_HISTORY.md`](docs/ITERATION_HISTORY.md)
for how they were worked out (kept because the debugging process is a
useful worked example on its own).

## License

MIT — see [`LICENSE`](LICENSE).
