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
            records those drivers pull over RPC — generated, see "Record
            shapes" below.)
schema/     layouts.json: the ONE place a record's field offsets and types
            are written down — see "Record shapes" below.
legacy/     Earlier, superseded versions of dump_hd_quality_list.js, kept
            for reference — see docs/ITERATION_HISTORY.md
docs/       Struct layout notes and the debugging history
tests/      pytest unit tests for tools/relocate_offset.py (tiny in-memory
            AArch64 fixtures - no device or real binary needed), for
            tools/check_placeholders.py, and for the record-layout pipeline
            (schema/ -> scripts/_layouts.js, tools/records.py, docs/)
.githooks/  pre-commit hook wired to tools/check_placeholders.py - see
            "Keeping real offsets out of git" below
```

| Script | Purpose |
|---|---|
| `scripts/dump_hd_quality_list.js` | Dumps `ExampleNamespace.DeviceQualityAllowList`: which device names have HD render quality enabled. |
| `scripts/dump_recommend_config.js` | Dumps `ExampleNamespace.DeviceRecommendConfig`: the full table of graphics presets per device tier. |
| `scripts/dump_recommend_config_probe.js` | Generic raw-hex probe used to work out an unknown record layout by hand. |
| `scripts/dump_selection_logic.js` | Hooks `GetConfigMatchingDevicePattern` / `GetRecommendedQualityPreset` directly, to watch the live selection algorithm instead of just reading static tables. |
| `scripts/list_il2cpp_exports.js` | Lists `UnityFramework` exports/symbols — used to relocate `il2cpp_init` and other entry points in a build. Sends `{event: "scan-complete"}` when finished so `tools/list_exports.py` can detach as soon as the scan is done, instead of sleeping a fixed number of seconds. |
| `scripts/_lib.js` | Shared helpers (`readRecord`, `readIl2CppString`, `waitForModule`, `createRecordStore`) used by the agents above — not a standalone agent on its own. |
| `scripts/_layouts.js` | The record layouts the agents read with, **generated** from `schema/layouts.json` (`python tools/gen_layouts.py`) — don't edit by hand. |

## Adapting this template to your own target

This won't run against anything as-is — it's a worked example to copy the
*method* from. Rough order of operations:

1. **Get the binary + metadata.** Pull the IL2CPP binary (`UnityFramework`
   on iOS, `libil2cpp.so` on Android) and generate `dump.cs` / a symbol
   map for it with an IL2CPP dumper, then load both into Ghidra.
2. **Find your target function's RVA.** Locate the class/method you
   care about in `dump.cs`, find its `...$$unpack` (or whatever function
   you're hooking) in Ghidra's Symbol Table, and note its address with
   Image Base set to `0` - that's the RVA the agents and `--offset` take.
   (An RVA is not a *file offset*, and `tools/relocate_offset.py` works in
   file offsets - see "RVA vs file offset" below before mixing the two.)
   `scripts/list_il2cpp_exports.js` can help locate `il2cpp_init` and other
   entry points if the binary is stripped.
3. **Work out the record layout.** Point a copy of
   `scripts/dump_recommend_config_probe.js` at your offset to hexdump raw
   records, then read the layout by eye — field sizes, string encoding,
   and (per `docs/MEMORY_LAYOUT.md`) don't assume the standard IL2CPP
   object header size, it varies by build. `docs/ITERATION_HISTORY.md`
   walks through this process end to end, wrong guesses included.
4. **Write your hook.** Once the layout is confirmed, write it into
   `schema/layouts.json` (field name, offset, type) and run
   `python tools/gen_layouts.py`; then adapt
   `scripts/dump_hd_quality_list.js` / `dump_recommend_config.js` — same
   `Interceptor.attach` + `readRecord(ptr, <Record>Layout)` pattern, just
   with your own record. The agents never contain field offsets themselves.
   Reuse `readRecord` / `readIl2CppString` / `waitForModule` /
   `createRecordStore` from `scripts/_lib.js` rather than re-copying them.
5. **Build, then set your config and run.** Bundle the agents
   (`npm run build` — see "Building the agents" below), put your
   package/bundle id and RVA in `tools/config.py` (or pass them per run
   — see Usage below), then use the driver
   scripts (or attach manually with the Frida CLI — see Usage below).
6. **Carry offsets forward across updates.** When the app ships a new
   binary and offsets shift, `tools/relocate_offset.py` can re-locate a
   known offset in the new build via instruction fingerprinting, instead
   of re-deriving it by hand in Ghidra every time. It takes and prints
   *file* offsets, and says after each result whether that number can be
   used as the RVA as is (thin Mach-O) or has to be converted first (ELF,
   fat Mach-O). Each candidate is
   checked (alignment, inside an executable section, how the surrounding
   code compares to the old build) and reported with a HIGH/MEDIUM/LOW
   confidence - that is a sanity check around a byte fingerprint, not
   control-flow analysis, so verify the result once before trusting it.

## RVA vs file offset

"Offset" names two different numbers in this repo, and they are only
sometimes equal:

| | RVA | File offset |
|---|---|---|
| What it is | Address relative to the module's load address (a Ghidra address with Image Base = `0`); Frida hooks `module.base + RVA` | Byte position in the binary file on disk |
| Used by | `FRIDA_OFFSET` / `OFFSET_*` in `scripts/*.js`, `FRIDA_OFFSET` in `tools/config.py`, `--offset` / `$FRIDA_OFFSET`, `meta.offset` in exported dumps | `tools/relocate_offset.py`: takes them in, prints them out |

They coincide for code in a thin Mach-O slice such as the iOS
`UnityFramework` (its `__TEXT` segment starts at file offset 0). They do not
for a fat Mach-O (RVA = file offset minus the arch slice's offset, see `lipo
-detailed_info`) or an ELF such as Android's `libil2cpp.so` (per-segment
`p_offset` vs `p_vaddr`, see `readelf -lW`). Convert before handing a number
from one side to the other: `relocate_offset.py` prints a note after every
result saying which case it thinks it is, but it doesn't convert for you.

## Requirements

- A jailbroken iOS device or simulator running your target app, with
  `frida-server` running and reachable (scripts assume it's forwarded to
  `127.0.0.1:27042` — adjust `REMOTE_ADDR` in `tools/config.py`, or pass `--remote`, if yours
  differs). This template was built and tested against iOS
  (`UnityFramework`) only — see the platform note near the top for
  adapting it to Android.
- Node.js 18+ and npm, to bundle the agents in `scripts/` into `dist/` via
  `frida-compile` (see "Building the agents" below).
- Python 3.9+ with the packages in `requirements.txt`.
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
edit to `scripts/*.js` or `scripts/_lib.js`. If you changed
`schema/layouts.json`, run `python tools/gen_layouts.py` (or `npm run
gen:layouts`) first so `scripts/_layouts.js` is regenerated before the build.

## Usage

1. Build the agents (see "Building the agents" above) — re-run after any
   edit to `scripts/*.js` or `scripts/_lib.js`.
2. Set the target: put `TARGET` (your app's package/bundle id), `REMOTE_ADDR`
   and `FRIDA_OFFSET` (the RVA you found, see above) in `tools/config.py`
   as your defaults. For one-off runs — especially when trying several
   offsets in a row while working out a layout — you can skip editing the
   file and override any of them from the command line or the environment
   instead:

   | CLI flag | Env var | `config.py` | Notes |
   | --- | --- | --- | --- |
   | `--target ID` | `FRIDA_TARGET` | `TARGET` | package/bundle id |
   | `--remote HOST:PORT` | `FRIDA_REMOTE_ADDR` | `REMOTE_ADDR` | frida-server address |
   | `--offset HEX` | `FRIDA_OFFSET` | `FRIDA_OFFSET` | RVA of the hooked function; hex, `0x` optional (`ab68fc8` = `0xab68fc8`) |

   Precedence is CLI flag > environment variable > `config.py`. Each driver
   prints the resolved value and where it came from at startup, so a stale
   `FRIDA_OFFSET` exported in your shell can't quietly win without you
   seeing it. (`list_exports.py` takes `--target`/`--remote`/`--wait` — it has
   no offset. `--wait` is how long to wait for UnityFramework to load; the
   agent sends `scan-complete` when it is done, so a fast scan detaches
   immediately and a slow Unity boot can be given more time.)
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
     records_ab68fc8.json`. Keep the name matching `records*.json`: that's
     what `.gitignore` covers, and the export's `meta` holds the real target
     and offset (the driver prints a warning at startup if your `--out` isn't
     git-ignored); or
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
a real offset from the original investigation. Unlike the JS/TS files and
`tools/config.py`, `check_placeholders.py` does not scan the README, the
`tools/` docstrings, or `tests/` (see "Which files" in its own
docstring), so don't mistake its presence in those
files for something that's been placeholder-checked - it's just a
made-up number used consistently in usage examples and test data.

The placeholders described above (`com.example.unitygame`, `FRIDA_OFFSET =
0x0`, etc.) only stay placeholders if nobody forgets to reset them before
committing. Beyond the runtime `if (OFFSET === 0x0) throw ...` guards
already in `scripts/*.js` — which only catch it at *run* time, and only for
whoever runs it — `tools/check_placeholders.py` checks, *before* a real
value can land in git history:

- **Every JS/TS file in the repo** (not just `scripts/` and `legacy/`, so
  moving a file is no way around it): any number that looks like a code
  address (a literal of `0x10000` or more, in code, in a string, in a
  comment, in a table, however it's written), plus any `offset`/RVA-named
  constant (`FRIDA_OFFSET`, `OFFSET_GetFoo`, `HOOK_RVA`, ...) that isn't a
  zero placeholder. Struct-field offsets live in `schema/layouts.json` and
  the `scripts/_layouts.js` generated from it: `tools/gen_layouts.py`
  rejects any offset above `0x1000` in the schema, and a hand-written JS
  table is still allowed if it's named `*Offsets` and every entry is
  `0x1000` or less.
- **`tools/config.py`**: `TARGET` must be `"com.example.unitygame"` and
  `FRIDA_OFFSET` must be zero, however they're written (type hints,
  tuple-unpacking, line breaks, ...).

Some things are deliberately exempt (powers of two, masks like
`0xffffffff`, Mach-O/ELF magics). If a legitimate number of yours gets
blocked — say a `100000` ms timeout — write it as an expression
(`100 * 1000`) rather than asking for an exemption.

It runs in two places:

- **Locally**, as a pre-commit hook. Install once per clone (from the repo
  root):

  ```bash
  git config core.hooksPath .githooks
  ```

- **In CI**, via `.github/workflows/check-placeholders.yml`, which runs the
  same script on every push/PR — a backstop for a clone that never
  installed the hook, or a commit made with `--no-verify`. The same
  workflow also runs `pytest` (Python 3.9 and the latest 3.x, with Node
  installed so the layout tests that execute the agents run too — they fail
  rather than skip in CI) and a full `npm run build`, checking that the two RPC agents' bundles still contain
  the `const FRIDA_OFFSET = 0x0;` line the driver rewrites.

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
The validation step that runs on every raw byte match is covered too:
alignment, "is this match inside an executable section?" for thin/fat
Mach-O and ELF64 containers (built in memory by `tests/binfmt_fixtures.py`),
and the soft context checks that produce the HIGH/MEDIUM/LOW label.

`tests/` also covers smaller things, none needing capstone or Frida:
`test_check_placeholders.py` exercises the pre-commit/CI check from
"Keeping real offsets out of git" above against fixture files,
`test_layouts.py` checks the record-layout pipeline from "Record shapes"
below (it runs the real agents under Node with a faked Frida, so it wants
`node` on the PATH and skips itself without it), `test_terminology.py` keeps
"RVA" (the hook address) and "file offset" (what `relocate_offset.py` works
in) from being mixed up in comments and docs, `test_common.py` covers the
CLI/env/`config.py` precedence and the `FRIDA_OFFSET` injection, and
`test_run_hd_quality_dump.py` and `test_list_exports.py` pin the drivers'
spawn/resume/detach lifecycle (shared via `_common.spawn_agent`) against a
stubbed `frida` module.

## Record shapes

A record's layout — each field's name, offset, type and meaning — is written
down once, in [`schema/layouts.json`](schema/layouts.json). Everything else
that needs it is generated from that file by `python tools/gen_layouts.py`
(also `npm run gen:layouts`):

| Generated file | What it is |
|---|---|
| `scripts/_layouts.js` | The layout tables the agents read with (`readRecord(ptr, RecommendConfigRecordLayout)`), plus JSDoc `@typedef`s for the records they produce. |
| `tools/records.py` | The `TypedDict`s the Python drivers annotate with (`DeviceQualityRecord`, `RecommendConfigRecord`, and `SelectionResult`, the 5-field subset `dump_selection_logic.js` watches live). |
| `docs/MEMORY_LAYOUT.md` | The offset listings between its `GENERATED` markers; the prose around them is hand-written and doesn't repeat offsets. |

Because the agents never spell out an offset or a read width themselves,
there is nothing to keep in sync by hand — and `tests/test_layouts.py` covers
the remaining ways it can go wrong: a stale or hand-edited generated file, an
offset restated in an agent or in the docs' prose, an invalid layout
(misaligned, overlapping, unknown type), and — the part a field-name diff
can't see — the *types*. It runs `readRecord` and the real agents under Node
against a fake process image and compares every decoded field, including
sign, width and nullable strings, with an independent Python decoder, so a
reader that started treating a `u32` as an `int8` fails a test rather than
silently corrupting a dump. `records.py` remains plain annotations: nothing
runs mypy/pyright over it and RPC still hands the drivers plain `dict`s.

## Findings

See [`docs/MEMORY_LAYOUT.md`](docs/MEMORY_LAYOUT.md) for the confirmed
struct layouts, and [`docs/ITERATION_HISTORY.md`](docs/ITERATION_HISTORY.md)
for how they were worked out (kept because the debugging process is a
useful worked example on its own).

## License

MIT — see [`LICENSE`](LICENSE).
