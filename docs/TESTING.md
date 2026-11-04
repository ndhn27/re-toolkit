[← Back to README](../README.md)

# Tests

```bash
pip install -r requirements-dev.txt   # runtime requirements + pytest + ruff
pytest
ruff check .                          # the lint CI runs (rules chosen in pyproject.toml)
```

No device and no real binary are needed. Frida is used for real in exactly one
file (`test_frida_real.py`, below); everywhere else it is faked:

- `test_layouts.py` — layout validation, and the real agents run under Node
  with a faked Frida against a fake process image (it wants `node` on the PATH
  and skips itself without it). Every decoded field — sign, width, nullable
  strings — is compared with an independent Python decoder, so a reader that
  started treating a `u32` as an `int8` fails a test rather than silently
  corrupting a dump. It also pins the contract: the agents hook exactly the
  RVAs the profile gives, take the module, string layout and `key` from it,
  refuse an offset of `0`, a missing layout or a missing `module` (no platform
  default; `--platform` is a name you give, not one it guesses), warn about a module
  that never loads, and contain no value themselves.
- `test_cli.py`, `test_resources.py`, `test_setup_hook.py` — the `retk` command and its
  packaging: `retk --help` lists every command and does not load frida or capstone, a
  command forwards its line and exit status to its tool (and explains a missing
  dependency instead of a traceback), every command has a tool with `main(argv, prog)`
  and answers `--help`; where the agent bundles and the example profile are found
  (checkout, installed package, `$RETK_AGENTS_DIR`), `--agent` as a path or a name, what is
  said when a bundle is missing; and the wheel build hook (which bundles it expects, when
  `dist/` is current, no npm → a failure that names the way out, a stale `build/lib` never
  riding into a wheel). `stub_import.py` is the helper the driver tests use to import a
  driver against a stub frida. The real install - a wheel in an empty environment - is
  the CI `package` job.
- `test_profiles.py`, `test_common.py` — profile loading and validation, how the
  command line overrides it, the parameters an agent receives, and the
  spawn → attach → load → `init` → resume → detach lifecycle (a failure before
  resume kills the app rather than leaving it frozen).
- `test_buildid.py`, `test_build_cache_agent.py`, `test_buildcache.py` — the build
  cache (see [Builds the toolkit has seen](PROFILES.md#builds-the-toolkit-has-seen)): the Mach-O UUID / GNU build-id read from
  a file (Python) and from a loaded module (the agent, under Node) agree on the same
  bytes and give nothing for damaged ones; the agent hooks a cached address, ignores
  it for an unseen or unreadable build, for `names`/`rva` mode and outside the
  module, and refuses a malformed `cache`; the JSON records (one per build, merged,
  atomic, migrated by `schema_version`, a newer one never touched, a damaged one
  ignored), the per-OS data directories, and `retk dump` end to end across two
  runs and a rebuilt app, including everything that must NOT be recorded.
- `test_module_lookup.py` — where the IL2CPP module's name comes from and where it is
  looked up. `resolve_module()` is the one function that picks it (`--module`,
  `--platform`, the profile's `module`, its `platform`; an error, never a default), the
  platform names are typed in one table (`PLATFORM_MODULES`) that the agents' hint copy
  must equal, and `fridaModules()` in `scripts/_lib.js` is the only code that calls
  Frida's module APIs - so a Frida with a different module API is a one-function port.
- `test_run_dump.py`, `test_list_exports.py` — the two drivers end to end
  against a stubbed `frida` module, including the layout verdict (exit status 3,
  `meta.layout_check`, `--no-layout-check`, `--layout-tolerance`).
- `test_frida_real.py` — the agents under **real Frida**, end to end, which the
  faked-Frida tests above cannot check. It compiles a small native program and
  library (`tests/native/`) with `cc`, builds the real `scripts/*.js` with
  Frida's own compiler (`frida.Compiler`, no npm needed), spawns the program
  through the repo's own `spawn_agent()` and reads the result over RPC. It
  checks that `Interceptor.attach` fires on the profile's RVA with the record in
  `args[0]`; that `retval` is the whole 64-bit register, so `unpackFailed()`'s
  "low 32 bits" rule holds with garbage in the upper half; that every field type
  and a UTF-16 string decode from real memory at an address above 4 GiB; that
  `waitForModule()` waits for a library loaded later; that unreadable strings
  come out as `null` + `_unreadable`; and what `retk dump` sees from a real
  script (`require_dump_agent`, `collect_unreadable`). It runs on the machine
  that runs the tests (Linux, x86-64 or AArch64), **not on the phone**: AArch64
  `x0`/`w0` and the iOS/Android runtime still need a run against the real app.
  It also hooks the native function through `verify_hook.js` and checks that the
  records it hands back are called VERIFIED, and that records which are not of the
  layout are called REJECTED. Its own `onLeave` is held to the same
  64-bit rule: calls returning garbage in the upper half (success and failure), `-1` as
  an int and a plain failure are counted by the low 32 bits alone, every enter has its
  leave, and a candidate whose every return fails is NOT EXERCISED rather than judged;
  a candidate in writable data or far past the module is refused by what the real
  process reports for that address, while the real function beside it is still hooked. And it runs the name lookup against a native library
  with a small IL2CPP of its own (`tests/native/fake_il2cpp.c`): found through
  `il2cpp_init`'s `onLeave` when spawned and straight away when attached late, a
  stale RVA losing to the name, every unresolvable name falling back, hidden and
  renamed exports (`names.exports`), and the runtime's field offsets failing a
  contradicted layout. And the snapshot agent against the same library: a static List /
  array / single record, the heap scan finding live instances (and rejecting the ones that
  break the layout), the heap as the fallback, hidden exports, asked before the runtime is
  up and asked again.
  It skips off Linux, without a compiler, or where the sandbox forbids ptrace;
  with `$CI` set a missing `frida`/compiler/`nm` fails instead of skipping, and with
  `$REQUIRE_REAL_FRIDA` set (the workflow does) so does a runner that forbids ptrace, so a
  green CI run means Frida really hooked the compiled program. CI runs it against the
  pinned Frida 17, on the scripts compiled by `frida.Compiler` and on the `dist/` bundles
  `npm run build` writes (`$REQUIRE_DIST`, which the workflow sets, makes a missing bundle
  fail rather than skip).
- `test_frida_version.py` — the Frida pin: exact in `requirements.txt`, the installed
  Frida is that one (its major always, the release under `$CI`), `frida-tools` admits it,
  `frida-compile` bundles with the same major, and no agent calls an API Frida 17 removed.
- `test_il2cpp_names.py`, `test_names_driver.py`, `test_names_agent.py`,
  `test_relocate_by_name.py` — looking things up by name. The `Class::Method`
  grammar and the three metadata formats (an ambiguous name is an error, never a
  pick); the profile's `names` section, `--resolve`, the `--offset` override and how
  `retk dump` reports where each hook point came from (exit 4 when one ended with
  no address); `layout_check.py` judging the runtime's field offsets; the real
  `_resolve.js` under Node against a made-up runtime (name resolves / is ambiguous /
  is stale in the profile, runtime up now / later / unavailable, hidden exports,
  fields) and the real agents on a module that exports nothing; and
  `retk relocate --name`: RVA -> file offset in every container, name and bytes
  agreeing / disagreeing / the function rewritten, name-only, every way a name can
  fail to fit the binary, and the usage errors.
- `test_diff_records.py` — `retk diff`: matching by key rather than position, an
  unreadable field never a change, the key inferred / from the profile, every schema-drift
  finding made from data that has exactly that sign - and the near-misses that must not raise
  it - the exit statuses and the report.
- `test_snapshot_driver.py`, `test_build_scripts.py` — the snapshot mode's Python side:
  `names.snapshot`, `attach_agent` (never resumes or kills, always detaches), the polling and
  what `retk dump --attach --snapshot` prints and writes (an empty snapshot writes nothing,
  exit 5); and that every agent in `scripts/` is in `package.json`'s build.
- `test_unreadable.py` — a read error never passes for data: the agents export
  an unreadable string as `null` plus `_unreadable`, the layout check still counts
  the original failure, the driver reports those records in `meta` and on the
  console (including a few bad strings *under* the tolerance, the case where nothing
  in the file would otherwise tell them from data). Also: `retk dump`
  refuses an agent that collects nothing before the app is resumed, and
  `retk profile params` takes `--offset` / `--module` / `--platform`.
- `test_canary.py`, `test_layout_check.py` — the layout self-check. The real dump
  agents run under Node against a fake process image whose layout is right, moved
  by 8 bytes, zeroed, or has a wrong header or key, and what they count is judged
  by the real `retk/layout_check.py`; the judge's thresholds (including the exact
  boundary of `--layout-tolerance`) and the blind spots are pinned on purpose, so
  a pass can't quietly start meaning more than it does.
- `test_layout_drift.py` — the shift probe and the early gate: the real agent run
  under Node against an image whose layout is right, moved by +8 / -8 / +24, moved
  by something that is not a uniform shift, zeroed, or has a bad class word; what
  `layout_check.measure_drift` and `judge_gate` make of the counts (a header that
  grew is named, a non-uniform move and a layout with nothing to measure are not
  blamed on a shift, a bad class word is not dressed up as drift), and the gate in
  `retk dump` end to end (`stop` writes `records.suspect.json` and exits 3, `warn`
  carries on, a passing gate is recorded, `--layout-gate 0` and `--no-layout-check`
  turn it off).
- `test_relocate_rva_json.py` — `retk relocate`'s RVA line and `--json`: thin
  and fat Mach-O (per arm64 slice) and ELF64 conversions, pinned against hand-computed
  addresses, an unconvertible container, and the report's shape.
- `test_verify_hook.py`, `test_verification.py`, `test_verify_offset.py` — the
  dynamic verification. The real `verify_hook.js` runs under Node (a hook that is
  entered but never returns, failed returns, refusals: unaligned on arm64, beyond
  the module, not executable, `attach` that throws, one refused candidate not
  stopping the others); `verification.py` turns counts into verdicts (what
  *verified* may mean, `WEAK`, ambiguity, crashed vs ended); `retk verify` is
  driven end to end against a stubbed `frida` (candidates from a relocate report
  or the command line, duplicates, the agent check before the app resumes, exit
  statuses, `--json`).
- `test_relocate_offset.py` — `retk relocate`, the trickiest logic in
  the repo (backward disassembly + fingerprint matching): which instructions
  count as PC-relative, how the fingerprint is built, how `find_new_offset`
  behaves with 0, 1 and several matches, and the validation run on every raw
  match (alignment, "is this inside an executable section?" for thin/fat
  Mach-O and ELF64 containers built in memory by `tests/binfmt_fixtures.py`, and
  the soft context checks behind the HIGH/MEDIUM/LOW label).
- `test_relocate_function_entry.py` — the same tool for a hook point at a function
  *entry*: the operand wildcards (`bl`/`adrp`/branch offsets, the lo12 that goes
  with an `adrp`), the forward fingerprint and its masked search, `--mode auto`,
  and end-to-end runs on a 300-function synthetic build (`tests/synth_image.py`)
  where the neighbours change, get reordered, or a function is inserted in front
  — the cases where fingerprinting the previous function's tail gives the
  wrong function.
- `test_relocate_anchors.py` — the anchors that vote: the body windows and call-site
  windows (and which wildcards they inherit), how each is found in the new build and
  what it points at, and the rules that turn votes into a grade (a conflict -> LOW, a
  moved window -> MEDIUM, call sites never nominate, votes never raise). Its
  `TestFiveScenarioRegression` replays five situations - nothing changed, the neighbour's tail edited, the target rewritten, a
  function inserted in front, two neighbours swapped - with the anchors on, code-only
  and off, and the class after it swaps in a fingerprint of the code in front of the entry to show those
  same five checks fail on it (the wrong function, with no alarm) and that the votes
  still turn two of those wrong answers into LOW.
- `test_relocate_architecture.py` — the AArch64-only guard: x86-64 / 32-bit ARM
  ELF, Mach-O without an arm64 slice and non-ARM64 PE files are refused, for
  either binary, with the reason; every AArch64 container still passes.
- `test_check_identifiers.py` — the name check, with made-up names (no real name
  appears in the tests), and a guard that every workflow file the tree refers to
  exists in `.github/workflows/`.
- `test_terminology.py` — keeps "RVA" (the hook address) and "file offset" (what
  `retk relocate` works in) from being mixed up in comments and docs.
