# Changelog

All notable changes to this project are documented in this file, newest release first.

Versions are `MAJOR.MINOR.PATCH`. A release is a git tag plus a bump of `__version__` in
`src/retk/__init__.py`, the one place `pyproject.toml` reads the version from.

## [1.1.0] - 2026-11-05

A maintenance release: documentation accuracy, one portability fix in the test suite, and release
housekeeping. Nothing changes in the `retk` command line, the Frida agents, the profile format, the
export format or any runtime behaviour.

### Changed

- **README: "read-only" is now "observe-only", and the instrumentation is described as what it is.**
  The 1.0.0 README said nothing patches the binary or writes into the process. That was too strong:
  `retk` runs inside the target process. Frida injects an agent, `Interceptor.attach` rewrites the code
  at each hook site in memory, the agents use scratch allocations there, and name lookup and snapshots
  call the runtime's own IL2CPP API through `NativeFunction` (which can have side effects such as
  class initialisation). The README now says exactly that, and keeps the two claims that do hold: the
  binary on disk is never modified, and the hooks never change the app's arguments, return values or
  data (no `Interceptor.replace`, no `retval.replace`, no argument rewriting anywhere in `scripts/`).
  The one-line summary at the top changes from "Read-only Frida tooling" to "Observe-only Frida
  tooling" to match.
- **README: fewer emoji.** Removed from the navigation bar, from the feature list and from the
  Documentation table (where every row carried one). The title and the scope warning keep theirs.
- **`retk --version` now reports `1.1.0`.** In 1.0.0 it printed the development placeholder
  `3.1.0.dev0`, which did not match the release number. The package version, the git tag and this file
  now agree.
- `CHANGELOG.md` is listed in the README's Documentation table and repository layout and in
  `docs/AGENTS.md`, is included in source distributions (`MANIFEST.in`), and is linked as the
  `Changelog` project URL in `pyproject.toml`.
- `docs/TESTING.md` describes the new test below.

### Fixed

- **Stale workflow name in `tools/check_identifiers.py`.** Its docstring said the whole-tree name check
  runs from a workflow called `check-placeholders.yml`. No such workflow exists; the check is the
  `names` job in `.github/workflows/ci.yml`. The docstring now says so.
- **`tests/test_cli.py::test_a_typo_is_refused_with_the_choices` no longer depends on how argparse
  quotes choices.** The test required the text `'dump'` in the error message. CPython has printed the
  list of valid choices quoted (`'dump'`) in most releases and bare (`dump`) in some patch releases, so
  a test that guards the CLI's behaviour could turn red on a supported Python for a reason that has
  nothing to do with `retk`. It now asserts that the command is refused with status 2, that the message
  says "invalid choice", and that every command name appears in the list of choices, quoted or not. It
  is also stricter than before: the old assertion checked one command, the new one checks all of them.

### Added

- `CHANGELOG.md` (this file).
- `tests/test_check_identifiers.py::test_every_workflow_file_the_tree_names_exists`: fails when any
  file in the tree refers to a `.github/workflows/<name>.yml` that is not there, so a reference like
  the one fixed above cannot drift silently again.

## [1.0.0] - 2026-11-05

First public release.

### Added

- **The `retk` command**, one entry point with one subcommand per tool (`python -m retk ...` is the same
  program):
  - `retk dump` spawns the app, or attaches to it with `--attach`, runs a bundled agent and exports the
    records it collected to JSON; `--snapshot` reads a table out of an app that is already running.
  - `retk relocate` finds a hook point again in a new build of the binary (AArch64 only), by bytes or
    by `Class::Method` name.
  - `retk verify` trial-hooks candidate offsets in the running app and reports which ones the app really
    calls.
  - `retk diff` compares two dumps semantically and reports schema drift.
  - `retk exports` lists the IL2CPP module's exports and symbols.
  - `retk profile layout|params|init` validates and prints a profile's layouts, shows the JSON an agent
    receives, or creates a profile from the example.
  - `retk builds where|key|list` shows where profiles and builds are kept, a binary's build id, and the
    builds recorded so far.
- **Seven Frida agents** in `scripts/` (`dump_table_a`, `dump_table_b`, `probe_record`, `trace_lookup`,
  `list_il2cpp_exports`, `verify_hook`, `snapshot_records`, with shared helpers in the `_*.js` files),
  bundled by `npm run build` (frida-compile) into `dist/`. A built wheel carries the bundles inside the
  package.
- **Layout self-check:** `retk dump` judges whether what it read still fits the profile's layout and says
  so when it does not.
- **Profiles outside the repository:** real target values (offsets, package ids, layouts, names) live in a
  profile in the user data directory, never in the tree. `profile.example.json` is a template with a
  made-up target, every offset `0x0` and synthetic layouts. A per-build cache records the builds the
  toolkit has seen.
- **Name guard:** `tools/check_identifiers.py` fails when a name taken from a real target appears
  anywhere in the tree. It compares SHA-256 digests of normalized names, so the committed list does not
  publish the names, and it runs from `.githooks/pre-commit` and from CI.
- **Documentation** in `docs/`: INSTALL, ADAPTING, METHODOLOGY, PROFILES, USAGE, SNAPSHOT, NAME_LOOKUP,
  RELOCATE_AND_VERIFY, LAYOUT_CHECK, DIFF, MEMORY_LAYOUT, AGENTS, KEEPING_VALUES_OUT_OF_GIT and TESTING.
- **A pytest suite that needs no device and no real binary.** It runs the real agents under Node against
  a fake process image, runs them under real Frida against a small native program built with the
  runner's compiler (`tests/test_frida_real.py`), and tests the relocator on tiny in-memory AArch64
  fixtures.
- **GitHub Actions CI** with four jobs: `names` (the name guard), `tests` (ruff and pytest on the oldest
  supported Python, 3.9, and the latest 3.x), `build` (every agent bundles, exposes `init` and holds no
  address) and `package` (builds the wheel, installs it into an empty virtualenv on Ubuntu and Windows,
  and runs the installed `retk`).
- **Packaging:** `setup.py` builds the agents while the wheel is built and puts them, together with
  `profile.example.json`, into the package. Frida is pinned exactly (`frida==17.25.1`) so the client
  always matches the `frida-server` the README tells you to put on the device.

### Fixed

- CI jobs that need Python 3.9 run on `ubuntu-24.04`: `actions/setup-python` has no Python 3.9 build for
  Ubuntu 26.04, which is what `ubuntu-latest` now is.
- Documentation cross-references point into `docs/`.

### Known limitations

- Only iOS has been exercised so far.
- `retk relocate` supports AArch64 only.
- The Frida agents need `frida-server` 17.25.1 reachable on the device or simulator.

[1.1.0]: https://github.com/ndhn27/re-toolkit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ndhn27/re-toolkit/releases/tag/v1.0.0
