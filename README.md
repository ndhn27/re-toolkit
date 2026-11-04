<div align="center">

# 🔬 re-toolkit

**Observe-only Frida tooling for inspecting how Unity + IL2CPP apps load their configuration tables.**

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![Frida 17.25.1](https://img.shields.io/badge/frida-17.25.1-E4002B)
![Node 20+](https://img.shields.io/badge/node-20%2B-339933?logo=nodedotjs&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

[Quick start](#quick-start) · [Commands](#commands) · [Documentation](#documentation) · [Development](#development)

</div>

`retk` hooks a target app's own `...$$unpack` and lookup functions at runtime, reads the records they fill in, and exports them as JSON. It is **observe-only, but it is still runtime instrumentation**. It never modifies the binary on disk, and its hooks never change the app's arguments, return values or data. It does run inside the target process: Frida injects an agent, `Interceptor.attach` rewrites the code at each hook site in memory, the agents use scratch allocations there, and name lookup and snapshots call the runtime's own IL2CPP API (which can have side effects such as class initialisation).

- **Dump** - spawn or attach, collect a table, export JSON; or snapshot an app that is already running
- **Relocate** - find a hook point again after an app update (AArch64), by bytes or by `Class::Method` name
- **Verify** - trial-hook candidate offsets in the live app and see which ones the app really calls
- **Diff** - semantic diff of two dumps, with schema-drift detection
- **Self-checking** - a layout check tells you when what was read no longer fits the profile
- **Private by design** - no target value lives in this repo; profiles live in your user data directory

> **This is a generic template.** The package id, classes, lookup functions, layouts and every offset in [`profile.example.json`](profile.example.json) are placeholders (offsets are `0x0`, layouts are synthetic). Nothing here is taken from, or usable as-is against, any particular app.

> ⚠️ **Scope.** This is runtime reverse-engineering of a third-party app's client, for research and education. It may conflict with the app's Terms of Service - check those, and the laws where you live, before using or distributing anything built from it. It only reads configuration data. Please don't use it to build or distribute tooling aimed at a specific named app or its userbase.

## Quick start

You need Python 3.9+, Node.js 20+ and npm (at install time only), a device or simulator running your target with `frida-server` **17.25.1** reachable (default `127.0.0.1:27042`), and Ghidra or similar to find offsets. Only iOS has been exercised so far; `retk relocate` is AArch64-only. Full list: [docs/INSTALL.md](docs/INSTALL.md).

```bash
git clone https://github.com/ndhn27/re-toolkit && cd re-toolkit
pip install .                    # also builds the Frida agents (Node 20+ and npm on PATH)
retk --help
```

Then, on your own target:

```bash
retk builds where                # where profiles live on this machine
retk profile init myapp          # creates myapp.json from the example, outside git
# edit it: target, RVAs, your confirmed layout
retk profile layout myapp        # validate it and print each record's listing
retk dump --profile myapp        # spawn the app, use it, press Enter to export records.json
```

## Adapting it to your own target

1. **Get the binary and metadata** - the IL2CPP binary plus `dump.cs` / a symbol map from an IL2CPP dumper, loaded in Ghidra.
2. **Find the function's RVA** - the `...$$unpack` you want to hook, with Image Base set to `0`.
3. **Work out the record layout** - hexdump raw records with `scripts/probe_record.js`; check the header size first.
4. **Write it into your profile** - never into this repo; add an `expect` to every field you have actually looked at.
5. **Run it** - `retk dump --profile myapp`.

Step-by-step: [docs/ADAPTING.md](docs/ADAPTING.md) · Common first-guess mistakes: [docs/METHODOLOGY.md](docs/METHODOLOGY.md)

## After an app update

```bash
retk relocate OLD_BINARY 0x... NEW_BINARY --json relocate_new.json   # where did the hook point go?
retk verify --profile myapp --from-relocate relocate_new.json        # does the app call it, and does the layout still fit?
retk dump --profile myapp --out records_new.json                     # dump again
retk diff records_old.json records_new.json                          # what changed - and is it still the same shape?
```

Details: [Relocate and verify](docs/RELOCATE_AND_VERIFY.md) · [Find hook points by name](docs/NAME_LOOKUP.md) · [Layout check](docs/LAYOUT_CHECK.md) · [Diff](docs/DIFF.md)

## Commands

One entry point, one subcommand per tool; each has its own `--help` (`retk dump --help`). `python -m retk ...` is the same program.

| Command | What it does | See |
|---|---|---|
| `retk dump` | spawn (or `--attach` to) the app, run a bundled agent, export its records to JSON; `--snapshot` reads a running app | [Usage](docs/USAGE.md), [Snapshot](docs/SNAPSHOT.md) |
| `retk relocate` | find a hook point again in a new build (AArch64), by bytes or by `Class::Method` name | [Relocate](docs/RELOCATE_AND_VERIFY.md#relocating-an-offset), [By name](docs/NAME_LOOKUP.md) |
| `retk verify` | trial-hook candidate offsets in the running app and say which are VERIFIED | [Verify](docs/RELOCATE_AND_VERIFY.md#verifying-a-relocated-offset) |
| `retk diff` | semantic diff of two dumps, with schema-drift detection | [Diff](docs/DIFF.md) |
| `retk exports` | list the IL2CPP module's exports/symbols | [Usage](docs/USAGE.md) |
| `retk profile layout\|params\|init` | validate and print a profile's layouts, the JSON an agent receives, or create a profile from the example | [Profiles](docs/PROFILES.md) |
| `retk builds where\|key\|list` | where retk keeps profiles and builds, a binary's build id, the builds recorded | [Build cache](docs/PROFILES.md#builds-the-toolkit-has-seen) |

`tools/check_identifiers.py` is deliberately not a `retk` command: it guards this repository's tree, which an installed copy does not have. See [Keeping real values out of git](docs/KEEPING_VALUES_OUT_OF_GIT.md).

## RVA vs file offset

"Offset" names two different numbers in this repo, and they are only sometimes equal:

| | RVA | File offset |
|---|---|---|
| What it is | Address relative to the module's load address (a Ghidra address with Image Base = `0`); Frida hooks `module.base + RVA` | Byte position in the binary file on disk |
| Used by | a profile's `offsets`, `--offset KEY=HEX`, `meta.offsets` in exported dumps, `retk verify --candidate` | `retk relocate`: takes them in, prints them out (and the RVA beside them) |

They coincide only for code in a thin Mach-O slice such as the iOS `UnityFramework`; a fat Mach-O or an ELF such as Android's `libil2cpp.so` differs. `retk relocate` prints both (`NEW FILE OFFSET`, `NEW RVA`), but its *input* is a file offset, so convert a Ghidra address of the old build before handing it in. How the conversion works: [docs/RELOCATE_AND_VERIFY.md](docs/RELOCATE_AND_VERIFY.md#file-offset-to-rva-conversion).

## Documentation

| Doc | What's inside |
|---|---|
| [INSTALL](docs/INSTALL.md) | Requirements, install, the Frida 17 pin, building the agents, platform notes |
| [ADAPTING](docs/ADAPTING.md) | The 7-step walkthrough for a real target |
| [METHODOLOGY](docs/METHODOLOGY.md) | Working out an unknown record layout; the usual ways a first guess goes wrong |
| [PROFILES](docs/PROFILES.md) | Profile format and location; the per-build cache |
| [USAGE](docs/USAGE.md) | Drivers, flags, the export format, attaching with the Frida CLI |
| [SNAPSHOT](docs/SNAPSHOT.md) | Reading a table out of an app that is already running |
| [NAME_LOOKUP](docs/NAME_LOOKUP.md) | Finding hook points by `Namespace.Class::Method` instead of by RVA |
| [RELOCATE_AND_VERIFY](docs/RELOCATE_AND_VERIFY.md) | Re-locating offsets in a new build, then proving them by running them |
| [LAYOUT_CHECK](docs/LAYOUT_CHECK.md) | How `retk dump` judges that a layout still fits the build |
| [DIFF](docs/DIFF.md) | Comparing two dumps; schema-drift findings |
| [MEMORY_LAYOUT](docs/MEMORY_LAYOUT.md) | Struct layouts of the example records; run-time layout-check rules |
| [AGENTS](docs/AGENTS.md) | Every Frida agent script and the full repository layout |
| [KEEPING_VALUES_OUT_OF_GIT](docs/KEEPING_VALUES_OUT_OF_GIT.md) | The name checker, the pre-commit hook, what CI guards |
| [TESTING](docs/TESTING.md) | What each test file covers |
| [CHANGELOG](CHANGELOG.md) | What changed in each release |

## Repository layout

```
src/retk/             Python package behind the `retk` command: drivers, profiles, relocator, diff, build cache
scripts/              Frida agent sources (.js); `npm run build` bundles them into dist/
dist/                 Bundled agents (build output, git-ignored) - what Frida and retk actually load
docs/                 Guides and reference notes (table above)
tests/                pytest suite - no device or real binary needed
tools/                Name checker (check_identifiers.py) and its digest list
profile.example.json  Template profile: made-up target, every offset 0x0, synthetic layouts
CHANGELOG.md          Release notes, newest first
```

Per-script details: [docs/AGENTS.md](docs/AGENTS.md).

## Development

```bash
pip install -r requirements-dev.txt   # runtime requirements + pytest + ruff
npm ci && npm run build               # dist/ - what the tests and a checkout load
pytest
ruff check .                          # the lint CI runs
git config core.hooksPath .githooks   # once per clone: the name-check pre-commit hook
```

Real target values (offsets, package ids, layouts, names) stay in your private profile, never in the tree - see [docs/PROFILES.md](docs/PROFILES.md) and [docs/KEEPING_VALUES_OUT_OF_GIT.md](docs/KEEPING_VALUES_OUT_OF_GIT.md). Test coverage: [docs/TESTING.md](docs/TESTING.md).

## License

MIT - see [LICENSE](LICENSE).
