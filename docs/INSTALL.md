[← Back to README](../README.md)

# Installing, requirements and building

## Requirements

- A jailbroken iOS device or simulator running your target app, with
  `frida-server` running and reachable (scripts assume it's forwarded to
  `127.0.0.1:27042` — set `remote` in your profile, or pass `--remote`, if
  yours differs). This template has only been exercised for iOS — see
  [Platform notes](#platform-notes) for Android. The Python `frida` package and
  `frida-server` must have the **same major version** - and should be the same
  release: `requirements.txt` pins Frida 17.25.1, so put frida-server 17.25.1 on
  the device (see [Frida 17](#frida-17)).
- Node.js and npm, to bundle the agents in `scripts/` into `dist/` via
  `frida-compile` (see [Building the agents](#building-the-agents)). CI builds on Node 20;
  `frida-compile` 19 was tried on Node 22 here, and an older Node than 20 has
  not been tried with it.
- Python 3.9+ (the packages in `requirements.txt` come with the install below).
- The Frida CLI (`frida`, `frida-ps`, etc.) if you want to attach manually
  instead of via the provided Python drivers.
- Ghidra (or similar) with the IL2CPP binary + `dump.cs` loaded, to find
  function offsets for new builds — `retk relocate` can then
  carry a known offset forward from one build to the next without
  re-opening Ghidra every time.

## Install

```bash
git clone https://github.com/ndhn27/re-toolkit && cd re-toolkit
pip install .            # or: pipx install .   (a `retk` of its own, away from your other Python packages)
retk --help
```

`pip install .` builds the wheel, and the wheel build runs `npm ci` and
`npm run build` (see [Building the agents](#building-the-agents)) so that the Frida agents are inside
the installed package: Node.js 20+ and npm have to be on `PATH` at **install**
time. They are not needed to *run* retk afterwards. Without Node, the install
stops and says so; `RETK_SKIP_AGENTS=1 pip install .` installs without the
agents (`retk relocate`, `retk diff`, `retk profile` and `retk builds` never
use them; `retk dump` tells you when it has none). To build a wheel to carry
to another machine: `python -m build --wheel --outdir wheelhouse` (not into
`dist/`, which is where the bundles are).

Working on the toolkit itself:

```bash
pip install -r requirements-dev.txt    # runtime requirements, pytest, ruff
npm ci && npm run build                # dist/ - what the tests and a checkout load
pip install -e .                       # optional: the `retk` command on this checkout
pytest
```

The tests put `src/` on the path themselves (`pytest.ini`), so `pytest` needs no
install; `pip install -e .` only adds the `retk` command, which finds the
checkout's `dist/` and `profile.example.json` where they are.
`RETK_AGENTS_DIR=/some/folder` makes retk load the agent bundles from there
instead, in either mode.

## Frida 17

`requirements.txt` pins `frida==17.25.1` and `frida-tools==14.11.0` exactly (the
`frida-tools` release asks for `frida>=17.10,<18`). Exact, because the
`frida-server` on the device has to be the same major as this client - a 17
client cannot talk to a 16 server, nor the other way round - and is best the
same release; a range would let pip pick what is newest the day you install.
**Put frida-server 17.25.1 on the device.** To move to another release, change
both pins together, run `pytest` and `npm run build`, and update the device.

Frida 17 removed the static `Module` APIs (`Module.findExportByName` and
friends), the `enumerate*` callback and `*Sync` forms and `Memory.read*` /
`Memory.write*`, and stopped bundling the ObjC/Java/Swift bridges. The agents
use none of them: they look a module up with `Process.getModuleByName` /
`Process.enumerateModules` / `Process.attachModuleObserver` - all in one
function, `fridaModules()` in `scripts/_lib.js` - and then use the module's own
methods and `NativePointer.read*`. `tests/test_frida_version.py` fails if an
agent starts to use a removed API, if the pin stops being exact, or if the Frida
the tests run under is not the pinned one; and no agent needs a bridge, so
there is nothing to bundle one for (an agent that wants `Java` or `ObjC` would
have to import `frida-java-bridge` / `frida-objc-bridge` and be bundled with it).

The behaviour is checked, not assumed: `tests/test_frida_real.py` runs the
agents under the pinned Frida against a real process - the hook firing on the
profile's RVA and the 64-bit `retval` in `onLeave` judged by its low 32 bits
(so a garbage upper half neither fails a success nor passes a failure) - both
the scripts compiled by `frida.Compiler` and, after `npm run build`, the very
`dist/` files the drivers load (CI builds first, and fails when they are
missing). Two things it cannot tell you:

- It runs on Linux x86-64 only. A device build of `frida-server` may differ in
  details this repo can't see, so run `retk exports` on the device first.
- It never meets a frida-server of another major: the tests spawn on the local
  device. Frida itself refuses a client and server whose majors differ (at
  connection time, before any agent loads), but that refusal is not exercised here.

## Building the agents

`scripts/*.js` import shared helpers from `scripts/_lib.js` as ES modules
(see the [agent table](AGENTS.md)), so they need bundling into a single
self-contained file before Frida — or the Python drivers in `retk` — can
load them:

```bash
npm run build
```

This writes one bundled file per agent to `dist/` (e.g.
`dist/dump_table_a.js`) — point Frida or `retk` at
that, not at the files in `scripts/` directly. Re-run `npm run build` (or
e.g. `npm run watch:table-a` for just that one agent) after any
edit to `scripts/*.js`. (`pip install .` does this for you and copies the
result into the package, see [Install](#install).)

`retk` finds a bundle in `$RETK_AGENTS_DIR` if you set it, else inside the
installed package, else in the checkout's `dist/`. `--agent` takes a path or just
a bundle's name (`retk dump --agent dump_table_b.js`) — the name is how an
installed retk, with no `dist/` to point at, picks the other agent.

You build once, for every target: the bundles hold no value of your target,
so a new target, a new offset or a changed layout is a profile edit and never
a rebuild.

## Platform notes

Nothing in the agents or drivers assumes a platform:
the IL2CPP module is whatever you SAY - your profile's `module` or `platform`,
or `--module` / `--platform` - and there is no default, because a default
would quietly pick one platform for everybody (`UnityFramework` is an iOS
name; on Android it is `libil2cpp.so`, on Windows `GameAssembly.dll`).
`--platform ios|android|windows` is just a shorthand for that platform's usual
name (the table is `PLATFORM_MODULES` in `src/retk/profiles.py`); `--module`
beats it, for a build that renamed the library.
What has actually been exercised is iOS, so Android is unverified here:
IL2CPP's internals are largely the same across platforms, but the record
layouts must be re-derived against that binary from scratch. Two limits are
deliberate: the agents' own reads are architecture-neutral, but
`retk relocate` handles **AArch64 only** (arm64/arm64e Mach-O,
arm64-v8a ELF, ARM64 PE) and refuses an x86-64 or 32-bit ARM binary with the
reason rather than searching it for byte patterns that are not instructions
there; and the layout self-check (see [Checking a layout against the build](LAYOUT_CHECK.md))
is what tells you a layout has gone stale on a build you haven't looked at.
