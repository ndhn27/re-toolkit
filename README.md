# IL2CPP Render-Quality Research (Generic Template)

Frida-based tooling and methodology notes for inspecting how a Unity +
IL2CPP mobile game (`com.example.unitygame` — replace with your own
target's package name) decides which devices are eligible for HD render
quality and which graphics preset gets recommended for a given device.
Everything here is **read-only instrumentation** — the scripts hook the
target app's own unpack/lookup functions at runtime and read memory;
nothing patches the binary or writes back into the process.

This is a **generalized template**, distilled from a real investigation
against one specific app. All target-identifying details — the package
name, the app's actual internal class/method names, and the memory
offsets found in that build — have been replaced with placeholders
(`com.example.unitygame`, `ExampleNamespace.*`, `FRIDA_OFFSET = 0x0`,
etc.) so this can be reused as a starting point for research on **your
own** target, rather than being usable as-is against any particular app.
You'll need to re-derive the real class/method names and offsets for
whatever app you're actually studying, using Ghidra or similar, following
the methodology in `docs/ITERATION_HISTORY.md`.

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
scripts/    Frida agents (.js) — attach to a running game process
tools/      Python drivers that spawn/attach via frida-tools and drive the agents
legacy/     Earlier, superseded versions of dump_hd_quality_list.js, kept
            for reference — see docs/ITERATION_HISTORY.md
docs/       Struct layout notes and the debugging history
```

| Script | Purpose |
|---|---|
| `scripts/dump_hd_quality_list.js` | Dumps `ExampleNamespace.DeviceQualityAllowList`: which device names have HD render quality enabled. |
| `scripts/dump_recommend_config.js` | Dumps `ExampleNamespace.DeviceRecommendConfig`: the full table of graphics presets per device tier. |
| `scripts/dump_recommend_config_probe.js` | Generic raw-hex probe used to work out an unknown record layout by hand. |
| `scripts/dump_selection_logic.js` | Hooks `GetConfigMatchingDevicePattern` / `GetRecommendedQualityPreset` directly, to watch the live selection algorithm instead of just reading static tables. |
| `scripts/list_il2cpp_exports.js` | Lists `UnityFramework` exports/symbols — used to relocate `il2cpp_init` and other entry points in a build. |

## Requirements

- A rooted/jailbroken device or emulator running `com.example.unitygame`,
  with `frida-server` running and reachable (scripts assume it's forwarded
  to `127.0.0.1:27042` — adjust `REMOTE_ADDR` in the Python tools if yours
  differs).
- Python 3.8+ with the packages in `requirements.txt`.
- The Frida CLI (`frida`, `frida-ps`, etc.) if you want to attach manually
  instead of via the provided Python drivers.
- Ghidra (or similar) with the IL2CPP binary + `dump.cs` loaded, to find
  function offsets for new builds — `tools/relocate_offset.py` can then
  carry a known offset forward from one build to the next without
  re-opening Ghidra every time.

```bash
pip install -r requirements.txt
```

## Usage

1. Find the file offset of the function you want to hook (e.g.
   `DeviceQualityAllowList$$unpack`) via Ghidra's Symbol Table,
   with Image Base set to 0, and set `FRIDA_OFFSET` at the top of the
   corresponding script in `scripts/`.
2. Either:
   - Run the matching driver in `tools/` (e.g. `python tools/run_hd_quality_dump.py`),
     which spawns the game, loads the agent, and lets you export the
     collected table to JSON by pressing Enter; or
   - Attach manually with the Frida CLI:
     `frida -R -f com.example.unitygame -l scripts/dump_hd_quality_list.js`
3. Play through to the point where the game loads the relevant data
   (usually the graphics settings screen or app start) and watch the
   console output.

When a game update ships a new `UnityFramework` binary, offsets shift. Use
`tools/relocate_offset.py OLD_BINARY OLD_OFFSET_HEX NEW_BINARY` to carry a
known-good offset forward via an instruction-fingerprint match, instead of
re-finding it by hand in Ghidra each time.

## Findings

See [`docs/MEMORY_LAYOUT.md`](docs/MEMORY_LAYOUT.md) for the confirmed
struct layouts, and [`docs/ITERATION_HISTORY.md`](docs/ITERATION_HISTORY.md)
for how they were worked out (kept because the debugging process is a
useful worked example on its own).

## License

MIT — see [`LICENSE`](LICENSE).
