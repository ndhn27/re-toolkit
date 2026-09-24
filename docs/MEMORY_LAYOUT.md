# Memory layout notes

Findings from instrumenting `UnityFramework` in this build with Frida.
These are build-specific and will need to be re-verified against any new
build (offsets in particular will drift — see `tools/relocate_offset.py`).

> For a quick field-by-field reference rather than the full narrative
> below, see the `DeviceQualityRecord` / `RecommendConfigRecord` /
> `SelectionResult` JSDoc `@typedef` blocks in the matching
> `scripts/*.js` files, and `tools/records.py`'s `TypedDict`s (the Python
> mirror of the first two — see that file's docstring for why
> `SelectionResult` has no Python-side equivalent). This file stays useful
> for *how* those layouts were worked out — see `ITERATION_HISTORY.md` for
> that process end to end.

## IL2CPP object header

Standard IL2CPP objects normally have a 16-byte header (`klass` pointer +
`monitor` pointer). **In this build, the header is only 8 bytes** — just
the `klass` pointer, no separate monitor word. This applies to every
object observed, not just one record type, and it's the root cause behind
several early wrong guesses in the iteration history below.

## `System.String`

```
+0x00 : klass          (8 bytes)
+0x08 : length          (int32, NOT padded to 8 bytes)
+0x0C : UTF-16LE chars, starting immediately, no gap
```

## `DeviceQualityAllowList` record

```
+0x00 : klass
+0x08 : id       (uint32)
+0x18 : enabled   (int8 — HD render quality on/off flag)
+0x20 : name       (System.String* — device name/identifier)
```

Every field occupies a full 8-byte slot regardless of its actual size —
including the single-byte `enabled` flag and the padded `uint32 id`.
There's also an unused `szName_ByteArray` (`byte[]`) field at `+0x10` that
was consistently observed as `NULL`; the real name lives in the
`System.String` field at `+0x20` instead.

## `DeviceRecommendConfig` record

```
+0x08 : id                              (uint32)
+0x0c : type                            (uint32)
+0x18 : paramMin1 / +0x1c : paramMax1   (int32)
+0x20 : paramMin2 / +0x24 : paramMax2   (int32)
+0x28 : paramMin3 / +0x2c : paramMax3   (int32)
+0x30 : deviceLevel                     (uint32)
+0x34 : supportsFPS60                  (uint32)
+0x38 : supportsParticleHD             (uint32)
+0x3c : recommendGraphicMode            (uint32)
+0x40 : renderQualityPerfMode    (uint32)
+0x44 : particleQualityPerfMode  (uint32)
+0x48 : resolutionPerfMode       (uint32)
+0x4c : fpsPerfMode              (uint32)
+0x50 : renderQualityGraphicMode        (uint32)
+0x54 : particleQualityGraphicMode      (uint32)
+0x58 : resolutionGraphicMode           (uint32)
+0x5c : fpsGraphicMode                  (uint32)
+0x60 : szConfig                        (System.String*)
```

Field names/spelling below match the naming convention used elsewhere in
this build's managed metadata.

## Selection-logic entry points

Two functions were hooked directly (instead of only reading the static
tables) to observe the live selection algorithm:

- `GetConfigMatchingDevicePattern(deviceName, ?, type)` → returns a
  `DeviceRecommendConfig*` or `NULL` if no regex pattern matched the
  device name.
- `GetRecommendedQualityPreset()` → the top-level entry point, called on
  entering the graphics/lobby screen; returns the final chosen config.

RVAs for these were located via static analysis (Image Base = 0).
