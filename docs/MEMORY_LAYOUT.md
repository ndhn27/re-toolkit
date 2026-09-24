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

Standard 64-bit IL2CPP objects have a 16-byte header (`klass` pointer +
`monitor` pointer). **In this build, the header was observed to be only 8
bytes** — just the `klass` pointer, no separate monitor word — for every
object read, not just one record type. This is a property of the build
investigated here (it differs from stock IL2CPP), so re-verify it on a new
target before trusting any offset in this file; it is the root cause of
several early wrong guesses in `ITERATION_HISTORY.md`.

## Field placement rule

Fields are laid out in declaration order with **natural alignment**: a
field starts at the next offset that is a multiple of its own size, and
any gap before it is padding. Fields are *not* padded to 8-byte slots
individually. The two records below show both effects:

- `DeviceQualityAllowList` mixes a `uint32`, an `int8` and two pointers, so
  padding appears before each pointer and after the `uint32` / `int8`.
- `DeviceRecommendConfig` packs `uint32`/`int32` fields back to back at a
  4-byte stride, with no padding between them.

## `System.String`

```
+0x00 : klass          (8 bytes)
+0x08 : length          (int32, NOT padded to 8 bytes)
+0x0C : UTF-16LE chars, starting immediately, no gap
```

## `DeviceQualityAllowList` record

```
+0x00 : klass
+0x08 : id                (uint32)         +0x0c..0x0f: padding
+0x10 : szName_ByteArray  (byte[]*)        observed NULL every time
+0x18 : enabled           (int8)           +0x19..0x1f: padding
+0x20 : name              (System.String*) device name/identifier
```

`enabled` is the HD render quality on/off flag. The `byte[]` field at
`+0x10` is unused in practice; the real name lives in the `System.String`
at `+0x20`. The pointers land on 8-byte boundaries because pointers must
be 8-aligned, which is why the small fields look like they occupy full
slots here.

## `DeviceRecommendConfig` record

```
+0x08 : id                              (uint32)
+0x0c : type                            (uint32)
+0x10 : (not identified, 8 bytes)       not read by any agent here
+0x18 : paramMin1 / +0x1c : paramMax1   (int32)
+0x20 : paramMin2 / +0x24 : paramMax2   (int32)
+0x28 : paramMin3 / +0x2c : paramMax3   (int32)
+0x30 : deviceLevel                     (uint32)
+0x34 : supportsFPS60                   (uint32)
+0x38 : supportsParticleHD              (uint32)
+0x3c : recommendGraphicMode            (uint32)
+0x40 : renderQualityPerfMode           (uint32)
+0x44 : particleQualityPerfMode         (uint32)
+0x48 : resolutionPerfMode              (uint32)
+0x4c : fpsPerfMode                     (uint32)
+0x50 : renderQualityGraphicMode        (uint32)
+0x54 : particleQualityGraphicMode      (uint32)
+0x58 : resolutionGraphicMode           (uint32)
+0x5c : fpsGraphicMode                  (uint32)
+0x60 : szConfig                        (System.String*)
```

`+0x10..0x17` is an 8-byte region the investigation never resolved. It
is 8-aligned and sits before the first `int32` run, which is consistent
with a pointer field, but nothing here confirms that — treat it as
unknown until you read it on your own build.

Field names/spelling match the naming convention used elsewhere in this
build's managed metadata.

## Selection-logic entry points

Two functions were hooked directly (instead of only reading the static
tables) to observe the live selection algorithm:

- `GetConfigMatchingDevicePattern(deviceName, ?, type)` → returns a
  `DeviceRecommendConfig*` or `NULL` if no regex pattern matched the
  device name.
- `GetRecommendedQualityPreset()` → the top-level entry point, called on
  entering the graphics/lobby screen; returns the final chosen config.

RVAs for these were located via static analysis (Image Base = 0).
