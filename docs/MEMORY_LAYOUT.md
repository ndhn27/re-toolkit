# Memory layout notes

Findings from instrumenting `UnityFramework` in this build with Frida.
These are build-specific and will need to be re-verified against any new
build (offsets in particular will drift — see `tools/relocate_offset.py`).

> The field-by-field listings below are **generated** from
> [`schema/layouts.json`](../schema/layouts.json) - the one place an offset or
> a field type is written down. The Frida agents read their records through
> the same schema (`scripts/_layouts.js`, generated) and `tools/records.py`
> is generated from it too, so change the schema and run
> `python tools/gen_layouts.py` rather than editing any of those by hand;
> `tests/test_layouts.py` fails if one is stale. The text around the listings
> is the hand-written narrative (why the layout looks the way it does) and
> deliberately doesn't repeat offsets. See `ITERATION_HISTORY.md` for how the
> layouts were worked out, wrong guesses included.

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

<!-- BEGIN GENERATED: il2cpp-string (tools/gen_layouts.py from schema/layouts.json - do not edit) -->
```text
+0x00  klass    (8 bytes, object header)
+0x08  length   (int32, NOT padded to 8 bytes)
+0x0c  UTF-16LE chars, starting immediately after length, no gap
```
<!-- END GENERATED: il2cpp-string -->

## `DeviceQualityAllowList` record

<!-- BEGIN GENERATED: DeviceQualityRecord (tools/gen_layouts.py from schema/layouts.json - do not edit) -->
```text
+0x00  klass             object header (8 bytes)
+0x08  id                uint32          numeric record id
+0x0c  (padding, 4 bytes)
+0x10  szName_ByteArray  (not read; 8 bytes)
+0x18  enabled           int8            HD render quality on/off flag (observed as 0 or 1)
+0x19  (padding, 7 bytes)
+0x20  name              System.String*  device name/identifier
```

`szName_ByteArray` (`+0x10..0x17`): byte[]* - observed NULL every time and unused in practice; the real name is the System.String in `name`.
<!-- END GENERATED: DeviceQualityRecord -->

The pointers land on 8-byte boundaries because pointers must be 8-aligned,
which is why the small fields look like they occupy full slots here.

## `DeviceRecommendConfig` record

<!-- BEGIN GENERATED: RecommendConfigRecord (tools/gen_layouts.py from schema/layouts.json - do not edit) -->
```text
+0x00  klass                       object header (8 bytes)
+0x08  id                          uint32          numeric record id
+0x0c  type                        uint32          record type discriminator
+0x10  unidentified                (not read; 8 bytes)
+0x18  paramMin1                   int32
+0x1c  paramMax1                   int32
+0x20  paramMin2                   int32
+0x24  paramMax2                   int32
+0x28  paramMin3                   int32
+0x2c  paramMax3                   int32
+0x30  deviceLevel                 uint32
+0x34  supportsFPS60               uint32          observed as a 0/1 flag
+0x38  supportsParticleHD          uint32          observed as a 0/1 flag
+0x3c  recommendGraphicMode        uint32
+0x40  renderQualityPerfMode       uint32
+0x44  particleQualityPerfMode     uint32
+0x48  resolutionPerfMode          uint32
+0x4c  fpsPerfMode                 uint32
+0x50  renderQualityGraphicMode    uint32
+0x54  particleQualityGraphicMode  uint32
+0x58  resolutionGraphicMode       uint32
+0x5c  fpsGraphicMode              uint32
+0x60  szConfig                    System.String*  graphics preset name
```

`unidentified` (`+0x10..0x17`): 8-byte region the investigation never resolved; not read by any agent. It is 8-aligned and sits before the first int32 run, which is consistent with a pointer field, but nothing here confirms that - treat it as unknown until you read it on your own build.
<!-- END GENERATED: RecommendConfigRecord -->

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
