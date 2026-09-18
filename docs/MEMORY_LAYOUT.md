# Memory layout notes

Findings from instrumenting `UnityFramework` in this build with Frida.
These are build-specific and will need to be re-verified against any new
build (offsets in particular will drift — see `tools/relocate_offset.py`).

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
+0x08 : dwID       (uint32)
+0x18 : chEnable   (int8 — HD render quality on/off flag)
+0x20 : name       (System.String* — device name/identifier)
```

Every field occupies a full 8-byte slot regardless of its actual size —
including the single-byte `chEnable` flag and the padded `uint32 dwID`.
There's also an unused `szName_ByteArray` (`byte[]`) field at `+0x10` that
was consistently observed as `NULL`; the real name lives in the
`System.String` field at `+0x20` instead.

## `DeviceRecommendConfig` record

```
+0x08 : dwID                              (uint32)
+0x0c : dwType                            (uint32)
+0x18 : iIntParam1min / +0x1c : iIntParam1max   (int32)
+0x20 : iIntParam2min / +0x24 : iIntParam2max   (int32)
+0x28 : iIntParam3min / +0x2c : iIntParam3max   (int32)
+0x30 : dwDeviceLevel                     (uint32)
+0x34 : dwISSupportFPS60                  (uint32)
+0x38 : dwISSupportParticleHD             (uint32)
+0x3c : dwRecommendGraphicMode            (uint32)
+0x40 : dwRenderQualityPerformanceMode    (uint32)
+0x44 : dwParticleQualityPerformanceMode  (uint32)
+0x48 : dwResolutionPerformanceMode       (uint32)
+0x4c : dwFPSPerformanceMode              (uint32)
+0x50 : dwRenderQualityGraphicMode        (uint32)
+0x54 : dwParticleQualityGraphicMode      (uint32)
+0x58 : dwResolutionGraphicMode           (uint32)
+0x5c : dwFPSGraphicMode                  (uint32)
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
