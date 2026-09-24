"""
records.py

TypedDict schemas for the JSON records the Frida agents in scripts/ send
back over rpc.exports (see run_hd_quality_dump.py's `get_records()` call) -
the Python-side mirror of the JSDoc `@typedef` blocks in the matching
scripts/*.js files:

    DeviceQualityRecord    <->  scripts/dump_hd_quality_list.js
    RecommendConfigRecord  <->  scripts/dump_recommend_config.js

Field names and types here must match those JSDoc blocks exactly - RPC
just forwards whatever the agent's JS object literal contained, so any
drift between the two sides would be silent (Python's TypedDict isn't
checked at runtime either). tests/test_records_schema.py diffs this
file's fields against each typedef's `@property` list so a drift doesn't
stay silent for long.

These are documentation, same as the JS side: nothing in this project runs
mypy/pyright over them, and rpc.exports.get_records() itself still returns
a plain `list[dict]` at runtime - see the type comment on `recs` in
run_hd_quality_dump.py for how they're used there.
"""
from typing import Optional, TypedDict


class DeviceQualityRecord(TypedDict):
    """One entry of ExampleNamespace.DeviceQualityAllowList.

    Mirrors the `DeviceQualityRecord` typedef in
    scripts/dump_hd_quality_list.js - see that file (and
    docs/MEMORY_LAYOUT.md) for the field offsets and how they were found.
    """
    id: int
    enabled: int
    name: Optional[str]


class RecommendConfigRecord(TypedDict):
    """One entry of ExampleNamespace.DeviceRecommendConfig.

    Mirrors the `RecommendConfigRecord` typedef in
    scripts/dump_recommend_config.js - see that file (and
    docs/MEMORY_LAYOUT.md) for the field offsets and how they were found.
    scripts/dump_selection_logic.js's `SelectionResult` typedef documents a
    5-field subset of this same record (id, type, deviceLevel,
    fpsGraphicMode, szConfig), read via a different pair of hooked
    functions - there's no separate Python TypedDict for that subset since
    nothing on the Python side consumes it (dump_selection_logic.js has no
    rpc.exports; it only prints to the console - see run_hd_quality_dump.py's
    docstring).
    """
    id: int
    type: int
    paramMin1: int
    paramMax1: int
    paramMin2: int
    paramMax2: int
    paramMin3: int
    paramMax3: int
    deviceLevel: int
    supportsFPS60: int
    supportsParticleHD: int
    recommendGraphicMode: int
    renderQualityPerfMode: int
    particleQualityPerfMode: int
    resolutionPerfMode: int
    fpsPerfMode: int
    renderQualityGraphicMode: int
    particleQualityGraphicMode: int
    resolutionGraphicMode: int
    fpsGraphicMode: int
    szConfig: Optional[str]
