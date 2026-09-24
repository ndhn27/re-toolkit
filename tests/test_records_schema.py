"""
Unit tests for tools/records.py.

The JSDoc `@typedef` blocks in scripts/*.js and the TypedDicts in
tools/records.py describe the same records from two different languages,
so nothing enforces that they stay in sync - a field renamed on one side
and not the other would be silent (see records.py's module docstring).
These tests parse each typedef's `@property` list out of the .js source and
diff it against the matching TypedDict's fields, so that kind of drift
fails a test instead of just confusing the next reader.

Run from the repo root:

    pytest
"""
import re
from pathlib import Path

import records

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"

# Matches a `/** ... */` JSDoc block containing "@typedef {Object} <name>",
# capturing the block body so @property lines can be pulled out of it.
_TYPEDEF_BLOCK_RE = re.compile(r"/\*\*(.*?)\*/", re.DOTALL)
_PROPERTY_RE = re.compile(r"@property\s+\{[^}]*\}\s+(\w+)")


def _js_typedef_fields(js_path, typedef_name):
    """Return the set of `@property` field names for `@typedef {Object}
    <typedef_name>` in the JSDoc comment block that declares it."""
    source = js_path.read_text(encoding="utf-8")
    for block in _TYPEDEF_BLOCK_RE.findall(source):
        if re.search(rf"@typedef\s+\{{Object\}}\s+{re.escape(typedef_name)}\b", block):
            return set(_PROPERTY_RE.findall(block))
    raise AssertionError(f"no @typedef {{Object}} {typedef_name} found in {js_path}")


def test_device_quality_record_matches_js_typedef():
    js_fields = _js_typedef_fields(SCRIPTS_DIR / "dump_hd_quality_list.js", "DeviceQualityRecord")
    py_fields = set(records.DeviceQualityRecord.__annotations__.keys())

    assert js_fields == py_fields


def test_recommend_config_record_matches_js_typedef():
    js_fields = _js_typedef_fields(SCRIPTS_DIR / "dump_recommend_config.js", "RecommendConfigRecord")
    py_fields = set(records.RecommendConfigRecord.__annotations__.keys())

    assert js_fields == py_fields


def test_selection_result_typedef_is_a_subset_of_recommend_config_record():
    # dump_selection_logic.js's SelectionResult has no Python TypedDict of
    # its own (see records.py's RecommendConfigRecord docstring for why) -
    # but it should still only ever name fields that really exist on
    # RecommendConfigRecord, since it's documented as reading a subset of
    # that same underlying struct.
    selection_fields = _js_typedef_fields(SCRIPTS_DIR / "dump_selection_logic.js", "SelectionResult")
    recommend_fields = set(records.RecommendConfigRecord.__annotations__.keys())

    assert selection_fields <= recommend_fields
    assert selection_fields  # sanity: the regex actually found something
