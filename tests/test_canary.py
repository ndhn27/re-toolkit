"""
Tests for the layout self-check, end to end: scripts/_canary.js counting what
an agent reads, and retk/layout_check.py judging those counts.

The agents run for real under Node against a fake process image (the harness in
tests/frida_harness.mjs), and what they export through `getHealth` goes through
the real judge. The scenarios are the failure this exists for: a layout that was
right for one build and is wrong for the next, which used to produce a dump of
plausible-looking garbage and no warning at all.

  * a table that matches its layout passes;
  * a build that moved every field by 8 bytes fails - with `expect`, and without
    it too when the stray bytes are unreadable;
  * what NO structural check can see - zeroed memory read through a shifted
    layout - passes without `expect`, passes with notes that say so, and fails
    the moment the profile claims anything about the field;
  * a wrong object header (the class word varies, is null or is unmapped), wrong
    `key`, reads that throw, and the tolerance that separates a stray read from
    a wrong layout.

The Node-backed tests skip when `node` isn't installed (and fail when $CI is
set). Run from the repo root:

    pytest
"""
import copy
import struct
from pathlib import Path

import pytest

from retk import layout_check
from retk import layouts
from retk import profiles
from node_support import run_harness

REPO_ROOT = Path(__file__).resolve().parent.parent
PROFILE = profiles.load(REPO_ROOT / "profile.example.json")
STRING_AT = PROFILE.layouts["string"]
A_OFFSETS = {f["name"]: f["offset"] for f in PROFILE.layouts["records"]["TableARecord"]["fields"]}
A_FIELDS = layouts.for_agent(PROFILE.layouts)["records"]["TableARecord"]["fields"]

IMAGE_SIZE = 0x4000
RECORD_BASE, RECORD_STRIDE = 0x1000, 0x80
STRING_BASE, STRING_STRIDE = 0x3000, 0x40
CLASS_WORD = 0x200            # an address inside the image, i.e. "mapped" in the fake process
HOOK_OFFSET = 0x40


def params(strip_expect=False, **layout_changes):
    """What the driver passes to init(): the example profile with table_a set."""
    p = profiles.agent_params(PROFILE, offsets={"table_a": HOOK_OFFSET})
    p = copy.deepcopy(p)
    for r in p["layouts"]["records"].values():
        for f in r["fields"]:
            if strip_expect:
                f.pop("expect", None)
    for rname, changes in layout_changes.items():
        p["layouts"]["records"][rname].update(changes)
    return p


class Table:
    """TableARecord objects in a fake process image. `shift` moves every field - the
    build that grew the header; `fill` is what unwritten memory holds (0xEE: garbage
    that no reader mistakes for data; 0x00: zeroed memory, which it often does)."""

    def __init__(self, fill=0xEE):
        self.mem = bytearray([fill]) * IMAGE_SIZE
        self.bases = []
        self._string_at = STRING_BASE

    def string(self, text):
        addr, self._string_at = self._string_at, self._string_at + STRING_STRIDE
        struct.pack_into("<i", self.mem, addr + STRING_AT["length_offset"], len(text))
        data = text.encode("utf-16-le", "surrogatepass")
        self.mem[addr + STRING_AT["chars_offset"]:addr + STRING_AT["chars_offset"] + len(data)] = data
        return addr

    def add(self, id, weight=0, enabled=0, name="x", klass=CLASS_WORD, shift=0):
        base = RECORD_BASE + len(self.bases) * RECORD_STRIDE
        self.bases.append(base)
        struct.pack_into("<Q", self.mem, base, klass)
        struct.pack_into("<I", self.mem, base + A_OFFSETS["id"] + shift, id)
        struct.pack_into("<i", self.mem, base + A_OFFSETS["weight"] + shift, weight)
        struct.pack_into("<b", self.mem, base + A_OFFSETS["enabled"] + shift, enabled)
        struct.pack_into("<Q", self.mem, base + A_OFFSETS["name"] + shift,
                         0 if name is None else self.string(name))
        return base

    def add_good(self, n=6, **kw):
        for i in range(1, n + 1):
            self.add(i, weight=-5 * i, enabled=i % 2, name=f"name-{i}", **kw)
        return self

    def events(self, extra=()):
        return [{"hook": 0, "args": [b], "retval": 0} for b in [*self.bases, *extra]]


def run(node_scripts, table, p=None, extra_bases=(), **request):
    return run_harness(node_scripts, table.mem, mode="agent", agent="dump_table_a.js",
                       params=params() if p is None else p, events=table.events(extra_bases), **request)


def judged(out, **kw):
    return layout_check.judge(out["health"], **kw)


# ---------------------------------------------------------------------------
# the scenarios
# ---------------------------------------------------------------------------

def test_a_table_that_matches_its_layout_passes(node_scripts):
    out = run(node_scripts, Table().add_good())
    [rec] = out["health"]["records"]
    assert (rec["record"], rec["calls"], rec["read_errors"], rec["key_conflicts"]) == ("TableARecord", 6, 0, 0)
    assert rec["klass"]["bad_pointer"] == 0 and rec["klass"]["variants"] == [["0x200", 6]]
    assert all(f["violations"] == 0 and f["bad"] == 0 for f in rec["fields"].values())
    v = judged(out)
    assert v.status == layout_check.OK and v.problems == []
    assert any("no `expect` for weight" in n for n in v.notes)       # the one field nothing checks


def test_a_build_that_moved_every_field_by_eight_bytes_fails(node_scripts):
    # What the user feared: the layout is right for the old build, the target is the
    # new one, and the tool used to dump whatever sat at the old offsets.
    table = Table()
    for i in range(1, 7):
        table.add(i, weight=-5 * i, enabled=i % 2, name=f"name-{i}", shift=8)
    v = judged(run(node_scripts, table))
    assert v.status == layout_check.FAIL
    assert any("TableARecord.name" in p for p in v.problems)              # the string pointer is junk
    assert any("TableARecord.enabled" in p for p in v.problems)           # ...and the flag isn't 0/1


def test_the_shift_is_caught_without_any_expect_when_the_strings_are_unreadable(node_scripts):
    table = Table()
    for i in range(1, 7):
        table.add(i, weight=-5 * i, enabled=i % 2, name=f"name-{i}", shift=8)
    v = judged(run(node_scripts, table, p=params(strip_expect=True)))
    assert v.status == layout_check.FAIL
    assert any("TableARecord.name" in p and "not a valid string" in p for p in v.problems)


def test_zeroed_memory_where_the_layout_expects_data_needs_an_expect_to_be_caught(node_scripts):
    """The blind spot, pinned on purpose. The build moved the data well away from where
    the layout looks, so every read is a clean zero: no structural check has anything to
    object to, and the verdict is a pass whose notes say that nothing varied. The moment
    the profile claims something (here: ids start at 1) it fails."""
    def build():
        table = Table(fill=0)
        for i in range(1, 7):
            table.add(i, weight=-5 * i, enabled=i % 2, name=f"name-{i}", shift=0x40)
        return table

    blind = judged(run(node_scripts, build(), p=params(strip_expect=True)))
    assert blind.status == layout_check.OK                       # NOT contradicted - not "correct"
    assert any("every field read identically in all 6 reads" in n for n in blind.notes)

    claimed = judged(run(node_scripts, build()))
    assert claimed.status == layout_check.FAIL
    assert any("TableARecord.id" in p and "below min 1" in p for p in claimed.problems)


def test_a_class_word_that_varies_means_args0_is_not_the_record(node_scripts):
    table = Table()
    for i in range(1, 7):
        table.add(i, weight=-i, enabled=i % 2, name=f"n{i}", klass=CLASS_WORD + 8 * i)
    out = run(node_scripts, table)
    assert len(out["health"]["records"][0]["klass"]["variants"]) == 6
    v = judged(out)
    assert v.status == layout_check.FAIL
    assert any("not the same in every record" in p for p in v.problems)


def test_klass_pointer_mode_accepts_a_table_of_subclasses(node_scripts):
    table = Table()
    for i in range(1, 7):
        table.add(i, weight=-i, enabled=i % 2, name=f"n{i}", klass=CLASS_WORD + 8 * (i % 2))
    p = params(TableARecord={"klass": "pointer"})
    assert judged(run(node_scripts, table, p=p)).status == layout_check.OK
    assert judged(run(node_scripts, table)).status == layout_check.FAIL     # the default is stricter


@pytest.mark.parametrize("klass, why", [
    (0, "null"),
    (CLASS_WORD + 4, "not 8-aligned"),
    (IMAGE_SIZE + 0x1000, "not mapped"),
    (0xEEEEEEEEEEEEEEE8, "junk"),
])
def test_a_class_word_that_is_not_a_valid_pointer_fails_whatever_it_is(node_scripts, klass, why):
    table = Table()
    for i in range(1, 7):
        table.add(i, weight=-i, enabled=i % 2, name=f"n{i}", klass=klass)
    out = run(node_scripts, table)
    assert out["health"]["records"][0]["klass"]["bad_pointer"] == 6, why
    v = judged(out)
    assert v.status == layout_check.FAIL
    assert any("not a valid class pointer" in p for p in v.problems), why
    assert any("layout check TableARecord: the word at +0" in line for line in out["log"]), why


def test_a_key_that_does_not_identify_records_fails(node_scripts):
    table = Table()
    for i in range(1, 7):
        table.add(7, weight=-i, enabled=i % 2, name=f"n{i}")      # one id, six different records
    out = run(node_scripts, table)
    assert out["rpc"]["count"] == 1                                # what the store kept
    v = judged(out)
    assert v.status == layout_check.FAIL
    assert any("does not identify a record" in p for p in v.problems)


def test_an_app_that_updates_one_record_is_a_note_not_a_failure(node_scripts):
    table = Table().add_good()
    table.add(3, weight=999, enabled=1, name="renamed")             # id 3 again, new contents
    v = judged(run(node_scripts, table))
    assert v.status == layout_check.OK
    assert any("re-sent a key with different contents" in n for n in v.notes)


def test_reads_that_throw_are_counted_and_judged(node_scripts):
    table = Table().add_good(5)
    out = run(node_scripts, table, extra_bases=[IMAGE_SIZE - 4])    # the record runs off the image
    assert out["health"]["records"][0]["read_errors"] == 1
    assert judged(out).status == layout_check.FAIL                  # 1 of 6
    assert judged(out, tolerance=0.2).status == layout_check.OK     # ...which a looser line tolerates
    assert any("a record could not be read" in line for line in out["log"])


def test_a_stray_unreadable_string_is_judged_by_the_tolerance(node_scripts):
    table = Table().add_good(5)
    table.add(6, weight=-30, enabled=0, name="bad\x01name")         # a control character
    out = run(node_scripts, table)
    [rec] = out["health"]["records"]
    assert rec["fields"]["name"]["bad"] == 1
    assert judged(out).status == layout_check.FAIL
    assert judged(out, tolerance=0.2).status == layout_check.OK


def test_getHealth_before_init_is_safe_and_unverified(node_scripts):
    out = run_harness(node_scripts, Table().mem, mode="agent", agent="dump_table_a.js", params=None, events=[])
    assert out["initError"] is not None
    assert out["health"] == {"version": 1, "records": []}
    assert layout_check.judge(out["health"]).status == layout_check.UNVERIFIED


def test_both_dump_agents_export_getHealth(node_scripts):
    table = Table().add_good(2)
    out = run_harness(node_scripts, table.mem, mode="agent", agent="dump_table_b.js",
                      params=profiles.agent_params(PROFILE, offsets={"table_b": HOOK_OFFSET}), events=[])
    assert out["health"] == {"version": 1, "records": [
        {**out["health"]["records"][0], "record": "TableBRecord", "calls": 0}]}


# ---------------------------------------------------------------------------
# the canary on its own (scripts/_canary.js through the harness)
# ---------------------------------------------------------------------------

def canary(node_scripts, fields, observations, klass=None, table=None):
    return run_harness(node_scripts, (table or Table()).mem, mode="canary", record="R",
                       fields=fields, klass=klass, observations=observations)


def f(name, type_, **expect):
    out = {"name": name, "offset": 0, "type": type_}
    if expect:
        out["expect"] = expect
    return out


def test_expect_rules_count_violations_and_keep_a_few_examples(node_scripts):
    fields = [f("n", "u32", min=2, max=5), f("flag", "s8", oneOf=[0, 1]), f("s", "string", nonEmpty=True, maxLength=3)]
    rows = [
        {"n": 1, "flag": 0, "s": "ab"},        # n below min
        {"n": 2, "flag": 1, "s": "abc"},       # fine
        {"n": 5, "flag": 2, "s": ""},          # flag not in oneOf, s empty
        {"n": 6, "flag": -1, "s": "abcd"},     # n above max, flag bad, s too long
        {"n": 9, "flag": 7, "s": None},        # n above max, flag bad, null pointer
        {"n": 12, "flag": 3, "s": "z"},        # n above max, flag bad
    ]
    out = canary(node_scripts, fields, [{"base": 0x300, "record": r} for r in rows])
    h = out["health"]
    assert h["calls"] == 6
    n, flag, s = h["fields"]["n"], h["fields"]["flag"], h["fields"]["s"]
    assert (n["checked"], n["violations"], n["min"], n["max"]) == (6, 4, 1, 12)
    assert (flag["violations"], s["violations"]) == (4, 3)
    assert len(n["examples"]) == 3 and n["examples"][0] == "1 is below min 2"     # capped, in order
    assert "is not one of 0, 1" in flag["examples"][0]
    assert s["examples"] == ["empty string, expected a non-empty one", "length 4 is above maxLength 3",
                             "null pointer, expected a string"]
    assert all(f_["has_expect"] for f_ in h["fields"].values())


def test_a_field_without_expect_is_counted_but_never_violated(node_scripts):
    out = canary(node_scripts, [f("n", "s32")], [{"base": 0x300, "record": {"n": v}} for v in (-5, 0, 77)])
    n = out["health"]["fields"]["n"]
    assert (n["violations"], n["has_expect"], n["min"], n["max"]) == (0, False, -5, 77)
    assert n["values"] == [-5, 0, 77]                               # few enough to list: a hint for writing `expect`


def test_many_distinct_values_are_not_listed(node_scripts):
    out = canary(node_scripts, [f("n", "u32")], [{"base": 0x300, "record": {"n": v}} for v in range(40)])
    n = out["health"]["fields"]["n"]
    assert n["distinct"] is None and "values" not in n and (n["min"], n["max"]) == (0, 39)


STRING_CASES = [
    ("plain", "hello", False),
    ("accented letters", "Crème brûlée", False),
    ("emoji, a valid surrogate pair", "ok \U0001F600", False),
    ("tab and newlines are text", "a\tb\nc\r", False),
    ("control character", "a\x01b", True),
    ("NUL inside", "a\x00b", True),
    ("replacement character", "caf�", True),
    ("lone high surrogate", "x\ud800", True),
    ("lone low surrogate", "\udc00x", True),
    ("high surrogate then a letter", "\ud800a", True),
    ("failed read placeholder", "<read error: access violation accessing 0x10>", True),
    ("bad length placeholder", "<unexpected len: 99999999>", True),
]


def test_string_sanity_accepts_real_text_and_rejects_what_a_wrong_offset_reads(node_scripts):
    out = canary(node_scripts, [f("s", "string")],
                 [{"base": 0x300, "record": {"s": text}} for _, text, _ in STRING_CASES])
    s = out["health"]["fields"]["s"]
    assert s["bad"] == sum(bad for *_, bad in STRING_CASES)
    # ...and exactly the right ones: replay one at a time
    for label, text, bad in STRING_CASES:
        one = canary(node_scripts, [f("s", "string")], [{"base": 0x300, "record": {"s": text}}])
        assert one["health"]["fields"]["s"]["bad"] == int(bad), label


def test_a_null_string_is_not_a_bad_string(node_scripts):
    out = canary(node_scripts, [f("s", "string")], [{"base": 0x300, "record": {"s": None}}] * 3)
    s = out["health"]["fields"]["s"]
    assert (s["checked"], s["nulls"], s["bad"], s["violations"]) == (3, 3, 0, 0)


def test_a_failed_read_placeholder_is_not_also_counted_against_expect(node_scripts):
    out = canary(node_scripts, [f("s", "string", nonEmpty=True, maxLength=3)],
                 [{"base": 0x300, "record": {"s": "<read error: x>"}}])
    s = out["health"]["fields"]["s"]
    assert (s["bad"], s["violations"]) == (1, 0)


def test_the_first_violation_of_each_kind_is_logged_once(node_scripts):
    out = canary(node_scripts, [f("n", "u32", max=1)], [{"base": 0x300, "record": {"n": 5 + i}} for i in range(8)])
    warnings = [line for line in out["log"] if "layout check R: n:" in line]
    assert len(warnings) == 1 and "5 is above max 1" in warnings[0]
    assert out["health"]["fields"]["n"]["violations"] == 8


def test_observe_never_throws_and_counts_its_own_failures(node_scripts):
    out = canary(node_scripts, [f("n", "u32")],
                 [{"base": 0x300, "record": None}, {"base": 0x300, "record": {"n": 1}}])
    h = out["health"]
    assert h["internal_errors"] == 1 and h["fields"]["n"]["checked"] == 1


def test_a_field_missing_from_the_record_is_skipped_not_counted(node_scripts):
    out = canary(node_scripts, [f("a", "u32"), f("b", "u32")], [{"base": 0x300, "record": {"a": 1}}])
    assert out["health"]["fields"]["b"]["checked"] == 0


def test_klass_variants_are_tracked_and_capped(node_scripts):
    table = Table()
    for i in range(12):
        table.add(i, klass=CLASS_WORD + 8 * i)
    out = canary(node_scripts, [], [{"base": b, "record": {}} for b in table.bases], table=table)
    k = out["health"]["klass"]
    assert k["checked"] == 12 and len(k["variants"]) == 8 and k["other"] == 4
    assert k["mode"] == "constant" and canary(node_scripts, [], [], klass="pointer")["health"]["klass"]["mode"] == "pointer"


def test_a_failed_read_is_counted_by_readFailed(node_scripts):
    out = canary(node_scripts, [f("n", "u32")], [{"failed": "access violation"}, {"base": 0x300, "record": {"n": 1}}])
    assert out["health"]["read_errors"] == 1 and out["health"]["calls"] == 1
    assert any("could not be read: access violation" in line for line in out["log"])


# ---------------------------------------------------------------------------
# the layout's side of it
# ---------------------------------------------------------------------------

def test_the_example_profile_makes_claims_the_agents_receive(node_scripts):
    p = params()
    claims = {f["name"]: f["expect"] for f in p["layouts"]["records"]["TableARecord"]["fields"] if "expect" in f}
    assert claims == {"id": {"min": 1}, "enabled": {"oneOf": [0, 1]},
                      "name": {"nonEmpty": True, "maxLength": 64}}
    assert p["layouts"]["records"]["TableARecord"]["klass"] == "constant"
