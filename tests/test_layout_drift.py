"""
Tests for the layout drift measurement and the early gate: scripts/_canary.js probing
where the fields WOULD be if the whole layout had moved, retk/layout_check.py turning
the probe's counts into "LAYOUT MAY HAVE CHANGED ... the header would be N bytes".

The agents run for real under Node against a fake process image (tests/frida_harness.mjs),
and what they export goes through the real judge. The scenarios are the failure this
exists for - a build that grew or shrank the object header, so that every offset in the
profile reads the wrong bytes and the dump is plausible-looking garbage:

  * a build that moved every field by 8 bytes is not just "failed": the report says by
    how much and what the header would be (and the same for -8 and +24);
  * nothing is claimed when the data cannot support it - memory that is zero everywhere
    says nothing, a move beyond the probed range is "no uniform shift", a layout with no
    field that can tell right from wrong is not blamed;
  * the claim is a measurement, never an edit: nothing in the profile or the agent changes;
  * the probe is quiet (no log line per junk string read at a wrong offset), covers only
    the first N records, and the gate sends ONE snapshot - after N reads, failed reads
    included - and never when it is off.

The Node-backed tests skip when `node` isn't installed (and fail when $CI is set).
Run from the repo root:

    pytest
"""
import json

import pytest

from retk import layout_check as lc
from node_support import run_harness
from test_canary import (IMAGE_SIZE, STRING_AT, A_OFFSETS, RECORD_BASE, RECORD_STRIDE, Table,
                         judged, params, run)


def shifted(shift, n=6, fill=0xEE):
    table = Table(fill=fill)
    for i in range(1, n + 1):
        table.add(i, weight=-5 * i, enabled=i % 2, name=f"name-{i}", shift=shift)
    return table


def drift_of(verdict):
    [d] = verdict.drift
    return d


# ---------------------------------------------------------------------------
# the measurement
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("shift, header", [(8, 24), (-8, 8), (16, 32), (24, 40), (-16, 0)])
def test_a_build_that_moved_every_field_is_measured_as_a_new_header_size(node_scripts, shift, header):
    # `-16` is a header of 0 bytes: not a real object, but it must still be what the arithmetic says.
    v = judged(run(node_scripts, shifted(shift)))
    assert v.status == lc.FAIL
    d = drift_of(v)
    assert (d["shift"], d["candidates"], d["header_declared"], d["header_measured"]) == (shift, [shift], 16, header)
    text = next(p for p in v.problems if "LAYOUT MAY HAVE CHANGED" in p)
    assert f"{abs(shift)} bytes {'further in' if shift > 0 else 'earlier'}" in text
    assert f"the object header would be {header} bytes, not the 16 the layout assumes" in text
    assert "nothing was applied" in text


def test_the_measurement_works_when_unwritten_memory_is_zero_not_junk(node_scripts):
    # Zeroed memory is what real heaps look like; every wrong shift reads as nothing at all, so
    # the one shift that reads data stands out all the more.
    v = judged(run(node_scripts, shifted(24, fill=0)))
    assert drift_of(v)["shift"] == 24 and drift_of(v)["header_measured"] == 40


def test_the_measurement_needs_no_expect_when_there_is_a_string_to_read(node_scripts):
    v = judged(run(node_scripts, shifted(8), p=params(strip_expect=True)))
    assert v.status == lc.FAIL and drift_of(v)["shift"] == 8


def test_a_layout_that_fits_is_not_told_it_drifted(node_scripts):
    v = judged(run(node_scripts, Table().add_good()))
    assert v.status == lc.OK and v.drift == []
    assert not any("MAY HAVE CHANGED" in p for p in v.problems)


def test_a_move_beyond_the_probed_range_is_reported_as_unexplained_not_guessed(node_scripts):
    v = judged(run(node_scripts, shifted(0x40, fill=0)))
    assert v.status == lc.FAIL
    d = drift_of(v)
    assert d["shift"] is None and d["candidates"] == [] and d["header_measured"] is None
    assert any("no uniform shift of -32..+32 bytes explains it" in p for p in v.problems)


def test_zeroed_memory_gives_the_probe_nothing_to_blame_or_clear(node_scripts):
    # No `expect`, zeros everywhere: the structural checks pass (the blind spot test_canary.py pins)
    # and the probe has no informative read at any shift - it must not invent a drift.
    v = judged(run(node_scripts, shifted(0x40, fill=0), p=params(strip_expect=True)))
    assert v.status == lc.OK and v.drift == []


def test_a_layout_with_no_field_that_can_tell_right_from_wrong_is_not_blamed(node_scripts):
    p = params(strip_expect=True)
    fields = p["layouts"]["records"]["TableARecord"]["fields"]
    p["layouts"]["records"]["TableARecord"]["fields"] = [f for f in fields if f["type"] != "string"]
    p["layouts"]["records"]["TableARecord"]["key"] = ["id"]
    out = run(node_scripts, shifted(8), p=p)
    assert out["health"]["records"][0]["drift"]["probed"] == 6          # it did probe...
    v = judged(out)
    assert v.drift == [] and not any("MAY HAVE CHANGED" in p_ for p_ in v.problems)    # ...and found nothing to say


def test_a_failure_with_another_cause_is_not_dressed_up_as_drift(node_scripts):
    # The fields read fine at the declared offsets; only the class word is wrong (args[0] is not the object).
    table = Table()
    for i in range(1, 7):
        table.add(i, weight=-i, enabled=i % 2, name=f"n{i}", klass=0)
    v = judged(run(node_scripts, table))
    assert v.status == lc.FAIL and v.drift == []
    assert not any("MAY HAVE CHANGED" in p for p in v.problems)


def test_only_the_first_n_records_are_probed(node_scripts):
    table = shifted(0, n=6)
    out = run(node_scripts, table, p={**params(), "check": {"sample": 3, "gate": False}})
    drift = out["health"]["records"][0]["drift"]
    assert (drift["sample"], drift["probed"]) == (3, 3)
    at_zero = next(t for t in drift["shifts"] if t["shift"] == 0)
    assert at_zero["reads"] == 3 * 4                                  # 3 records x 4 fields, not 6 x 4


def test_a_sample_of_zero_turns_the_probe_off(node_scripts):
    out = run(node_scripts, shifted(8), p={**params(), "check": {"sample": 0, "gate": False}})
    # parseParams treats a non-positive sample as "unset": the default applies - the probe cannot be disabled by accident
    assert out["health"]["records"][0]["drift"]["sample"] == 16
    off = run_harness(node_scripts, shifted(8).mem, mode="canary", record="R", fields=[], sample=0, observations=[])
    assert off["health"]["drift"] is None


def test_probing_wrong_offsets_does_not_spam_the_log(node_scripts):
    # A probe that lands on a pointer to a "string" with an absurd length is expected; it must not log it.
    table = Table(fill=0)
    for i in range(1, 7):
        table.add(i, weight=-i, enabled=i % 2, name=f"n{i}")
        base = RECORD_BASE + (i - 1) * RECORD_STRIDE
        table.mem[base + A_OFFSETS["name"] + 8:base + A_OFFSETS["name"] + 16] = (0x2000).to_bytes(8, "little")
    table.mem[0x2000 + STRING_AT["length_offset"]:0x2000 + STRING_AT["length_offset"] + 4] = (0x7FFFFFFF).to_bytes(4, "little")
    out = run(node_scripts, table)
    assert not any("rejected length" in line for line in out["log"])
    at_plus8 = next(t for t in out["health"]["records"][0]["drift"]["shifts"] if t["shift"] == 8)
    assert at_plus8["bad"] > 0                                         # it WAS read, and judged bad


def test_the_probe_reads_what_the_agent_would_not_report_so_the_export_is_unchanged(node_scripts):
    # Probing must not change what the agent stores or exports.
    out = run(node_scripts, shifted(0))
    assert out["rpc"]["count"] == 6 and [r["id"] for r in out["rpc"]["records"]] == [1, 2, 3, 4, 5, 6]


# ---------------------------------------------------------------------------
# the rule in plain Python (hand-written counts)
# ---------------------------------------------------------------------------

def probe(shifts, probed=6, header=16):
    """A record's `drift` section from {shift: (bad, good)}, every shift fully read."""
    return {"header_size": header, "step": 8, "sample": 16, "probed": probed,
            "shifts": [{"shift": s, "reads": 24, "bad": b, "good": g} for s, (b, g) in sorted(shifts.items())]}


def rec(drift):
    return {"drift": drift}


BASE_BAD = {-8: (12, 6), 0: (11, 7), 8: (12, 6), 16: (12, 6)}


def test_a_unique_fitting_shift_is_measured():
    d = lc.measure_drift(rec(probe({**BASE_BAD, 8: (0, 15)})), 0.05)
    assert d["shift"] == 8 and d["header_measured"] == 24 and d["fit"] == {"bad": 0, "good": 15}
    assert d["baseline"] == {"bad": 11, "good": 7}


def test_two_shifts_that_fit_equally_are_ambiguous_and_no_header_is_claimed():
    d = lc.measure_drift(rec(probe({**BASE_BAD, 8: (0, 15), 16: (0, 15)})), 0.05)
    assert d["shift"] is None and d["candidates"] == [8, 16] and d["header_measured"] is None
    assert "several uniform shifts equally (+8, +16)" in lc._drift_text("R", d)


def test_nothing_is_measured_when_the_declared_offsets_read_fine():
    assert lc.measure_drift(rec(probe({**BASE_BAD, 0: (0, 15), 8: (0, 15)})), 0.05) is None


def test_nothing_is_measured_when_the_declared_offsets_read_as_nothing():
    assert lc.measure_drift(rec(probe({**BASE_BAD, 0: (0, 0), 8: (0, 15)})), 0.05) is None


def test_a_fit_needs_about_one_strong_read_per_probed_record():
    # 0 bad of 3 is a clean fit in rate but thin evidence for 6 records
    assert lc.measure_drift(rec(probe({**BASE_BAD, 8: (0, 3)})), 0.05)["shift"] is None
    assert lc.measure_drift(rec(probe({**BASE_BAD, 8: (0, 6)})), 0.05)["shift"] == 8


def test_a_shift_that_had_to_skip_fields_in_front_of_the_object_proves_nothing():
    drift = probe({**BASE_BAD, 8: (12, 6)})
    drift["shifts"].insert(0, {"shift": -32, "reads": 6, "bad": 0, "good": 6})   # fully clean, but it read 6 of 24
    assert lc.measure_drift(rec(drift), 0.05)["shift"] is None


def test_the_fit_tolerance_follows_the_judge_but_is_clamped():
    drift = probe({**BASE_BAD, 8: (2, 28)})                                       # 6.7 % bad
    assert lc.measure_drift(rec(drift), 0.05)["shift"] is None
    assert lc.measure_drift(rec(drift), 0.10)["shift"] == 8
    loose = probe({**BASE_BAD, 8: (4, 28)})                                       # 12.5 % bad
    assert lc.measure_drift(rec(loose), 0.25)["shift"] is None                    # the gate's 25 % does not loosen the FIT past 10 %


def test_the_report_and_the_exported_meta_carry_the_measurement():
    health = {"version": 1, "records": [{
        "record": "TableARecord", "calls": 6, "read_errors": 0, "key_conflicts": 0, "internal_errors": 0,
        "klass": {"mode": "constant", "checked": 6, "bad_pointer": 0, "other": 0, "variants": [["0x200", 6]]},
        "fields": {"name": {"type": "string", "checked": 6, "violations": 0, "bad": 6, "nulls": 0,
                            "has_expect": False, "examples": ["unreadable (<read error: x>)"], "distinct": 6}},
        "drift": probe({**BASE_BAD, 8: (0, 15)})}]}
    v = lc.judge(health)
    text = "\n".join(lc.render(v))
    assert "LAYOUT MAY HAVE CHANGED" in text and "layout may have changed" in text        # the banner and the measurement
    meta = json.loads(json.dumps(v.as_meta()))
    assert meta["drift"][0]["record"] == "TableARecord" and meta["drift"][0]["header_measured"] == 24


def test_an_agent_without_the_probe_just_fails_as_before():
    health = {"version": 1, "records": [{
        "record": "R", "calls": 6, "read_errors": 6, "key_conflicts": 0, "internal_errors": 0,
        "klass": {"mode": "constant", "checked": 0, "bad_pointer": 0, "other": 0, "variants": []}, "fields": {}}]}
    v = lc.judge(health)
    assert v.status == lc.FAIL and v.drift == []


# ---------------------------------------------------------------------------
# the gate: one snapshot, after the Nth read
# ---------------------------------------------------------------------------

def gate_params(sample, gate=True):
    return {**params(), "check": {"sample": sample, "gate": gate}}


def test_the_agent_sends_one_snapshot_after_the_nth_read(node_scripts):
    out = run(node_scripts, shifted(0, n=6), p=gate_params(4))
    [msg] = out["messages"]
    assert msg["type"] == "layout-sample" and msg["sample"] == 4
    [rec_] = msg["health"]["records"]
    assert rec_["calls"] == 4                                      # the state AT the 4th read, not at the end
    assert out["health"]["records"][0]["calls"] == 6               # and the agent kept collecting
    assert lc.judge_gate(msg["health"]).status == lc.OK


def test_no_snapshot_before_n_reads_and_none_when_the_gate_is_off(node_scripts):
    assert run(node_scripts, shifted(0, n=3), p=gate_params(4))["messages"] == []
    assert run(node_scripts, shifted(0, n=6), p=gate_params(4, gate=False))["messages"] == []
    assert run(node_scripts, shifted(0, n=6))["messages"] == []    # a driver that did not ask (frida -P) gets no messages


def test_failed_reads_count_toward_the_gate(node_scripts):
    table = Table().add_good(2)
    out = run(node_scripts, table, p=gate_params(4), extra_bases=[IMAGE_SIZE - 4] * 3)
    [msg] = out["messages"]
    [rec_] = msg["health"]["records"]
    assert (rec_["calls"], rec_["read_errors"]) == (2, 2)          # 2 good + 2 failed = the 4th attempt
    assert lc.judge_gate(msg["health"]).status == lc.FAIL           # half the attempts failed outright


def test_a_layout_that_moved_fails_the_gate_with_the_measurement(node_scripts):
    out = run(node_scripts, shifted(8, n=8), p=gate_params(8))
    [msg] = out["messages"]
    v = lc.judge_gate(msg["health"])
    assert v.status == lc.FAIL and drift_of(v)["header_measured"] == 24
    assert "the first 8 records already contradict" in "\n".join(lc.render_gate(v, 8))


def test_the_gate_is_looser_than_the_final_check_on_purpose(node_scripts):
    # One stray record in the first 8 (12.5 %) fails the export-time check (5 %) but not the gate.
    table = Table().add_good(7)
    table.add(8, weight=1, enabled=7, name="stray")                # enabled is 0/1 by `expect`
    out = run(node_scripts, table, p=gate_params(8))
    [msg] = out["messages"]
    assert lc.judge_gate(msg["health"]).status == lc.OK
    assert lc.judge(msg["health"]).status == lc.FAIL
    assert lc.judge_gate(msg["health"], tolerance=0.5).tolerance == 0.5          # a looser --layout-tolerance wins
    assert lc.judge_gate(msg["health"]).tolerance == lc.GATE_TOLERANCE


def test_both_dump_agents_take_the_gate_parameters(node_scripts):
    from retk import profiles
    from test_canary import PROFILE, HOOK_OFFSET
    p = {**profiles.agent_params(PROFILE, offsets={"table_b": HOOK_OFFSET}), "check": {"sample": 2, "gate": True}}
    table = Table().add_good(2)
    out = run_harness(node_scripts, table.mem, mode="agent", agent="dump_table_b.js", params=p,
                      events=[{"hook": 0, "args": [b], "retval": 0} for b in table.bases])
    assert len(out["messages"]) == 1 and out["messages"][0]["sample"] == 2


def test_the_canary_options_are_plain_json_in_and_out(node_scripts):
    out = run_harness(node_scripts, Table().add_good(2).mem, mode="canary", record="R", fields=[], headerSize=16,
                      sample=2, gate=True, observations=[{"base": 0x1000, "record": {}}, {"base": 0x1080, "record": {}}])
    assert json.loads(json.dumps(out["health"]))["drift"]["header_size"] == 16
    assert len(out["messages"]) == 1
