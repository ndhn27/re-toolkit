"""
Tests for retk/verification.py: turning what scripts/verify_hook.js counted into a verdict on
each candidate - verified, weak, rejected, not exercised, crashed - and into an overall outcome
and exit status.

Pure Python: the counts are written by hand here, in the shape getVerification() returns them
(tests/test_verify_hook.py runs the real agent and feeds its real counts through the same judge).
What is pinned is the RULE, and above all what a "verified" is allowed to mean: the hook fired,
enough records were read, nothing contradicted the layout, and at least one field that could
have told right from wrong did - and that two verified candidates are ambiguous, never a tie
broken quietly.

Run from the repo root:

    pytest
"""
import json

import pytest

from retk import layout_check as lc
from retk import verification as vf
def field(type_="u32", checked=6, violations=0, bad=0, nulls=0, has_expect=True, distinct=6):
    out = {"type": type_, "checked": checked, "violations": violations, "bad": bad, "nulls": nulls,
           "has_expect": has_expect, "examples": [], "distinct": distinct}
    if type_ != "string":
        out.update(min=1, max=6)
    return out


def health(calls=6, read_errors=0, bad_pointer=0, variants=None, fields=None, drift=None):
    variants = [["0x200", calls]] if variants is None else variants
    return {
        "record": "TableARecord", "calls": calls, "read_errors": read_errors, "key_conflicts": 0,
        "internal_errors": 0,
        "klass": {"mode": "constant", "checked": calls, "bad_pointer": bad_pointer, "other": 0, "variants": variants},
        "fields": fields if fields is not None else {"id": field(checked=calls),
                                                     "name": field("string", checked=calls)},
        "drift": drift,
    }


def cand(id_="c0", rva=0x1234, enters=6, hooked=True, error=None, failed_returns=0, h="default"):
    return {"id": id_, "rva": rva, "hooked": hooked, "error": error, "enters": enters, "leaves": enters,
            "failed_returns": failed_returns, "health": health() if h == "default" else h}


def snap(*cands, module_loaded=True):
    return {"version": 1, "record": "TableARecord", "module": "UnityFramework", "module_loaded": module_loaded,
            "candidates": list(cands)}


def one(result):
    [c] = result.candidates
    return c


# --- a candidate -----------------------------------------------------------------

def test_a_clean_run_with_enough_records_and_something_to_tell_is_verified():
    result = vf.judge(snap(cand()))
    c = one(result)
    assert c.status == vf.VERIFIED and result.outcome == vf.OUTCOME_VERIFIED and result.exit_code == 0
    assert (c.enters, c.records, c.reasons) == (6, 6, [])
    assert c.evidence == ["class word a valid pointer in all 6 and identical", "id: varies and keeps its `expect`",
                          "name: 6 readable strings"]


def test_the_class_word_alone_is_never_enough():
    # Every field a number with no `expect`: nothing in the record could tell right from wrong.
    fields = {"id": field(has_expect=False), "weight": field("s32", has_expect=False)}
    c = one(vf.judge(snap(cand(h=health(fields=fields)))))
    assert c.status == vf.WEAK and "nothing in the record could tell right from wrong" in c.headline
    assert c.evidence == ["class word a valid pointer in all 6 and identical"]


def test_strings_that_are_all_null_say_nothing_either():
    fields = {"name": field("string", nulls=6)}
    assert one(vf.judge(snap(cand(h=health(fields=fields))))).status == vf.WEAK


def test_a_constant_value_that_keeps_its_expect_is_not_evidence():
    fields = {"id": field(distinct=1)}                       # one value in every record: could be anything
    assert one(vf.judge(snap(cand(h=health(fields=fields))))).status == vf.WEAK


def test_a_value_that_varies_by_a_lot_is_evidence_even_when_its_distinct_count_was_capped():
    fields = {"id": field(distinct=None)}                    # more than 32 distinct values: the agent stops counting
    assert one(vf.judge(snap(cand(h=health(fields=fields))))).status == vf.VERIFIED


@pytest.mark.parametrize("records, status", [(2, vf.WEAK), (3, vf.VERIFIED)])
def test_the_number_of_records_decides_between_weak_and_verified(records, status):
    c = one(vf.judge(snap(cand(h=health(calls=records)))))
    assert c.status == status
    if status == vf.WEAK:
        assert "only 2 records read (need 3)" in c.headline


def test_min_records_is_the_callers():
    assert one(vf.judge(snap(cand(h=health(calls=2))), min_records=2)).status == vf.VERIFIED
    assert one(vf.judge(snap(cand(h=health(calls=9))), min_records=10)).status == vf.WEAK


def test_a_layout_that_is_contradicted_rejects_the_candidate_with_the_layout_judges_reasons():
    c = one(vf.judge(snap(cand(h=health(bad_pointer=6)))))
    assert c.status == vf.REJECTED and any("not a valid class pointer" in r for r in c.reasons)
    assert c.layout_drift is None


def test_the_tolerance_is_the_layout_judges():
    fields = {"id": field(violations=1), "name": field("string")}
    assert one(vf.judge(snap(cand(h=health(fields=fields))))).status == vf.REJECTED
    assert one(vf.judge(snap(cand(h=health(fields=fields))), tolerance=0.2)).status == vf.VERIFIED


def drift_probe(fit_shift=8):
    shifts = {s: (12, 6) for s in (-8, 0, 8, 16)}
    shifts[fit_shift] = (0, 15)
    return {"header_size": 16, "step": 8, "sample": 16, "probed": 6,
            "shifts": [{"shift": s, "reads": 24, "bad": b, "good": g} for s, (b, g) in sorted(shifts.items())]}


def test_a_candidate_that_fires_with_a_valid_class_word_but_a_moved_layout_is_a_layout_problem():
    fields = {"id": field(violations=6), "name": field("string", bad=6)}
    c = one(vf.judge(snap(cand(h=health(fields=fields, drift=drift_probe())))))
    assert c.status == vf.REJECTED and c.layout_drift["shift"] == 8
    assert "valid class pointer, but the fields fit the layout only shifted by +8 bytes" in c.headline
    assert any("not a wrong candidate" in n for n in c.notes)


def test_a_moved_layout_with_a_bad_class_word_is_still_a_wrong_candidate():
    fields = {"id": field(violations=6), "name": field("string", bad=6)}
    c = one(vf.judge(snap(cand(h=health(bad_pointer=6, fields=fields, drift=drift_probe())))))
    assert c.status == vf.REJECTED and c.headline == "fired, but what it returned contradicts the layout"
    assert not any("not a wrong candidate" in n for n in c.notes)


def test_a_candidate_that_could_not_be_hooked_is_rejected_with_the_agents_reason():
    c = one(vf.judge(snap(cand(hooked=False, error="RVA 0x1235 is not 4-byte aligned", enters=0, h=None))))
    assert c.status == vf.REJECTED and c.headline == "could not be hooked"
    assert c.reasons == ["RVA 0x1235 is not 4-byte aligned"]


def test_a_candidate_that_was_never_called_is_not_exercised_and_the_note_says_what_to_do():
    c = one(vf.judge(snap(cand(enters=0, h=health(calls=0, fields={})))))
    assert c.status == vf.NOT_EXERCISED and c.headline == "was never called"
    assert any("use the app" in n for n in c.notes)


def test_a_module_that_never_loaded_is_not_exercised():
    c = one(vf.judge(snap(cand(hooked=False, enters=0, h=None), module_loaded=False)))
    assert c.status == vf.NOT_EXERCISED and "module did not load" in c.headline
    assert any("wrong `module`" in n for n in c.notes)


def test_every_call_failing_is_not_exercised_and_names_the_assumption():
    c = one(vf.judge(snap(cand(enters=5, failed_returns=5, h=health(calls=0, fields={})))))
    assert c.status == vf.NOT_EXERCISED and "every call returned a failure" in c.headline
    assert any("unpackFailed" in n for n in c.notes)


def test_a_crash_is_attributed_to_every_hooked_candidate_and_never_to_a_refused_one():
    result = vf.judge(snap(cand("c0"), cand("c1", rva=0x2000), cand("c2", rva=0x2002, hooked=False, error="not aligned", h=None)),
                      crashed="process-terminated")
    assert [c.status for c in result.candidates] == [vf.CRASHED, vf.CRASHED, vf.REJECTED]
    assert "one at a time" in result.candidates[0].reasons[0]
    assert result.outcome == vf.OUTCOME_REJECTED and result.exit_code == 3


# --- the outcome ---------------------------------------------------------------------

def test_one_verified_among_others_is_verified():
    result = vf.judge(snap(cand("c0"), cand("c1", enters=0, h=health(calls=0, fields={}))))
    assert [c.status for c in result.candidates] == [vf.VERIFIED, vf.NOT_EXERCISED]
    assert result.outcome == vf.OUTCOME_VERIFIED and result.verified()[0].id == "c0"


def test_two_verified_is_ambiguous_and_says_why_it_cannot_be_decided_here():
    result = vf.judge(snap(cand("c0"), cand("c1", rva=0x2000)))
    assert result.outcome == vf.OUTCOME_AMBIGUOUS and result.exit_code == 5
    assert any("cannot tell them apart" in n for n in result.notes)


def test_all_rejected_is_rejected_but_one_not_exercised_keeps_it_open():
    rejected = cand("c0", h=health(bad_pointer=6))
    assert vf.judge(snap(rejected, cand("c1", h=health(bad_pointer=6)))).outcome == vf.OUTCOME_REJECTED
    mixed = vf.judge(snap(rejected, cand("c1", enters=0, h=health(calls=0, fields={}))))
    assert mixed.outcome == vf.OUTCOME_UNVERIFIED and mixed.exit_code == 4


def test_weak_is_unverified_not_a_pass():
    result = vf.judge(snap(cand(h=health(calls=2))))
    assert result.outcome == vf.OUTCOME_UNVERIFIED and result.exit_code == vf.EXIT_UNVERIFIED


@pytest.mark.parametrize("bad", [None, {}, {"version": 2, "candidates": []}, {"version": 1}, "x"])
def test_an_agent_that_cannot_say_is_unverified(bad):
    result = vf.judge(bad, why_missing="could not ask the agent (boom)")
    assert result.outcome == vf.OUTCOME_UNVERIFIED and result.candidates == []
    assert any("boom" in n and "npm run build" in n for n in result.notes)


def test_an_app_that_died_before_it_could_be_asked_says_so():
    result = vf.judge(None, crashed="process-terminated")
    assert any("the app died (process-terminated)" in n for n in result.notes)
    assert not any("npm run build" in n for n in result.notes)                 # the agent is fine; the app is gone


def test_a_lost_connection_is_not_blamed_on_the_agent_build():
    result = vf.judge(None, ended="connection-terminated")
    assert result.notes == ["the session ended (connection-terminated) before the agent could be asked"]


def test_no_candidate_at_all_is_unverified():
    assert vf.judge(snap()).outcome == vf.OUTCOME_UNVERIFIED


def test_exit_codes_are_distinct_and_the_rejection_matches_a_failed_layout():
    assert vf.EXIT_VERIFIED == 0 and vf.EXIT_REJECTED == lc.EXIT_LAYOUT_FAILED == 3
    assert len({vf.EXIT_VERIFIED, vf.EXIT_REJECTED, vf.EXIT_UNVERIFIED, vf.EXIT_AMBIGUOUS}) == 4


# --- the report ------------------------------------------------------------------------

def test_the_report_names_each_candidate_what_it_stood_on_and_the_caveat():
    result = vf.judge(snap(cand("c0")), labels={"c0": "relocate HIGH, file offset 0x1000"})
    text = "\n".join(vf.render(result))
    assert "[+] VERIFIED  c0 RVA 0x1234 (relocate HIGH, file offset 0x1000)" in text
    assert "+ name: 6 readable strings" in text
    assert "[+] VERIFIED - the app calls it" in text
    assert "a sibling function that takes the same record type would verify too" in text


def test_a_rejection_is_loud_and_lists_the_reasons():
    text = "\n".join(vf.render(vf.judge(snap(cand(h=health(bad_pointer=6))))))
    assert text.startswith("[!] REJECTED  c0") and "- TableARecord: the word at +0" in text
    assert "NOT VERIFIED - every candidate was rejected: do not use these offsets" in text


def test_the_result_survives_json():
    result = vf.judge(snap(cand("c0"), cand("c1", rva=0x2000, enters=0, h=None)))
    data = json.loads(json.dumps(result.as_json()))
    assert data["outcome"] == "verified" and data["exit_code"] == 0
    assert [(c["id"], c["rva"], c["status"]) for c in data["candidates"]] == [
        ("c0", "0x1234", "verified"), ("c1", "0x2000", "not_exercised")]
