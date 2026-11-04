"""
Tests for dynamic verification: scripts/verify_hook.js trial-hooking candidate addresses,
and retk/verification.py judging what it saw - "verified", not just "the bytes matched".

The agent runs for real under Node against a fake process image (tests/frida_harness.mjs),
and what it exports through getVerification() goes through the real judge. The scenarios are
the questions a relocate result leaves open:

  * the candidate IS the function: it is called, its records fit the layout -> verified;
  * the candidate is a different function: it is called, but args[0] is not a record of
    this layout (bad class word, junk strings) -> rejected;
  * the candidate is right but the layout moved by 8 bytes -> rejected, and the report says
    it is the LAYOUT that moved, not the candidate that is wrong;
  * the candidate is never called -> not exercised (not "rejected": the code path may simply
    not have run), and one that is always called but always "fails" is the same;
  * several candidates at once: each judged on its own calls; two that both verify are
    ambiguous, never quietly resolved;
  * a candidate that cannot be hooked safely (not aligned, beyond the module, not
    executable, not mapped) is refused with the reason, not hooked.

The Node-backed tests skip when `node` isn't installed (and fail when $CI is set).
Run from the repo root:

    pytest
"""
import copy
import json

import pytest

from retk import layout_check as lc
from retk import verification as vf
from node_support import run_harness
from test_canary import IMAGE_SIZE, Table, params

C0, C1, C2 = 0x40, 0x80, 0xC0          # three 4-aligned RVAs inside the fake image


def verify_params(*rvas, record="TableARecord", strip_expect=False, **layout_changes):
    p = copy.deepcopy(params(strip_expect=strip_expect, **layout_changes))
    p["verify"] = {"record": record, "candidates": [{"id": f"c{i}", "rva": r} for i, r in enumerate(rvas)]}
    return p


def calls(hook, table, retval=0):
    return [{"hook": hook, "args": [b], "retval": retval} for b in table.bases]


def verify(node_scripts, table, p, events, **request):
    return run_harness(node_scripts, table.mem, mode="agent", agent="verify_hook.js", params=p, events=events, **request)


def judged(out, **kw):
    return vf.judge(out["verification"], **kw)


def only(result):
    [c] = result.candidates
    return c


# ---------------------------------------------------------------------------
# what the agent counts
# ---------------------------------------------------------------------------

def test_the_agent_hooks_every_candidate_and_counts_what_each_one_did(node_scripts):
    table = Table().add_good(6)
    out = verify(node_scripts, table, verify_params(C0, C1), calls(0, table))
    assert out["attached"] == [C0, C1] and out["initError"] is None
    v = out["verification"]
    assert (v["version"], v["record"], v["module"], v["module_loaded"]) == (1, "TableARecord", "UnityFramework", True)
    c0, c1 = v["candidates"]
    assert (c0["id"], c0["rva"], c0["hooked"], c0["error"]) == ("c0", C0, True, None)
    assert (c0["enters"], c0["leaves"], c0["failed_returns"], c0["health"]["calls"]) == (6, 6, 0, 6)
    assert (c1["enters"], c1["health"]["calls"]) == (0, 0)             # hooked, never called
    assert out["rpc"] is None and out["unreadable"] is None            # it collects and exports nothing


def test_a_call_that_returns_failure_is_counted_and_reads_no_record(node_scripts):
    table = Table().add_good(4)
    out = verify(node_scripts, table, verify_params(C0), calls(0, table, retval=1))
    [c] = out["verification"]["candidates"]
    assert (c["enters"], c["failed_returns"], c["health"]["calls"]) == (4, 4, 0)


def test_the_module_is_waited_for_like_in_every_agent(node_scripts):
    table = Table().add_good(3)
    out = verify(node_scripts, table, verify_params(C0), calls(0, table), moduleAlreadyLoaded=False)
    assert out["verification"]["module_loaded"] is True
    assert out["verification"]["candidates"][0]["health"]["calls"] == 3
    never = verify(node_scripts, table, verify_params(C0), [], moduleAlreadyLoaded=False, moduleNeverLoads=True)
    assert never["verification"]["module_loaded"] is False and never["attached"] == []
    assert never["verification"]["candidates"][0]["hooked"] is False


def test_getVerification_before_init_is_safe(node_scripts):
    out = verify(node_scripts, Table(), None, [])
    assert out["initError"] is not None
    assert out["verification"] == {"version": 1, "record": None, "module": None, "module_loaded": False,
                                   "candidates": []}


@pytest.mark.parametrize("change, message", [
    (lambda p: p.pop("verify"), "no `verify` section"),
    (lambda p: p["verify"].update(candidates=[]), "no `verify` section"),
    (lambda p: p["verify"].update(record="NoSuchRecord"), "no record"),
    (lambda p: p["verify"]["candidates"][0].update(rva=0), "rva is missing or 0"),
    (lambda p: p["verify"]["candidates"][0].update(rva="0x40"), "rva is missing or 0"),
    (lambda p: p["verify"]["candidates"].append({"id": "c0", "rva": C1}), "unique `id`"),
    (lambda p: p.pop("module"), "no `module`"),
    (lambda p: p.pop("layouts"), "no `layouts`"),
])
def test_bad_parameters_are_refused_by_init_with_the_reason(node_scripts, change, message):
    p = verify_params(C0)
    change(p)
    out = verify(node_scripts, Table(), p, [])
    assert message in out["initError"] and out["attached"] == []


# ---------------------------------------------------------------------------
# candidates that are refused instead of hooked
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rva, request_extra, why", [
    (C0 + 2, {}, "not 4-byte aligned"),
    (C0, {"moduleSize": C0}, "beyond the end of UnityFramework"),
    (C0, {"rangeProtections": {str(C0): "rw-"}}, "rw- memory, not executable"),
    (IMAGE_SIZE + 0x100, {}, "not in any mapped range"),
    (C0, {"attachThrows": [C0]}, "could not hook"),
])
def test_a_candidate_that_cannot_be_hooked_safely_is_refused_with_the_reason(node_scripts, rva, request_extra, why):
    table = Table().add_good(3)
    out = verify(node_scripts, table, verify_params(rva), [], **request_extra)
    [c] = out["verification"]["candidates"]
    assert c["hooked"] is False and why in c["error"] and out["attached"] == []
    result = judged(out)
    assert only(result).status == vf.REJECTED and why in only(result).reasons[0]
    assert result.outcome == vf.OUTCOME_REJECTED


def test_off_aarch64_alignment_is_not_a_reason_to_refuse(node_scripts):
    # x86-64 instructions can start anywhere; only arm64 has the 4-byte rule.
    table = Table().add_good(3)
    out = verify(node_scripts, table, verify_params(C0 + 2), calls(0, table), arch="x64")
    [c] = out["verification"]["candidates"]
    assert c["hooked"] is True and c["error"] is None and c["health"]["calls"] == 3


def test_one_refused_candidate_does_not_stop_the_others(node_scripts):
    table = Table().add_good(4)
    out = verify(node_scripts, table, verify_params(C0 + 2, C1), calls(0, table))          # only c1 got attached
    bad, good = out["verification"]["candidates"]
    assert bad["hooked"] is False and good["hooked"] is True and good["health"]["calls"] == 4


# ---------------------------------------------------------------------------
# the verdicts
# ---------------------------------------------------------------------------

def test_the_right_function_with_the_right_layout_is_verified(node_scripts):
    table = Table().add_good(6)
    result = judged(verify(node_scripts, table, verify_params(C0), calls(0, table)))
    c = only(result)
    assert c.status == vf.VERIFIED and result.outcome == vf.OUTCOME_VERIFIED and result.exit_code == 0
    assert (c.enters, c.records) == (6, 6)
    text = "\n".join(vf.render(result))
    assert "VERIFIED" in text and "class word a valid pointer in all 6 and identical" in text
    assert "name: 6 readable strings" in text and "id: varies and keeps its `expect`" in text


def test_a_function_whose_argument_is_not_a_record_is_rejected(node_scripts):
    # Called, returns success - but args[0] is something else: here, the middle of a zero-filled page
    # with no class word and no strings. Exactly what a different function with a similar start does.
    table = Table(fill=0)
    table.add_good(6)
    stray = [{"hook": 0, "args": [0x2000 + 0x80 * i], "retval": 0} for i in range(6)]
    result = judged(verify(node_scripts, table, verify_params(C0), stray))
    c = only(result)
    assert c.status == vf.REJECTED and result.outcome == vf.OUTCOME_REJECTED and result.exit_code == 3
    assert any("not a valid class pointer" in r for r in c.reasons)
    assert c.headline == "fired, but what it returned contradicts the layout"


def test_the_right_function_with_a_moved_layout_is_rejected_as_a_layout_problem(node_scripts):
    table = Table()
    for i in range(1, 7):
        table.add(i, weight=-5 * i, enabled=i % 2, name=f"name-{i}", shift=8)
    result = judged(verify(node_scripts, table, verify_params(C0), calls(0, table)))
    c = only(result)
    assert c.status == vf.REJECTED
    assert c.layout_drift["shift"] == 8 and c.layout_drift["header_measured"] == 24
    assert "valid class pointer, but the fields fit the layout only shifted by +8 bytes" in c.headline
    assert any("looks like a layout that moved" in n for n in c.notes)
    assert any("LAYOUT MAY HAVE CHANGED" in r for r in c.reasons)


def test_a_candidate_that_is_never_called_is_not_exercised_not_rejected(node_scripts):
    table = Table().add_good(3)
    result = judged(verify(node_scripts, table, verify_params(C0), []))
    c = only(result)
    assert c.status == vf.NOT_EXERCISED and result.outcome == vf.OUTCOME_UNVERIFIED and result.exit_code == 4
    assert c.headline == "was never called" and any("use the app" in n for n in c.notes)


def test_a_candidate_whose_every_call_fails_says_which_assumption_to_doubt(node_scripts):
    table = Table().add_good(3)
    c = only(judged(verify(node_scripts, table, verify_params(C0), calls(0, table, retval=1))))
    assert c.status == vf.NOT_EXERCISED and "every call returned a failure" in c.headline
    assert any("unpackFailed" in n for n in c.notes)


def test_too_few_records_is_weak_and_the_threshold_is_the_callers(node_scripts):
    table = Table().add_good(2)
    out = verify(node_scripts, table, verify_params(C0), calls(0, table))
    assert only(judged(out)).status == vf.WEAK                                  # 2 < the default 3
    assert "only 2 records read (need 3)" in only(judged(out)).headline
    assert only(judged(out, min_records=2)).status == vf.VERIFIED


def test_records_with_nothing_that_can_tell_right_from_wrong_are_weak(node_scripts):
    # No `expect`, and every string null: the class word is fine and nothing contradicts the layout -
    # which is all a layout of numbers alone could ever say.
    table = Table()
    for i in range(1, 7):
        table.add(i, weight=-i, enabled=i % 2, name=None)
    out = verify(node_scripts, table, verify_params(C0, strip_expect=True), calls(0, table))
    c = only(judged(out))
    assert c.status == vf.WEAK and "nothing in the record could tell right from wrong" in c.headline
    assert any("add an `expect`" in n for n in c.notes)


def test_one_candidate_that_fits_and_one_that_never_runs_verifies_the_first(node_scripts):
    table = Table().add_good(5)
    result = judged(verify(node_scripts, table, verify_params(C0, C1), calls(0, table)))
    assert [c.status for c in result.candidates] == [vf.VERIFIED, vf.NOT_EXERCISED]
    assert result.outcome == vf.OUTCOME_VERIFIED


def test_two_candidates_that_both_verify_are_ambiguous(node_scripts):
    table = Table().add_good(5)
    events = calls(0, table) + calls(1, table)
    result = judged(verify(node_scripts, table, verify_params(C0, C1), events))
    assert [c.status for c in result.candidates] == [vf.VERIFIED, vf.VERIFIED]
    assert result.outcome == vf.OUTCOME_AMBIGUOUS and result.exit_code == 5
    assert any("cannot tell them apart" in n for n in result.notes)


def test_a_candidate_is_judged_only_on_its_own_calls(node_scripts):
    table = Table().add_good(6)
    stray = [{"hook": 1, "args": [0x2000 + 0x80 * i], "retval": 0} for i in range(6)]
    result = judged(verify(node_scripts, table, verify_params(C0, C1), calls(0, table) + stray))
    assert [c.status for c in result.candidates] == [vf.VERIFIED, vf.REJECTED]


def test_the_results_survive_json_for_the_report_file(node_scripts):
    table = Table().add_good(6)
    result = judged(verify(node_scripts, table, verify_params(C0), calls(0, table)))
    data = json.loads(json.dumps(result.as_json()))
    assert data["outcome"] == "verified" and data["exit_code"] == 0
    assert data["candidates"][0]["rva"] == hex(C0) and data["candidates"][0]["status"] == "verified"


def test_what_the_agent_exports_is_what_the_layout_judge_reads(node_scripts):
    # `health` per candidate is exactly the canary's record health: the same judge, no second set of rules.
    table = Table().add_good(6)
    out = verify(node_scripts, table, verify_params(C0), calls(0, table))
    health = out["verification"]["candidates"][0]["health"]
    assert lc.judge({"version": 1, "records": [health]}).status == lc.OK
