"""
Tests for retk/layout_check.py: turning what scripts/_canary.js counted into
a verdict on the profile's layout.

Pure Python - the counts are written by hand here, in the shape getHealth()
returns them (tests/test_canary.py runs the real agents and feeds their real
counts through the same judge). What is pinned is the RULE: which counts fail a
layout, which are only worth a note, how --layout-tolerance moves the line, and
what the report says. The shape of the claim matters as much as the threshold:
a pass is "not contradicted", never "correct", and the notes must say where the
check was blind.

Run from the repo root:

    pytest
"""
import json

import pytest

from retk import layout_check as lc
def field(type_="u32", checked=6, violations=0, bad=0, nulls=0, has_expect=True, examples=(),
          distinct=6, min_=1, max_=6):
    out = {"type": type_, "checked": checked, "violations": violations, "bad": bad, "nulls": nulls,
           "has_expect": has_expect, "examples": list(examples), "distinct": distinct}
    if type_ != "string":
        out.update(min=min_, max=max_)
    return out


def record(name="TableARecord", calls=6, read_errors=0, key_conflicts=0, bad_pointer=0, variants=None,
           other=0, mode="constant", fields=None, internal_errors=0, **extra):
    variants = [["0x200", calls]] if variants is None else variants
    return {
        "record": name, "calls": calls, "read_errors": read_errors, "key_conflicts": key_conflicts,
        "internal_errors": internal_errors,
        "klass": {"mode": mode, "checked": calls, "bad_pointer": bad_pointer, "other": other,
                  "variants": variants},
        "fields": fields if fields is not None else {
            "id": field(),
            "enabled": field("s8", distinct=2, min_=0, max_=1),
            "name": field("string", distinct=6),
        },
        **extra,
    }


def health(*records):
    return {"version": 1, "records": list(records)}


def judge(*records, **kw):
    return lc.judge(health(*records), **kw)


# --- a clean read -----------------------------------------------------------

def test_a_table_that_matches_its_layout_passes_without_problems():
    v = judge(record())
    assert v.status == lc.OK and v.problems == []
    assert lc.render(v)[0].startswith("[+] Layout check passed")


def test_a_pass_still_says_which_fields_nothing_checked():
    fields = {"id": field(), "weight": field("s32", has_expect=False, min_=-25, max_=0, distinct=6),
              "tag": field("string", has_expect=False)}
    v = judge(record(fields=fields))
    assert v.status == lc.OK
    [note] = [n for n in v.notes if "no `expect`" in n]
    assert "weight [-25..0]" in note and "tag" in note and "id" not in note
    assert "plausible" in note                   # says what that blindness costs


def test_a_small_sample_is_flagged_as_proving_little():
    v = judge(record(calls=2, fields={"id": field(checked=2, distinct=2)}))
    assert v.status == lc.OK
    assert any("only 2 record(s) read" in n for n in v.notes)


def test_one_record_cannot_show_the_class_word_is_constant():
    v = judge(record(calls=1, fields={"id": field(checked=1, distinct=1)}))
    assert v.status == lc.OK
    assert any("constancy" in n for n in v.notes)


# --- what fails -------------------------------------------------------------

def test_a_class_word_that_is_not_a_pointer_fails():
    v = judge(record(bad_pointer=6))
    assert v.status == lc.FAIL
    assert any("not a valid class pointer" in p and "6 of 6" in p for p in v.problems)


def test_a_class_word_that_differs_between_records_fails_and_names_the_way_out():
    v = judge(record(variants=[["0x200", 3], ["0x300", 2], ["0x400", 1]]))
    assert v.status == lc.FAIL
    [p] = [p for p in v.problems if "not the same in every record" in p]
    assert "3 of 6" in p and "3 distinct" in p and 'klass: "pointer"' in p


def test_pointer_mode_accepts_several_classes():
    v = judge(record(mode="pointer", variants=[["0x200", 3], ["0x300", 3]]))
    assert v.status == lc.OK


def test_pointer_mode_still_rejects_a_bad_pointer():
    assert judge(record(mode="pointer", bad_pointer=2)).status == lc.FAIL


def test_expect_violations_fail_and_quote_the_first_example():
    fields = {"enabled": field("s8", violations=3, examples=["-18 is not one of 0, 1"], distinct=3)}
    v = judge(record(fields=fields))
    assert v.status == lc.FAIL
    assert any("TableARecord.enabled" in p and "3 of 6" in p and "-18 is not one of 0, 1" in p
               for p in v.problems)


def test_unreadable_strings_fail():
    fields = {"name": field("string", bad=4, examples=["unreadable (<read error: access violation>)"])}
    v = judge(record(fields=fields))
    assert v.status == lc.FAIL
    assert any("TableARecord.name" in p and "not a valid string" in p for p in v.problems)


def test_reads_that_throw_fail():
    v = judge(record(calls=3, read_errors=3))
    assert v.status == lc.FAIL
    assert any("3 of 6" in p and "reads failed outright" in p for p in v.problems)


def test_reads_that_all_throw_still_fail_with_nothing_else_to_look_at():
    v = judge(record(calls=0, read_errors=4, fields={}))
    assert v.status == lc.FAIL and len(v.problems) == 1


def test_one_failing_record_type_fails_the_whole_verdict():
    v = judge(record(), record("TableBRecord", bad_pointer=6))
    assert v.status == lc.FAIL
    assert all("TableBRecord" in p for p in v.problems)


# --- key conflicts ----------------------------------------------------------

def test_most_reads_conflicting_on_their_key_means_the_key_is_wrong():
    v = judge(record(key_conflicts=5))
    assert v.status == lc.FAIL
    assert any("5 of 6" in p and "does not identify a record" in p for p in v.problems)


def test_an_occasional_conflict_is_an_update_not_a_verdict():
    # The app re-sends a record with new contents: legitimate, worth a note.
    v = judge(record(key_conflicts=1))
    assert v.status == lc.OK
    assert any("re-sent a key with different contents" in n for n in v.notes)


def test_exactly_half_conflicting_is_not_yet_a_failure():
    assert judge(record(key_conflicts=3)).status == lc.OK
    assert judge(record(key_conflicts=4)).status == lc.FAIL


# --- tolerance --------------------------------------------------------------

def test_one_bad_record_in_six_fails_by_default_and_passes_when_tolerated():
    fields = {"name": field("string", bad=1, examples=["control character U+0001 at index 2"])}
    assert judge(record(fields=fields)).status == lc.FAIL
    tolerated = judge(record(fields=fields), tolerance=0.2)
    assert tolerated.status == lc.OK
    assert any("control character" in n for n in tolerated.notes)      # still reported, as a note


def test_the_default_tolerates_a_stray_read_in_a_large_table():
    fields = {"enabled": field("s8", checked=100, violations=4, examples=["7 is not one of 0, 1"],
                               distinct=3)}
    assert judge(record(calls=100, fields=fields, variants=[["0x200", 100]])).status == lc.OK
    fields["enabled"]["violations"] = 6
    assert judge(record(calls=100, fields=fields, variants=[["0x200", 100]])).status == lc.FAIL


def test_the_tolerance_itself_is_still_within_tolerance():
    # "More than 5 %" fails; exactly 5 % does not - on every kind of check.
    def one_in_twenty(**kw):
        return record(calls=20, variants=[["0x200", 20]],
                      fields={"enabled": field("s8", checked=20, distinct=2, examples=["7 is not one of 0, 1"], **kw)})

    assert judge(one_in_twenty(violations=1)).status == lc.OK
    assert judge(one_in_twenty(violations=2)).status == lc.FAIL
    assert judge(one_in_twenty(bad=1)).status == lc.OK
    assert judge(one_in_twenty(bad=2)).status == lc.FAIL
    assert judge(record(calls=20, variants=[["0x200", 19], ["0x300", 1]],
                        fields={"id": field(checked=20)})).status == lc.OK
    assert judge(record(calls=20, variants=[["0x200", 18], ["0x300", 2]],
                        fields={"id": field(checked=20)})).status == lc.FAIL
    assert judge(record(calls=19, read_errors=1, variants=[["0x200", 19]],
                        fields={"id": field(checked=19)})).status == lc.OK
    assert judge(record(calls=18, read_errors=2, variants=[["0x200", 18]],
                        fields={"id": field(checked=18)})).status == lc.FAIL


def test_zero_tolerance_means_a_single_violation_fails():
    fields = {"enabled": field("s8", checked=100, violations=1, examples=["7 is not one of 0, 1"],
                               distinct=3)}
    rec = record(calls=100, fields=fields, variants=[["0x200", 100]])
    assert judge(rec, tolerance=0).status == lc.FAIL
    assert judge(rec, tolerance=0.05).status == lc.OK


def test_the_tolerance_is_recorded_in_the_verdict():
    assert judge(record(), tolerance=0.2).tolerance == 0.2


# --- blind spots stay visible -----------------------------------------------

def test_nothing_varying_at_all_is_a_note_not_a_failure():
    # Zeroed memory read through a shifted layout looks like this - and so does an
    # app that has unpacked a single record six times. The judge can't tell them
    # apart, so it must say so rather than guess.
    fields = {"id": field(distinct=1, min_=0, max_=0, has_expect=False),
              "name": field("string", distinct=1, nulls=6, has_expect=False)}
    v = judge(record(fields=fields))
    assert v.status == lc.OK
    assert any("every field read identically in all 6 reads" in n for n in v.notes)
    # ...once, not once per field
    assert sum("identically" in n or "in all 6 records" in n for n in v.notes) == 1


def test_a_single_constant_field_is_pointed_out():
    fields = {"id": field(), "weight": field("s32", distinct=1, min_=0, max_=0, has_expect=False)}
    v = judge(record(fields=fields))
    assert any("TableARecord.weight: 0 in all 6 records" in n for n in v.notes)


def test_a_string_field_that_is_always_null_is_pointed_out():
    fields = {"id": field(), "name": field("string", nulls=6, distinct=1, has_expect=False)}
    v = judge(record(fields=fields))
    assert any("TableARecord.name: null in all 6 records" in n for n in v.notes)


def test_a_failing_canary_is_not_mistaken_for_a_clean_read():
    v = judge(record(internal_errors=2))
    assert any("canary itself failed 2 time(s)" in n for n in v.notes)


# --- nothing to judge -------------------------------------------------------

def test_no_records_read_is_unverified_not_ok():
    v = judge(record(calls=0, fields={}))
    assert v.status == lc.UNVERIFIED
    assert any("nothing to check" in n for n in v.notes)


@pytest.mark.parametrize("bad", [None, {}, {"version": 2, "records": []}, {"version": 1}, "ok", []])
def test_an_agent_that_cannot_say_is_unverified(bad):
    v = lc.judge(bad)
    assert v.status == lc.UNVERIFIED
    assert any("npm run build" in n for n in v.notes)


def test_why_it_could_not_be_asked_is_in_the_note():
    v = lc.judge(None, why_missing="could not ask the agent (unable to find method 'getHealth')")
    assert any("getHealth" in n for n in v.notes)


def test_an_agent_with_no_record_type_is_unverified():
    assert lc.judge(health()).status == lc.UNVERIFIED


def test_skipped_says_so_and_prints_no_notes():
    v = lc.skipped(0.1)
    assert (v.status, v.tolerance) == (lc.SKIPPED, 0.1)
    assert len(lc.render(v)) == 1 and "skipped" in lc.render(v)[0]


# --- the report -------------------------------------------------------------

def test_a_failure_is_loud_lists_every_problem_and_the_notes_too():
    fields = {"enabled": field("s8", violations=6, examples=["-18 is not one of 0, 1"]),
              "weight": field("s32", has_expect=False, min_=-5, max_=0)}
    lines = lc.render(judge(record(bad_pointer=6, fields=fields)))
    text = "\n".join(lines)
    assert lines[0].startswith("[!] LAYOUT CHECK FAILED")
    assert "garbage" in lines[0]
    assert "not a valid class pointer" in text and "TableARecord.enabled" in text
    assert "note: " in text and "weight" in text
    assert "docs/METHODOLOGY.md" in text and "--layout-tolerance" in text


def test_the_verdict_survives_json_so_it_can_go_in_the_export():
    v = judge(record(bad_pointer=6))
    meta = json.loads(json.dumps(v.as_meta()))
    assert meta["status"] == "fail" and meta["tolerance"] == lc.DEFAULT_TOLERANCE
    assert meta["problems"] and meta["records"][0]["record"] == "TableARecord"


def test_the_exit_status_for_a_failed_layout_is_distinct():
    assert lc.EXIT_LAYOUT_FAILED == 3            # 1 = crash, 2 = usage errors elsewhere in retk/
