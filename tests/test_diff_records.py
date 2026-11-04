"""
retk diff: a semantic diff of two run_dump.py exports.

Two things are pinned. The RECORD diff - matched by key, never by position; an unreadable field is
never a change; a key that does not identify a record is reported, not diffed - and the SCHEMA-DRIFT
findings: the signs that the two dumps are not two states of one table but one table and one misread,
each made from data that has exactly that sign and nothing else, plus the near-misses that must NOT
raise it (a ratio over four records, an unchanged column, a constant one).

Everything uses the template's made-up fields (id, weight, enabled, name).

Run from the repo root:

    pytest tests/test_diff_records.py
"""
import json
from pathlib import Path

import pytest

from retk import diff_records as dr
from retk import layout_check
REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "profile.example.json"


def rec(i, **over):
    out = {"id": i, "weight": 100 + 7 * i, "enabled": i % 2, "name": f"name-{i}"}
    out.update(over)
    return out


def table(n=20, **over):
    return [rec(i, **over) for i in range(1, n + 1)]


def dump(records, **meta):
    return dr.Dump("x.json", records, meta)


def run(old, new, **kw):
    return dr.diff(dump(old), dump(new), **kw)


def kinds(report, severity=None):
    return [f["kind"] for f in report["schema"]["findings"] if severity in (None, f["severity"])]


def write(tmp_path, name, records, **meta):
    path = tmp_path / name
    path.write_text(json.dumps({"meta": meta, "records": records}), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# the record diff
# ---------------------------------------------------------------------------

def test_identical_tables_have_no_differences_whatever_the_order():
    old = table()
    report = run(old, list(reversed(old)))
    assert report["summary"] == {"added": 0, "removed": 0, "changed": 0, "unchanged": 20, "inconclusive": 0}
    assert dr.status(report) == dr.EXIT_SAME and kinds(report) == []


def test_added_removed_and_changed_records_are_found_by_key_not_position():
    old, new = table(), table()
    new[2]["name"] = "renamed"                                   # id 3
    new[10]["weight"], new[10]["enabled"] = 7, 0                 # id 11 (enabled was 1)
    removed = new.pop(5)                                         # id 6
    new.insert(0, rec(99))                                       # added, and everything shifted position
    report = run(old, new, key=["id"])
    assert report["summary"] == {"added": 1, "removed": 1, "changed": 2, "unchanged": 17, "inconclusive": 0}
    assert report["added"] == [rec(99)] and report["removed"] == [removed]
    by_key = {c["key"]["id"]: c["changes"] for c in report["changed"]}
    assert by_key[3] == [{"field": "name", "old": "name-3", "new": "renamed"}]
    assert by_key[11] == [{"field": "weight", "old": 177, "new": 7}, {"field": "enabled", "old": 1, "new": 0}]
    assert dr.status(report) == dr.EXIT_DIFFERENT and not report["schema"]["drift"]


def test_one_and_one_point_zero_are_the_same_value_but_true_is_not_one():
    old, new = [rec(1, enabled=1)], [rec(1, enabled=1.0)]
    assert run(old, new, key=["id"])["summary"]["changed"] == 0
    assert run([rec(1, enabled=1)], [rec(1, enabled=True)], key=["id"])["summary"]["changed"] == 1


def test_a_field_one_dump_could_not_read_is_inconclusive_never_a_change():
    old, new = table(), table()
    new[0]["name"] = None
    new[0]["_unreadable"] = ["name"]                             # what the agents write for an unreadable string
    new[1]["weight"] = 1                                         # a real change next to it
    report = run(old, new, key=["id"])
    # only id 2 differs for sure; id 1 could be compared in part (weight, enabled the same) and counts as unchanged
    assert report["summary"] == {"added": 0, "removed": 0, "changed": 1, "unchanged": 19, "inconclusive": 1}
    assert [c["key"]["id"] for c in report["changed"]] == [2]
    only = dr.diff(dump([rec(1)]), dump([rec(1, name=None, _unreadable=["name"])]), key=["id"])
    assert only["summary"] == {"added": 0, "removed": 0, "changed": 0, "unchanged": 1, "inconclusive": 1}
    assert dr.status(only) == dr.EXIT_SAME                       # nothing was shown to differ


def test_unreadable_on_both_sides_is_not_even_inconclusive():
    both = dict(name=None, _unreadable=["name"])
    report = dr.diff(dump([rec(1, **both)]), dump([rec(1, **both)]), key=["id"])
    assert report["summary"]["inconclusive"] == 0 and report["summary"]["unchanged"] == 1


def test_ignored_fields_are_left_out_of_the_comparison_and_the_drift_findings():
    old, new = table(), table()
    for r in new:
        r["weight"] += 1
    assert run(old, new, key=["id"])["summary"]["changed"] == 20
    quiet = run(old, new, key=["id"], ignore={"weight"})
    assert quiet["summary"]["changed"] == 0 and "systematic_change" not in kinds(quiet)


def test_a_repeated_key_is_reported_and_the_last_record_is_the_one_compared():
    old = table(3)
    new = table(3) + [rec(2, name="twice")]
    report = run(old, new, key=["id"])
    [problem] = report["problems"]
    assert (problem["kind"], problem["dump"], problem["count"], problem["key"]) == ("duplicate_key", "new", 2, {"id": 2})
    assert report["changed"][0]["changes"] == [{"field": "name", "old": "name-2", "new": "twice"}]


def test_a_record_without_the_key_field_is_an_error_naming_the_dump():
    with pytest.raises(dr.DiffError, match="a record has no field id"):
        dr.diff(dump(table(2)), dump([{"weight": 1}]), key=["id"])


# ---------------------------------------------------------------------------
# which field is the key
# ---------------------------------------------------------------------------

def test_a_key_is_inferred_as_the_unique_field_most_records_share():
    old, new = table(), table()
    new[4]["name"] = "different"                                 # name is unique too, but id overlaps more
    report = run(old, new)
    assert report["key"] == {"fields": ["id"], "source": "inferred"}


def test_a_pair_of_fields_is_inferred_when_no_single_one_is_unique():
    def rows(offset):
        return [{"kind": k, "level": lv, "value": (k + lv) % 3 + offset} for k in (1, 2) for lv in (1, 2, 3)]
    report = run(rows(0), rows(1))
    assert report["key"]["fields"] == ["kind", "level"] and report["summary"]["changed"] == 6


def test_no_key_to_infer_is_an_error_that_says_what_to_do():
    flat = [{"a": 1}, {"a": 1}]
    with pytest.raises(dr.DiffError, match="pass --key"):
        dr.diff(dump(flat), dump(flat))
    with pytest.raises(dr.DiffError, match="no records"):
        dr.diff(dump([]), dump(table()))


def test_the_key_can_come_from_the_profiles_layout(tmp_path):
    report = run(table(), table(), profile=str(EXAMPLE), record="TableARecord")
    assert report["key"] == {"fields": ["id"], "source": "profile"}
    # no --record: the layout record whose fields are the dumps' fields is the one
    assert run(table(), table(), profile=str(EXAMPLE))["key"]["fields"] == ["id"]


def test_a_profile_that_does_not_settle_the_key_says_so(tmp_path):
    with pytest.raises(dr.DiffError, match="no record 'Nope'"):
        run(table(), table(), profile=str(EXAMPLE), record="Nope")
    odd = [{"alpha": 1, "beta": 2}]
    with pytest.raises(dr.DiffError, match="no record matches the dumps' fields"):
        dr.diff(dump(odd), dump(odd), profile=str(EXAMPLE))
    with pytest.raises(dr.DiffError):
        run(table(), table(), profile=str(tmp_path / "missing.json"))


# ---------------------------------------------------------------------------
# schema drift
# ---------------------------------------------------------------------------

def test_changed_data_alone_is_not_drift():
    old, new = table(), table()
    for r in new[:6]:
        r["weight"] += 1                                         # 30% of the records: ordinary balancing
    report = run(old, new, key=["id"])
    assert not report["schema"]["drift"] and dr.status(report) == dr.EXIT_DIFFERENT
    assert kinds(report) == []


def test_a_field_that_is_gone_or_new_is_drift():
    old = table()
    new = [{k: v for k, v in r.items() if k != "weight"} for r in table()]
    new = [dict(r, extra=1) for r in new]
    report = run(old, new, key=["id"])
    assert set(kinds(report, dr.BREAKING)) == {"field_removed", "field_added"}
    assert dr.status(report) == dr.EXIT_DRIFT


def test_a_field_that_changes_kind_is_drift():
    new = table()
    for r in new:
        r["weight"] = str(r["weight"])
    report = run(table(), new, key=["id"])
    [f] = [f for f in report["schema"]["findings"] if f["kind"] == "type_changed"]
    assert (f["field"], f["old"], f["new"], f["severity"]) == ("weight", "number", "string", dr.BREAKING)


def test_a_field_that_became_mostly_null_is_drift_but_one_that_stayed_nullable_is_not():
    new = table()
    for r in new[:15]:
        r["name"] = None
    assert "null_rate" in kinds(run(table(), new, key=["id"]), dr.BREAKING)
    nullable = table()
    for r in nullable[:4]:
        r["name"] = None
    both = run(nullable, [dict(r) for r in nullable], key=["id"])
    assert "null_rate" not in kinds(both)


def test_strings_turning_to_junk_is_drift_and_a_few_odd_ones_are_not():
    junk = table()
    for r in junk[:10]:
        r["name"] = "\x01\x02\ufffd" + r["name"]
    assert "garbled_strings" in kinds(run(table(), junk, key=["id"]), dr.BREAKING)
    few = table()
    few[0]["name"] = "\x01"
    assert "garbled_strings" not in kinds(run(table(), few, key=["id"]))
    tabs = table()
    for r in tabs:
        r["name"] += "\tx\n"                                     # whitespace is printable text, not junk
    assert "garbled_strings" not in kinds(run(table(), tabs, key=["id"]))


def test_a_field_with_few_values_now_holding_other_ones_is_drift_but_one_new_value_is_a_warning():
    shifted = table()
    for r in shifted:
        r["enabled"] = 7 + r["id"] % 3                           # old domain {0, 1}; 100% outside it
    report = run(table(), shifted, key=["id"])
    [f] = [f for f in report["schema"]["findings"] if f["kind"] == "domain_shift"]
    assert f["severity"] == dr.BREAKING and f["field"] == "enabled"
    grown = table()
    grown[0]["enabled"] = 2                                      # a new enum member: data, not schema
    report = run(table(), grown, key=["id"])
    assert "new_values" in kinds(report, dr.WARNING) and not report["schema"]["drift"]


def test_values_that_moved_to_another_field_are_found_even_when_the_names_stayed():
    # the layout shifted by one field: what `weight` held, `enabled` now reads (and so on)
    old = [{"id": i, "weight": 10 * i, "enabled": i % 2, "rank": 3 * i + 1} for i in range(1, 21)]
    new = [{"id": i, "weight": 99, "enabled": 10 * i, "rank": i % 2} for i in range(1, 21)]
    report = run(old, new, key=["id"])
    moved = {(f["field"], f["to"]) for f in report["schema"]["findings"] if f["kind"] == "field_moved"}
    assert ("weight", "enabled") in moved and ("enabled", "rank") in moved
    assert dr.status(report) == dr.EXIT_DRIFT


def test_an_unchanged_column_or_a_constant_one_is_not_a_move():
    old = [{"id": i, "a": i, "b": i, "c": 5} for i in range(1, 21)]       # b duplicates a; c is constant
    new = [{"id": i, "a": i, "b": i, "c": 5} for i in range(1, 21)]
    assert kinds(run(old, new, key=["id"])) == []
    new2 = [{"id": i, "a": i, "b": 100 + i, "c": 5} for i in range(1, 21)]  # b changed; a's values are not in b
    assert "field_moved" not in kinds(run(old, new2, key=["id"]))


def test_every_field_changing_in_nearly_every_record_is_drift():
    new = [{"id": i, "weight": -1 * i, "enabled": 5, "name": f"other-{i}"} for i in range(1, 21)]
    report = run(table(), new, key=["id"])
    assert "all_fields_changed" in kinds(report, dr.BREAKING)
    assert "systematic_change" not in kinds(report)               # said once, as the bigger finding


def test_one_field_changing_everywhere_is_a_warning_not_drift():
    new = table()
    for r in new:
        r["weight"] += 3
    report = run(table(), new, key=["id"])
    assert kinds(report, dr.WARNING) == ["systematic_change"] and not report["schema"]["drift"]
    assert dr.status(report) == dr.EXIT_DIFFERENT


def test_ratios_need_enough_shared_records_to_mean_anything():
    old, new = table(4), [dict(r, weight=r["weight"] + 1, name="x", enabled=9) for r in table(4)]
    report = run(old, new, key=["id"])
    assert kinds(report, dr.WARNING) == [] and "all_fields_changed" not in kinds(report) and "field_moved" not in kinds(report)


def test_a_field_ten_thousand_times_bigger_is_a_magnitude_warning():
    new = table()
    for r in new:
        r["weight"] *= 1000
    assert "magnitude_shift" in kinds(run(table(), new, key=["id"]), dr.WARNING)


def test_a_table_that_halved_or_barely_overlaps_is_a_warning():
    report = run(table(20), table(20)[:8], key=["id"])
    assert "count_shift" in kinds(report, dr.WARNING)
    other = [rec(i) for i in range(100, 120)]
    report = run(table(20), other, key=["id"])
    assert "low_key_overlap" in kinds(report, dr.WARNING) and not report["schema"]["drift"]


def test_a_dump_whose_own_layout_check_failed_makes_the_diff_untrustworthy():
    failed = dump(table(), layout_check={"status": layout_check.FAIL, "problems": ["TableARecord: bad class word"]})
    report = dr.diff(failed, dump(table()), key=["id"])
    [f] = [f for f in report["schema"]["findings"] if f["kind"] == "suspect_dump"]
    assert f["severity"] == dr.BREAKING and f["dump"] == "old" and "bad class word" in f["detail"]
    gated = dump(table(), suspect=True)
    assert "suspect_dump" in kinds(dr.diff(dump(table()), gated, key=["id"]), dr.BREAKING)
    unverified = dump(table(), layout_check={"status": layout_check.UNVERIFIED})
    report = dr.diff(unverified, dump(table()), key=["id"])
    assert kinds(report, dr.INFO) == ["layout_unverified"] and not report["schema"]["drift"]


def test_breaking_findings_come_first():
    new = [{"id": i, "weight": 1, "enabled": 5, "name": "x"} for i in range(1, 6)]
    severities = [f["severity"] for f in run(table(20), new, key=["id"])["schema"]["findings"]]
    assert severities == sorted(severities, key={"breaking": 0, "warning": 1, "info": 2}.get)


def test_the_build_part_of_meta_is_summarised_as_differences():
    old = dump(table(), target="a", offsets={"table_a": "0x10", "table_b": "0x30"}, dumped_at="then")
    new = dump(table(), target="b", offsets={"table_a": "0x20", "table_b": "0x30"}, dumped_at="now")
    assert dr.diff(old, new, key=["id"])["build"] == ["target: a -> b", "offsets.table_a: 0x10 -> 0x20"]


# ---------------------------------------------------------------------------
# loading and the command line
# ---------------------------------------------------------------------------

def test_a_bare_list_of_records_is_accepted(tmp_path):
    path = tmp_path / "bare.json"
    path.write_text(json.dumps(table(3)), encoding="utf-8")
    loaded = dr.load_dump(str(path))
    assert len(loaded.records) == 3 and loaded.meta == {}


@pytest.mark.parametrize("text, why", [("{not json", "not valid JSON"), ('{"meta": {}}', "not a run_dump.py export"),
                                       ("[1, 2]", "record 0 is int"), ("5", "not a run_dump.py export")])
def test_a_file_that_is_not_an_export_is_a_one_line_error(tmp_path, text, why):
    path = tmp_path / "bad.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(dr.DiffError, match=why):
        dr.load_dump(str(path))
    with pytest.raises(dr.DiffError):
        dr.load_dump(str(tmp_path / "missing.json"))


def test_the_cli_prints_the_diff_and_exits_1_when_the_dumps_differ(tmp_path, capsys):
    old, new = table(), table()
    new[2]["name"] = "renamed"
    code = dr.main([write(tmp_path, "old.json", old), write(tmp_path, "new.json", new), "--key", "id"])
    out = capsys.readouterr().out
    assert code == dr.EXIT_DIFFERENT
    assert "[+] 0 added, 0 removed, 1 changed, 19 unchanged" in out
    assert '~ changed id=3  name "name-3" -> "renamed"' in out


def test_the_cli_exits_0_with_a_sentence_when_nothing_differs(tmp_path, capsys):
    code = dr.main([write(tmp_path, "a.json", table()), write(tmp_path, "b.json", table())])
    assert code == dr.EXIT_SAME and "The two dumps hold the same records." in capsys.readouterr().out


def test_the_cli_exits_3_and_leads_with_the_drift_when_the_shape_changed(tmp_path, capsys):
    new = [{k: v for k, v in r.items() if k != "weight"} for r in table()]
    code = dr.main([write(tmp_path, "a.json", table()), write(tmp_path, "b.json", new), "--key", "id"])
    out = capsys.readouterr().out
    assert code == dr.EXIT_DRIFT and "SCHEMA DRIFT" in out and "[field_removed] weight is in the old records" in out


def test_the_cli_says_when_the_key_was_inferred(tmp_path, capsys):
    dr.main([write(tmp_path, "a.json", table()), write(tmp_path, "b.json", table())])
    assert "key: id  (inferred - pass --key or --profile to be sure)" in capsys.readouterr().out
    dr.main([write(tmp_path, "a.json", table()), write(tmp_path, "b.json", table()), "--key", "id"])
    assert "key: id  (cli)" in capsys.readouterr().out


def test_limit_caps_the_detail_but_not_the_counts_and_the_json_has_everything(tmp_path, capsys):
    old, new = table(30), [dict(r, weight=r["weight"] + (1 if r["id"] % 2 else 0)) for r in table(30)]
    out_json = tmp_path / "diff_records_t.json"
    code = dr.main([write(tmp_path, "a.json", old), write(tmp_path, "b.json", new), "--key", "id", "--limit", "3",
                    "--json", str(out_json)])
    out = capsys.readouterr().out
    assert code == dr.EXIT_DIFFERENT
    assert "[+] 0 added, 0 removed, 15 changed, 15 unchanged" in out and "... and 12 more changed" in out
    assert out.count("~ changed") == 3
    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert len(report["changed"]) == 15 and report["version"] == dr.REPORT_VERSION
    assert report["key"] == {"fields": ["id"], "source": "cli"} and report["schema"]["drift"] is False


def test_limit_zero_prints_counts_only(tmp_path, capsys):
    new = table()
    new[0]["name"] = "x"
    dr.main([write(tmp_path, "a.json", table()), write(tmp_path, "b.json", new), "--key", "id", "--limit", "0"])
    out = capsys.readouterr().out
    assert "1 changed" in out and "~ changed" not in out and "... and 1 more changed" in out


@pytest.mark.parametrize("argv, why", [
    (["--key", "id", "--profile", "p"], "use one"),
    (["--record", "R"], "--record names a record of --profile"),
    (["--key", ","], "--key is empty"),
])
def test_contradictory_options_are_usage_errors(tmp_path, capsys, argv, why):
    with pytest.raises(SystemExit) as e:
        dr.main([write(tmp_path, "a.json", table()), write(tmp_path, "b.json", table()), *argv])
    assert e.value.code == 2 and why in capsys.readouterr().err


def test_unusable_input_exits_2_with_one_error_line(tmp_path, capsys):
    code = dr.main([str(tmp_path / "missing.json"), write(tmp_path, "b.json", table())])
    err = capsys.readouterr().err
    assert code == dr.EXIT_USAGE and err.startswith("[!] ") and "Traceback" not in err


def test_json_outside_gitignore_is_warned_about(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("retk._common.is_gitignored", lambda path: False)
    dr.main([write(tmp_path, "a.json", table()), write(tmp_path, "b.json", table()), "--json", str(tmp_path / "out.json")])
    assert "is NOT covered by .gitignore" in capsys.readouterr().out


def test_the_repos_gitignore_covers_the_diff_output():
    lines = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "diff_records*.json" in lines


def test_a_real_export_roundtrips_through_the_diff(tmp_path):
    """The shape run_dump.export_records writes: a meta block the diff reads, records with _unreadable."""
    meta = {"profile": "p", "target": "t", "module": "m", "agent": "dump_table_a.js", "offsets": {"table_a": "0x40"},
            "layout_check": {"status": layout_check.OK, "problems": [], "notes": []}, "layout_gate": None,
            "suspect": False, "unreadable_count": 0, "unreadable_records": []}
    old = write(tmp_path, "records_old.json", table(), **meta)
    new = write(tmp_path, "records_new.json", table(), **dict(meta, offsets={"table_a": "0x48"}))
    assert dr.main([old, new]) == dr.EXIT_SAME
