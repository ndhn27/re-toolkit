"""
layout_check.py

Judges what scripts/_canary.js counted while an agent was reading records, and
says whether the profile's layout matched the build it ran against.

A layout is a hypothesis found by reading memory (see docs/MEMORY_LAYOUT.md),
and nothing used to test it on the build it was later run on: when a build moved
a field - or the object header wasn't what the layout assumed - the agent kept
reading the wrong bytes at the right addresses and wrote plausible-looking
garbage to records.json without a word. The agent now counts, record by record,
how often the data contradicted the layout (scripts/_canary.js documents what is
checked); this module turns the counts into a verdict, so the rule is plain
Python that a test can pin and `--layout-tolerance` can change.

    ok          nothing contradicted the layout (the notes say how much that proves)
    fail        too many reads contradicted it: the dump should not be trusted
    unverified  nothing could be checked (no record was read, or the agent can't say)
    skipped     --no-layout-check

A check FAILS when more than `tolerance` of the reads that were subject to it
violated it (default 5 %; 0 means a single violation fails). Small tables make
that strict on purpose: one bad record out of four is 25 %. The one exception is
key conflicts - the same key re-sent with different contents - which also happen
when the app legitimately updates a record, so they only fail the layout when
they are the majority (a wrong `key` or a wrong offset under it makes nearly
every read conflict); fewer are reported as a note.

Layout drift. When a check fails, the agent's first-N probe (scripts/_canary.js:
every offset shifted by -32..+32 bytes, in steps of 8) says whether the data would
fit if the WHOLE layout had moved. A build that grew or shrank the object header
moves every field by the same amount, and then the report says so - "LAYOUT MAY
HAVE CHANGED: the fields fit 8 bytes further in, the header would be 24 bytes, not
16" - instead of just "failed". It is a diagnosis, never applied automatically: a
shift is claimed only when it is the ONLY one that fits (at most DRIFT_FIT_MAX of
its informative reads bad, and about one strong read per probed record), because a
guess that looks like a fix is how a dump of plausible garbage gets made.

The same judge runs on the snapshot the agent sends after the first N records
(`judge_gate`, retk dump --layout-gate): a table of N records is a noisy
sample, so the gate uses the looser GATE_TOLERANCE - it is there to stop a layout
that is wrong about almost everything, not to second-guess one stray record; the
export-time judgement with `--layout-tolerance` still decides the final verdict.

Field offsets from the runtime. When the profile names a record's fields (`names.fields`, README.md's
"Looking things up by name"), the agent also asks the IL2CPP runtime where each of them is
(scripts/_resolve.js) and its health carries `field_offsets`. Those are not samples: the runtime
states the offset, so ONE mismatch fails the check whatever the tolerance, and a match is
noted as confirmed directly. A field the runtime could not be asked about is a note, never a verdict.

What a pass does NOT mean: the structural checks cannot see a layout that is
wrong in a way that keeps every value plausible (two u32 fields swapped that
both hold small numbers). Only `expect` in the profile narrows that, and only
for the fields it covers; the notes list the fields that have none.
"""
from dataclasses import dataclass, field

DEFAULT_TOLERANCE = 0.05
GATE_TOLERANCE = 0.25            # judging the first N records: stop only when a quarter of them (or more) are wrong
DEFAULT_GATE = 16                # --layout-gate: how many of the first reads are judged early
DRIFT_FIT_MIN = 0.05             # a shift "fits" when at most this share of its informative reads are bad -
DRIFT_FIT_MAX = 0.10             # the judge's own tolerance, clamped into [MIN, MAX]
KEY_CONFLICT_FAIL = 0.5          # a majority of reads conflicting: the key (or what is under it) is wrong
MIN_CONSTANCY_SAMPLE = 2         # records needed before "the class word is the same in all" means anything
MIN_CONSTANT_FIELD_SAMPLE = 4    # records needed before "this field never varies" is worth mentioning
EXIT_LAYOUT_FAILED = 3           # run_dump.py's exit status when the verdict is `fail`

OK, FAIL, UNVERIFIED, SKIPPED = "ok", "fail", "unverified", "skipped"


@dataclass
class Verdict:
    status: str
    problems: list = field(default_factory=list)      # why it failed (empty unless status == fail)
    notes: list = field(default_factory=list)         # what a reader should know even when it didn't
    tolerance: float = DEFAULT_TOLERANCE
    records: list = field(default_factory=list)       # the agent's raw counts, kept for the export's meta
    drift: list = field(default_factory=list)         # measured shifts (see measure_drift), one per record that has one

    def as_meta(self):
        """JSON-able form, for the exported file's `meta.layout_check`."""
        return {"status": self.status, "tolerance": self.tolerance, "problems": list(self.problems),
                "notes": list(self.notes), "drift": list(self.drift), "records": self.records}


def _pct(part, whole):
    return f"{part} of {whole} ({100 * part / whole:.0f}%)"


def _fields_summary(rec):
    """`id [1..4], name` - the fields the profile has no `expect` for, with the range seen."""
    parts = []
    for name, f in rec["fields"].items():
        if f["has_expect"] or not f["checked"]:
            continue
        if f["type"] != "string" and f.get("min") is not None:
            seen = f"{f['min']}" if f["min"] == f["max"] else f"{f['min']}..{f['max']}"
            parts.append(f"{name} [{seen}]")
        else:
            parts.append(name)
    return parts


def _rate(bad, good):
    """Share of the informative reads that were bad, or None when nothing was informative."""
    return bad / (bad + good) if bad + good else None


def measure_drift(rec, tolerance):
    """Has the whole layout moved? Judges the agent's drift probe for one record
    (`rec["drift"]`: per shift, how many field reads looked like data and how many
    did not - see scripts/_canary.js).

    Returns None when there is nothing to say: no probe, the declared offsets read
    fine, or they read as nothing at all (a null string and a zero say nothing, so
    a probe over zeroed memory can neither blame the layout nor clear it). Else a
    dict: `shift` (the one shift that fits, or None), `candidates` (every shift that
    fits - more than one means the data cannot tell them apart, and `shift` is None),
    `header_declared` / `header_measured` (the object header the profile assumes
    and, with a unique shift, the one the data suggests), `baseline` / `fit`
    ({bad, good} at the declared offsets / at `shift`) and `probed`."""
    drift = rec.get("drift")
    if not isinstance(drift, dict) or not drift.get("probed"):
        return None
    shifts = {t["shift"]: t for t in drift.get("shifts", [])}
    base = shifts.get(0)
    if base is None:
        return None
    base_rate = _rate(base["bad"], base["good"])
    fit_tolerance = min(max(tolerance, DRIFT_FIT_MIN), DRIFT_FIT_MAX)
    if base_rate is None or base_rate <= fit_tolerance:
        return None
    probed = drift["probed"]
    full = max(t["reads"] for t in shifts.values())          # a shift that had to skip fields (in front of the object) proves nothing
    fits = []
    for shift, t in sorted(shifts.items()):
        rate = _rate(t["bad"], t["good"])
        if (shift != 0 and t["reads"] == full and rate is not None and rate <= fit_tolerance
                and t["good"] >= max(2, probed)):
            fits.append(shift)
    header = drift.get("header_size")
    out = {"shift": fits[0] if len(fits) == 1 else None, "candidates": fits, "probed": probed,
           "header_declared": header, "header_measured": None,
           "baseline": {"bad": base["bad"], "good": base["good"]}, "fit": None}
    if len(fits) == 1:
        t = shifts[fits[0]]
        out["fit"] = {"bad": t["bad"], "good": t["good"]}
        if header is not None:
            out["header_measured"] = header + fits[0]
    return out


def _signed(n):
    return f"{n:+d}"


def _drift_text(name, d):
    """The problem line (or note) that says what measure_drift() found for record `name`."""
    base, fit = d["baseline"], d["fit"]
    if d["shift"] is not None:
        shift = d["shift"]
        where = f"{abs(shift)} bytes {'further in' if shift > 0 else 'earlier'}"
        header = ""
        if d["header_measured"] is not None:
            header = (f" - the object header would be {d['header_measured']} bytes, not the "
                      f"{d['header_declared']} the layout assumes")
        return (f"{name}: LAYOUT MAY HAVE CHANGED - the fields fit when read {where}{header}. "
                f"At the declared offsets {base['bad']} of {base['bad'] + base['good']} informative reads "
                f"in the first {d['probed']} record(s) are wrong; at {_signed(shift)} only "
                f"{fit['bad']} of {fit['bad'] + fit['good']} are. If so, `headerSize` and every offset move by "
                f"{_signed(shift)}; this is a measurement, nothing was applied - confirm it in the layout "
                f"(docs/METHODOLOGY.md) before using it")
    if len(d["candidates"]) > 1:
        shifts = ", ".join(_signed(s) for s in d["candidates"])
        return (f"{name}: LAYOUT MAY HAVE CHANGED - the declared offsets read wrong, and the data fits "
                f"several uniform shifts equally ({shifts}) - too uniform to say which")
    return (f"{name}: LAYOUT MAY HAVE CHANGED - the declared offsets read wrong in the first {d['probed']} "
            f"record(s), and no uniform shift of -32..+32 bytes explains it: single fields moved, or "
            f"args[0] is not the record the layout describes")


def _judge_record(rec, tolerance, drifts=None):
    """(problems, notes, checked) for one record type; `checked` is False when nothing could be tested.
    A measured drift (measure_drift) is added to the problems and appended to `drifts` (when given)."""
    name, calls, read_errors = rec["record"], rec["calls"], rec["read_errors"]
    problems, notes = [], []
    attempts = calls + read_errors

    if attempts == 0:
        return problems, [f"{name}: no record was read, so there was nothing to check"], False

    if read_errors:
        text = (f"{name}: {_pct(read_errors, attempts)} reads failed outright - an unmapped address, "
                f"i.e. a wrong offset, or args[0] is not the record the layout describes")
        (problems if read_errors / attempts > tolerance else notes).append(text)
    if calls == 0:
        return problems, notes, True

    klass = rec["klass"]
    if klass["bad_pointer"]:
        text = (f"{name}: the word at +0 is not a valid class pointer in {_pct(klass['bad_pointer'], calls)} "
                f"records - is args[0] the object the layout describes, and is the object header what "
                f"the layout assumed?")
        if klass["bad_pointer"] / calls > tolerance:
            problems.append(text)
        else:
            notes.append(text)
    if klass["mode"] == "constant":
        if klass["checked"] < MIN_CONSTANCY_SAMPLE:
            notes.append(f"{name}: only {klass['checked']} record(s) read, so the class word's constancy "
                         f"(the header check) could not be tested")
        else:
            counts = [c for _, c in klass["variants"]]
            modal = max(counts) if counts else 0
            off = klass["checked"] - modal
            if off / klass["checked"] > tolerance:
                problems.append(
                    f"{name}: the class word at +0 is not the same in every record ({_pct(off, klass['checked'])} "
                    f"differ from the most common one; {len(klass['variants']) + bool(klass['other'])} distinct) - "
                    f"either the table holds several classes (set `klass: \"pointer\"` in the layout) or "
                    f"args[0] / the object header is not what the layout assumes")

    # Nothing varying at all is the signature of reading the wrong place (zeroed
    # memory, one repeated value) - but also of an app that has unpacked just one
    # record so far, so it can only be a note.
    read_fields = [f for f in rec["fields"].values() if f["checked"]]
    all_constant = (calls >= MIN_CONSTANT_FIELD_SAMPLE and bool(read_fields)
                    and all(f["distinct"] == 1 for f in read_fields))
    if all_constant:
        notes.append(f"{name}: every field read identically in all {calls} reads - either the app has only "
                     f"unpacked one record so far, or the layout is reading something that is not the data "
                     f"(wrong object, wrong offsets)")

    for fname, f in rec["fields"].items():
        checked = f["checked"]
        if not checked:
            continue
        label = f"{name}.{fname}"
        if f["bad"]:
            text = f"{label}: {_pct(f['bad'], checked)} reads are not a valid string ({f['examples'][0] if f['examples'] else '?'})"
            (problems if f["bad"] / checked > tolerance else notes).append(text)
        if f["violations"]:
            text = f"{label}: {_pct(f['violations'], checked)} reads break the profile's `expect` ({f['examples'][0] if f['examples'] else '?'})"
            (problems if f["violations"] / checked > tolerance else notes).append(text)
        if all_constant:
            continue
        if f["type"] == "string" and f["nulls"] == checked and checked >= MIN_CONSTANT_FIELD_SAMPLE:
            notes.append(f"{label}: null in all {checked} records - fine if the field is unused, "
                         f"but a string offset that is wrong often reads as null")
        elif (not f["has_expect"] and f["distinct"] == 1 and checked >= MIN_CONSTANT_FIELD_SAMPLE
              and f["type"] != "string"):
            notes.append(f"{label}: {f['min']} in all {checked} records - fine if the field really never "
                         f"varies, but a misplaced offset often reads as a constant")

    kc = rec["key_conflicts"]
    if kc:
        text = (f"{name}: {_pct(kc, calls)} reads re-sent a key with different contents - an update from the "
                f"app, or `key` does not identify a record")
        (problems if kc / calls > KEY_CONFLICT_FAIL else notes).append(text)
    if rec.get("internal_errors"):
        notes.append(f"{name}: the canary itself failed {rec['internal_errors']} time(s); those reads were not checked")

    unchecked = _fields_summary(rec)
    if unchecked:
        notes.append(f"{name}: no `expect` for {', '.join(unchecked)} - these are only checked structurally, "
                     f"so a wrong offset that still yields plausible values would pass")
    if calls < MIN_CONSTANT_FIELD_SAMPLE:
        notes.append(f"{name}: only {calls} record(s) read - a small sample proves little")
    if problems:
        d = measure_drift(rec, tolerance)
        if d is not None:
            problems.append(_drift_text(name, d))
            if drifts is not None:
                drifts.append({"record": name, **d})
    return problems, notes, True


def _judge_field_offsets(rows):
    """(problems, notes, checked) for the agent's `field_offsets` - see the module docstring."""
    if not isinstance(rows, list):
        return [], [], False
    problems, matched, unresolved = [], 0, {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        where = f"{row.get('record')}.{row.get('field')}"
        status = row.get("status")
        if status == "mismatch":
            problems.append(
                f"layout field {where} is at 0x{row.get('layout_offset', 0):x} in the profile, but the IL2CPP "
                f"runtime puts {row.get('il2cpp_field')} at 0x{row.get('runtime_offset', 0):x}")
        elif status == "match":
            matched += 1
        else:
            unresolved.setdefault(str(row.get("reason") or "no reason given"), []).append(where)
    notes = []
    if matched:
        notes.append(f"{matched} layout field offset(s) confirmed directly by the IL2CPP runtime (names.fields)")
    for reason, where in unresolved.items():
        notes.append(f"{len(where)} layout field offset(s) could not be checked against the runtime "
                     f"({', '.join(where)}): {reason}")
    return problems, notes, bool(matched or problems)


def judge(health, tolerance=DEFAULT_TOLERANCE, why_missing=None):
    """The verdict on `health`, what the agent's getHealth() returned (None when
    it couldn't be asked; `why_missing` then says why)."""
    if (not isinstance(health, dict) or health.get("version") != 1
            or not isinstance(health.get("records"), list)):
        reason = why_missing or "the agent returned no layout health"
        return Verdict(UNVERIFIED, tolerance=tolerance,
                       notes=[f"{reason} - agents built before the layout check have no getHealth(); "
                              f"rebuild them with `npm run build`"])
    if not health["records"]:
        return Verdict(UNVERIFIED, tolerance=tolerance, notes=["the agent reported no record type to check"])

    problems, notes, drifts, any_checked = [], [], [], False
    for rec in health["records"]:
        p, n, checked = _judge_record(rec, tolerance, drifts)
        problems += p
        notes += n
        any_checked = any_checked or checked
    p, n, checked = _judge_field_offsets(health.get("field_offsets"))
    problems += p
    notes += n
    any_checked = any_checked or checked
    status = FAIL if problems else (OK if any_checked else UNVERIFIED)
    return Verdict(status, problems, notes, tolerance, health["records"], drifts)


def judge_gate(health, tolerance=DEFAULT_TOLERANCE):
    """The verdict on the snapshot an agent sends after its first N records (see the
    module docstring): the same judge, with the looser GATE_TOLERANCE unless the
    caller asked for an even looser one."""
    return judge(health, max(tolerance, GATE_TOLERANCE))


def render_gate(verdict, sample):
    """The console report for a gate verdict (judge_gate on the first `sample` reads), as a list of lines."""
    if verdict.status == FAIL:
        lines = [f"[!] LAYOUT MAY HAVE CHANGED - the first {sample} records already contradict the "
                 f"profile's layout:"]
        lines += [f"      - {p}" for p in verdict.problems]
        return lines
    if verdict.status == OK:
        return [f"[+] The first {sample} records fit the profile's layout (the full check runs at export)."]
    return [f"[?] The first {sample} records could not be checked ({'; '.join(verdict.notes) or 'no detail'})."]


def skipped(tolerance=DEFAULT_TOLERANCE):
    return Verdict(SKIPPED, tolerance=tolerance, notes=["--no-layout-check: the layout was not checked"])


def render(verdict):
    """The console report, as a list of lines."""
    if verdict.status == FAIL:
        lines = ["[!] LAYOUT CHECK FAILED - the layout may have changed: what the agent read contradicts "
                 "the profile's layout, so this dump is probably garbage:"]
        lines += [f"      - {p}" for p in verdict.problems]
        lines += ["    Re-derive the layout for this build (see docs/METHODOLOGY.md), or - if the checks are "
                  "wrong for this table, not the layout - correct `expect` / `klass` in the profile or "
                  "relax --layout-tolerance."]
    elif verdict.status == OK:
        lines = ["[+] Layout check passed: nothing the agent read contradicted the profile's layout."]
    elif verdict.status == SKIPPED:
        lines = ["[?] Layout check skipped (--no-layout-check) - this dump's layout is unverified."]
    else:
        lines = ["[?] Layout NOT verified - nothing could be checked."]
    lines += [f"    note: {n}" for n in verdict.notes if verdict.status != SKIPPED]
    return lines
