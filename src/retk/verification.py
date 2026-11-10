"""
verification.py

Judges what scripts/verify_hook.js saw while it trial-hooked candidate addresses, and
says - per candidate - whether it is VERIFIED, not just "the bytes matched".

retk relocate answers "where did this code go?" by matching bytes. That is
evidence about the CODE, and nothing about whether the address is the function the app
calls, or whether the record that function is handed still looks the way the profile's
layout says. The verification runs the candidate in the app and reads what comes back:

    verified       the hook fired, enough calls returned a record, and every record read
                   through the layout was valid: the class word a real, aligned, mapped
                   pointer and the same one every time, every string readable, every
                   `expect` of the profile kept - and at least one field that could have
                   told right from wrong actually did (a string that read as a string, a
                   varying value that kept its `expect`)
    weak           nothing contradicted the layout, but there is too little to say: fewer
                   than --min-records records, or no field in the record that can tell
                   (all numbers without an `expect`, or strings that were all null)
    rejected       it fired and what it returned contradicts the layout - or it could not
                   be hooked at all (not aligned, not executable, beyond the module). When
                   the class word is fine and the whole layout fits shifted by a uniform
                   amount (layout_check.measure_drift) the report says so: a candidate that
                   is probably RIGHT with a layout that has moved, which is a different
                   problem from a wrong candidate
    not exercised  never called in the time given, or called but every call returned a
                   failure (so no record could be read): there is nothing to judge. Not the
                   same as rejected - the code path may simply not have run
    crashed        the app died with the hook installed. It cannot be attributed to one
                   candidate when several were hooked: run them one at a time

The overall outcome, and the exit status of retk verify:

    verified     exactly one candidate verified                         0
    rejected     every candidate rejected or crashed                    3  (as a failed layout check)
    unverified   anything else: weak, not exercised, or a mix          4
    ambiguous    more than one candidate verified                       5

What "verified" is NOT: a proof that this is THE function the profile meant. Any function
that receives a record of this type and returns success for it - a sibling that unpacks the
same table, a wrapper - verifies the same way, which is why a second verified candidate is
`ambiguous` and not a tie broken quietly. It also inherits the layout canary's blind spot
(layout_check.py): a field with no `expect` that holds a plausible value in the wrong place.
It is a much stronger statement than a byte match, not a different kind of certainty.
"""
from dataclasses import dataclass, field
from typing import Optional

from . import layout_check
VERIFIED, WEAK, REJECTED, NOT_EXERCISED, CRASHED = "verified", "weak", "rejected", "not_exercised", "crashed"
LABELS = {VERIFIED: "VERIFIED", WEAK: "WEAK", REJECTED: "REJECTED", NOT_EXERCISED: "NOT EXERCISED",
          CRASHED: "CRASHED"}
MARKS = {VERIFIED: "[+]", WEAK: "[?]", REJECTED: "[!]", NOT_EXERCISED: "[?]", CRASHED: "[!]"}

DEFAULT_MIN_RECORDS = 3

OUTCOME_VERIFIED, OUTCOME_REJECTED, OUTCOME_UNVERIFIED, OUTCOME_AMBIGUOUS = (
    "verified", "rejected", "unverified", "ambiguous")
EXIT_VERIFIED = 0
EXIT_REJECTED = layout_check.EXIT_LAYOUT_FAILED     # 3: a candidate the layout contradicts, like a failed layout check
EXIT_UNVERIFIED = 4
EXIT_AMBIGUOUS = 5
EXIT_CODES = {OUTCOME_VERIFIED: EXIT_VERIFIED, OUTCOME_REJECTED: EXIT_REJECTED,
              OUTCOME_UNVERIFIED: EXIT_UNVERIFIED, OUTCOME_AMBIGUOUS: EXIT_AMBIGUOUS}


@dataclass
class CandidateVerdict:
    id: str
    rva: int
    status: str
    headline: str                                     # one line: what happened
    label: str = ""                                   # where the candidate came from (the driver's words)
    reasons: list = field(default_factory=list)       # why it was rejected (empty otherwise)
    notes: list = field(default_factory=list)
    evidence: list = field(default_factory=list)      # what a verification stood on
    enters: int = 0                                   # how often the hook fired
    records: int = 0                                  # how many records were read through the layout
    layout_drift: Optional[dict] = None                         # layout_check.measure_drift's finding, when there was one

    def as_json(self):
        return {"id": self.id, "rva": hex(self.rva), "label": self.label, "status": self.status,
                "headline": self.headline, "reasons": list(self.reasons), "notes": list(self.notes),
                "evidence": list(self.evidence), "enters": self.enters, "records": self.records,
                "layout_drift": self.layout_drift}


@dataclass
class Verification:
    outcome: str
    candidates: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    min_records: int = DEFAULT_MIN_RECORDS

    @property
    def exit_code(self):
        return EXIT_CODES[self.outcome]

    def verified(self):
        return [c for c in self.candidates if c.status == VERIFIED]

    def as_json(self):
        return {"outcome": self.outcome, "exit_code": self.exit_code, "min_records": self.min_records,
                "notes": list(self.notes), "candidates": [c.as_json() for c in self.candidates]}


def _plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def _evidence(health):
    """What in a clean record read could actually tell right from wrong: (evidence lines, how many of
    them come from fields rather than from the class word)."""
    lines = []
    klass = health["klass"]
    if klass["checked"] and not klass["bad_pointer"]:
        same = klass["mode"] == "constant" and len(klass["variants"]) == 1 and not klass["other"]
        lines.append(f"class word a valid pointer in all {klass['checked']}" + (" and identical" if same else ""))
    informative = 0
    for name, f in health["fields"].items():
        if f["type"] == "string":
            valid = f["checked"] - f["nulls"] - f["bad"]
            if valid > 0:
                informative += 1
                lines.append(f"{name}: {_plural(valid, 'readable string')}")
        elif f["has_expect"] and f["checked"] and (f["distinct"] is None or f["distinct"] >= 2):
            informative += 1
            lines.append(f"{name}: varies and keeps its `expect`")
    return lines, informative


def judge_candidate(cand, min_records=DEFAULT_MIN_RECORDS, tolerance=layout_check.DEFAULT_TOLERANCE,
                    crashed=None, label=""):
    """The verdict on one candidate of the agent's getVerification() (see scripts/verify_hook.js).
    `crashed` is the reason the session ended abnormally, if it did."""
    base = {"id": cand["id"], "rva": cand["rva"], "label": label, "enters": cand.get("enters", 0)}
    if cand.get("error"):
        return CandidateVerdict(status=REJECTED, headline="could not be hooked", reasons=[cand["error"]], **base)
    if not cand.get("hooked"):
        return CandidateVerdict(status=NOT_EXERCISED, headline="was never hooked: the module did not load",
                                notes=["the agent waits for the module named in the profile; a wrong `module` "
                                       "looks exactly like one that has not loaded yet"], **base)
    if crashed:
        return CandidateVerdict(
            status=CRASHED, headline=f"the app died with this hook installed ({crashed})",
            reasons=["a hook on an address that is not a function entry can crash the app - but so can any "
                     "other hooked candidate; with several hooked it cannot be attributed. Run the "
                     "candidates one at a time (--candidate)"], **base)
    health = cand.get("health") or {}
    if base["enters"] == 0:
        return CandidateVerdict(
            status=NOT_EXERCISED, headline="was never called",
            notes=["either the code path did not run in the time given - use the app so it does (open the "
                   "screen that loads the table) - or this is not a function the app calls"], **base)
    records = health.get("calls", 0)
    if records + health.get("read_errors", 0) == 0:
        return CandidateVerdict(
            status=NOT_EXERCISED,
            headline=f"was called {_plural(base['enters'], 'time')}, but every call returned a failure",
            notes=["no record could be read: either this is not the unpack function, or `0 = success` does not "
                   "hold for this build (unpackFailed in scripts/_lib.js) - the assumption is the same one "
                   "the dump agents make"], **base)

    verdict = layout_check.judge({"version": 1, "records": [health]}, tolerance)
    base["records"] = records
    if verdict.status == layout_check.FAIL:
        drift = verdict.drift[0] if verdict.drift else None
        reasons = list(verdict.problems)
        notes = list(verdict.notes)
        klass_fine = not health["klass"]["bad_pointer"]
        headline = "fired, but what it returned contradicts the layout"
        if drift and drift["shift"] is not None and klass_fine:
            headline = ("fired and hands back an object with a valid class pointer, but the fields fit the layout "
                        f"only shifted by {drift['shift']:+d} bytes")
            notes.append("so this looks like a layout that moved (see LAYOUT MAY HAVE CHANGED above), not a wrong "
                         "candidate: fix the layout, then verify again")
        return CandidateVerdict(status=REJECTED, headline=headline, reasons=reasons, notes=notes,
                                layout_drift=drift, **base)

    evidence, informative = _evidence(health)
    notes = list(verdict.notes)
    if records < min_records:
        return CandidateVerdict(
            status=WEAK, headline=f"fired, nothing contradicts the layout, but only {_plural(records, 'record')} "
                                  f"read (need {min_records})", evidence=evidence, notes=notes, **base)
    if informative == 0:
        return CandidateVerdict(
            status=WEAK,
            headline="fired and nothing contradicts the layout, but nothing in the record could tell right from wrong",
            evidence=evidence,
            notes=notes + ["every field is a number without an `expect`, or a string that read as null: add an "
                           "`expect` to a field you know the values of (docs/MEMORY_LAYOUT.md), or verify on "
                           "a table with filled-in strings"], **base)
    return CandidateVerdict(
        status=VERIFIED,
        headline=f"called {_plural(base['enters'], 'time')}, {_plural(records, 'record')} read through the layout, "
                 f"all of them valid",
        evidence=evidence, notes=notes, **base)


def judge(verification, min_records=DEFAULT_MIN_RECORDS, tolerance=layout_check.DEFAULT_TOLERANCE,
          crashed=None, labels=None, why_missing=None, ended=None):
    """The verdict on everything the agent's getVerification() returned (None when it could not be
    asked). `crashed` is the reason the app died, if it did; `ended` the reason the session ended for
    any other cause (a lost connection); `why_missing` says why the agent could not be asked otherwise."""
    if (not isinstance(verification, dict) or verification.get("version") != 1
            or not isinstance(verification.get("candidates"), list)):
        if crashed:
            note = f"the app died ({crashed}), taking the agent with it"
        elif ended:
            note = f"the session ended ({ended}) before the agent could be asked"
        else:
            note = (f"{why_missing or 'the agent returned no verification'} - rebuild the agents with "
                    f"`npm run build`")
        return Verification(OUTCOME_UNVERIFIED, min_records=min_records, notes=[note])
    labels = labels or {}
    verdicts = [judge_candidate(c, min_records, tolerance, crashed, labels.get(c["id"], ""))
                for c in verification["candidates"]]
    if not verdicts:
        return Verification(OUTCOME_UNVERIFIED, min_records=min_records, notes=["no candidate was given"])

    notes = []
    verified = [v for v in verdicts if v.status == VERIFIED]
    if len(verified) > 1:
        outcome = OUTCOME_AMBIGUOUS
        notes.append(f"{len(verified)} candidates verified: each is a function that receives records this layout fits, "
                     f"so the app cannot tell them apart. Decide by what the functions do (Ghidra), or hook the one "
                     f"you want and compare the records with what the game shows")
    elif len(verified) == 1:
        outcome = OUTCOME_VERIFIED
    elif all(v.status in (REJECTED, CRASHED) for v in verdicts):
        outcome = OUTCOME_REJECTED
    else:
        outcome = OUTCOME_UNVERIFIED
    if outcome in (OUTCOME_VERIFIED, OUTCOME_AMBIGUOUS):
        notes.append("verified = the hook fires and what it returns fits the layout; a sibling function that "
                     "takes the same record type would verify too, and a field with no `expect` is only "
                     "checked structurally")
    return Verification(outcome, verdicts, notes, min_records)


def render(result):
    """The console report, as a list of lines."""
    lines = []
    for v in result.candidates:
        where = f"RVA 0x{v.rva:x}" + (f" ({v.label})" if v.label else "")
        lines.append(f"{MARKS[v.status]} {LABELS[v.status]}  {v.id} {where}: {v.headline}")
        for e in v.evidence:
            lines.append(f"      + {e}")
        for r in v.reasons:
            lines.append(f"      - {r}")
        for n in v.notes:
            lines.append(f"      note: {n}")
    head = {
        OUTCOME_VERIFIED: "[+] VERIFIED - the app calls it, and what it hands back fits the profile's layout.",
        OUTCOME_AMBIGUOUS: "[!] AMBIGUOUS - more than one candidate verified.",
        OUTCOME_REJECTED: "[!] NOT VERIFIED - every candidate was rejected: do not use these offsets.",
        OUTCOME_UNVERIFIED: "[?] NOT VERIFIED - nothing could be confirmed (see each candidate).",
    }[result.outcome]
    lines.append(head)
    lines += [f"    note: {n}" for n in result.notes]
    return lines
