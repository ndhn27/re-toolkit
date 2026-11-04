"""
Tests for relocate_offset.py's anchors: the extra windows of the old build that are
searched for on their own in the new one and vote on where the hook point went.

  * body windows      - code deeper inside the function (a known distance behind the hook point)
  * call sites        - the code around each `bl <hook point>` of the old build; its vote is where
                        that `bl` lands in the new build
  * forward window    - for a hook point in the middle of a function: the code after it

The votes can only lower a grade (an anchor found in one place that points elsewhere -> LOW; a
window of the function's code that is no longer where it should be -> at most MEDIUM) or settle a
tie between candidates. TestFiveScenarioRegression replays, unchanged, the five situations that
exposed the original backward-fingerprint algorithm (see test_relocate_function_entry.py for why
they matter) and asserts that all of them still come out right with the anchors on, off, and for
the code anchors alone - and that the same five checks do catch the original algorithm.

Run from the repo root: `pytest`.
"""
import copy
import random
import re
import struct
import sys

import pytest
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

from retk import relocate_offset as ro
import synth_image as si
from binfmt_fixtures import CODE, S_CSTRING_LITERALS, build_macho

NOP, RET = si.NOP, si.RET
STP, MOV_FP, LDP = si.STP_FP_LR, si.MOV_FP_SP, si.LDP_FP_LR
BLR = 0xD63F0100                       # blr x8
WORD_MASK = ro.WORD_MASK
IMM12 = 0x003FFC00
BL_MASK = 0xFC000000

_MD_DETAIL = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
_MD_DETAIL.detail = True


def pack(words):
    return struct.pack(f"<{len(words)}I", *words)


def write_bin(tmp_path, words, name="build.bin"):
    path = tmp_path / name
    path.write_bytes(pack(words))
    return str(path)


def fill(n, salt=0):
    """n distinct position-independent words (add x1, x2, #imm) that write only x1."""
    return [si.add_imm(1, 2, 1 + 64 * salt + i) for i in range(n)]


def decode_run(words, base=0x1000):
    return [next(_MD_DETAIL.disasm(struct.pack("<I", w), base + 4 * i)) for i, w in enumerate(words)]


def run_main(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["relocate_offset.py", *map(str, argv)])
    try:
        ro.main()
        code = 0
    except SystemExit as e:
        code = e.code
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def fake_anchor(kind, label=None):
    return ro.Fingerprint("after", [(0, WORD_MASK)], 0, kind=kind, label=label or kind)


# --------------------------------------------------------------------------
# Fingerprint: what an anchor carries
# --------------------------------------------------------------------------

def test_a_fingerprint_is_labelled_by_its_kind_unless_named():
    assert ro.Fingerprint("after", [(0, WORD_MASK)], 0).label == "entry"
    assert ro.Fingerprint.from_bytes(pack([NOP] * 4)).kind == "before"
    assert fake_anchor("body", "body +0x10").label == "body +0x10"


def test_wildcarded_words_are_counted():
    fp = ro.Fingerprint("after", [(1, WORD_MASK), (2, BL_MASK), (3, BL_MASK)], 0)
    assert fp.n_wildcarded == 2


# --------------------------------------------------------------------------
# build_body_anchors()
# --------------------------------------------------------------------------

class TestBodyAnchors:
    @staticmethod
    def entry(n=16, complete=False):
        return ro.Fingerprint("after", [(0, WORD_MASK)] * n, 0, complete=complete)

    @staticmethod
    def run_of(n, replace=None):
        words = fill(n)
        for i, w in (replace or {}).items():
            words[i] = w
        insns = decode_run(words)
        return insns, ro.wildcard_masks(insns), words

    def test_a_long_function_gets_a_window_in_the_middle_and_one_at_the_end(self):
        insns, masks, words = self.run_of(42)

        mid, last = ro.build_body_anchors(insns, masks, self.entry(), min_instrs=4)

        assert (mid.kind, mid.label, mid.hook_delta) == ("body", "body +0x64", -4 * 25)
        assert (last.kind, last.label, last.hook_delta) == ("body", "body +0x88", -4 * 34)
        assert [v for v, _ in mid.words] == words[25:33] and [v for v, _ in last.words] == words[34:42]
        assert mid.xref is None and not mid.complete

    def test_a_medium_function_gets_only_the_window_at_the_end(self):
        insns, masks, _ = self.run_of(30)

        (last,) = ro.build_body_anchors(insns, masks, self.entry(), min_instrs=4)

        assert last.hook_delta == -4 * 22

    def test_count_limits_the_windows(self):
        insns, masks, _ = self.run_of(42)

        (last,) = ro.build_body_anchors(insns, masks, self.entry(), min_instrs=4, count=1)

        assert last.label == "body +0x88"
        assert ro.build_body_anchors(insns, masks, self.entry(), min_instrs=4, count=0) == []

    def test_nothing_when_the_entry_fingerprint_is_the_whole_function(self):
        insns, masks, _ = self.run_of(42)

        assert ro.build_body_anchors(insns, masks, self.entry(complete=True), min_instrs=4) == []

    def test_nothing_when_less_than_a_window_is_left_after_the_entry_fingerprint(self):
        insns, masks, _ = self.run_of(20)                    # 4 words after the 16 of the entry

        assert ro.build_body_anchors(insns, masks, self.entry(), min_instrs=4) == []

    def test_a_window_made_of_wildcards_is_not_an_anchor(self):
        # The last 8 words are all calls: nothing fixed in them to look for.
        insns, masks, _ = self.run_of(42, {i: si.bl(0x1000 + 4 * i, 0x9000) for i in range(34, 42)})

        (mid,) = ro.build_body_anchors(insns, masks, self.entry(), min_instrs=4)

        assert mid.label == "body +0x64"

    def test_wildcards_are_decided_over_the_whole_run_not_per_window(self):
        # The adrp is outside the window, the load that carries the page offset is inside it.
        words = {20: si.adrp(8, 0x1000, si.DATA_BASE), 26: si.ldr_x(0, 8, 0x11)}
        insns, masks, _ = self.run_of(42, words)

        mid, _last = ro.build_body_anchors(insns, masks, self.entry(), min_instrs=4)

        load = mid.words[26 - 25]
        assert load[1] == WORD_MASK & ~IMM12


# --------------------------------------------------------------------------
# find_call_sites() / build_caller_anchors()
# --------------------------------------------------------------------------

class TestFindCallSites:
    TARGET = 0x40

    def test_finds_every_bl_that_lands_on_the_target(self):
        words = [NOP] * 50
        words[1] = si.bl(4, self.TARGET)                     # forward
        words[30] = si.bl(120, self.TARGET)                  # backward: a negative immediate
        words[2] = si.bl(8, 0x80)                            # somewhere else
        words[3] = 0x14000000 | ((self.TARGET - 12) >> 2) & 0x3FFFFFF    # b: a tail call, not a call site
        words[4] = BLR
        words[45] = si.bl(180, self.TARGET)                  # beyond the executable range: data

        assert ro.find_call_sites(pack(words), [(0, 160, "text")], self.TARGET) == [4, 120]

    def test_only_the_given_ranges_are_searched(self):
        words = [NOP] * 10
        words[2] = si.bl(8, 0x20)
        words[7] = si.bl(28, 0x20)

        assert ro.find_call_sites(pack(words), [(0, 16, "a"), (24, 40, "b")], 0x20) == [8, 28]
        assert ro.find_call_sites(pack(words), [(12, 24, "none")], 0x20) == []

    def test_a_target_nobody_calls(self):
        assert ro.find_call_sites(pack([NOP] * 8), [(0, 32, "t")], 0x10) == []


def caller_image(tmp_path, extra_callers=0):
    """fn_a and fn_b call the target (and fn_a2.. are copies of fn_a); the target
    also calls itself. Returns (path, target offset, call site offsets, fn offsets)."""
    def fn_a(): return [STP, MOV_FP] + fill(3, 1) + ["BL"] + fill(1, 2) + [LDP, RET]
    fn_b = [STP, MOV_FP] + fill(4, 3) + ["BL"] + [LDP, RET]
    target = [STP, MOV_FP] + fill(6, 4) + ["BL"] + fill(2, 5) + [LDP, RET]
    layout = [fn_a(), fn_b] + [fn_a() for _ in range(extra_callers)] + [target]
    starts, pos = [], 0
    for fn in layout:
        starts.append(pos)
        pos += 4 * len(fn)
    target_off = starts[-1]
    words, sites = [], []
    for start, fn in zip(starts, layout):
        for i, w in enumerate(fn):
            at = start + 4 * i
            if w == "BL":
                w = si.bl(at, target_off)
                sites.append(at)
            words.append(w)
    return write_bin(tmp_path, words), target_off, sites[:-1], starts


class TestCallerAnchors:
    def test_a_window_around_each_call_with_the_calls_own_distance_wildcarded(self, tmp_path):
        path, target, sites, _ = caller_image(tmp_path)

        a, b = ro.build_caller_anchors(path, target, own_words=11, min_instrs=4)

        assert [x.label for x in (a, b)] == [f"call site 0x{s:x}" for s in sites]
        assert all(x.kind == "caller" and x.hook_delta == 0 for x in (a, b))
        assert (a.xref, b.xref) == (5, 6)                    # index of the bl in the window
        for x in (a, b):
            assert x.words[x.xref] == (si.bl(0, 0) & BL_MASK, BL_MASK)
            assert [m for i, (_v, m) in enumerate(x.words) if i != x.xref] == [WORD_MASK] * 8

    def test_the_window_does_not_reach_into_the_previous_function(self, tmp_path):
        path, target, _sites, _ = caller_image(tmp_path)

        _a, b = ro.build_caller_anchors(path, target, own_words=11, min_instrs=4)

        assert b.words[0] == (STP, WORD_MASK)                # fn_a's `ret` is a wall

    def test_a_call_from_inside_the_function_itself_is_not_an_anchor(self, tmp_path):
        path, target, sites, _ = caller_image(tmp_path)

        anchors = ro.build_caller_anchors(path, target, own_words=11, min_instrs=4)

        assert len(anchors) == len(sites) == 2               # the recursive `bl` made 3 call sites in all

    def test_identical_windows_count_once_and_the_number_is_capped(self, tmp_path):
        path, target, _sites, _ = caller_image(tmp_path, extra_callers=3)    # three copies of fn_a

        anchors = ro.build_caller_anchors(path, target, own_words=11, min_instrs=4)
        assert len(anchors) == 2                             # fn_a (once) and fn_b
        assert len(ro.build_caller_anchors(path, target, own_words=11, min_instrs=4, count=1)) == 1

    def test_a_window_with_too_few_fixed_instructions_is_not_an_anchor(self, tmp_path):
        path, target, _sites, _ = caller_image(tmp_path)

        assert ro.build_caller_anchors(path, target, own_words=11, min_instrs=9) == []


# --------------------------------------------------------------------------
# locate_anchors(): where each anchor is in the new build, and what it points at
# --------------------------------------------------------------------------

def macho(tmp_path, text_words, data_words=(), name="new.bin"):
    sections = [("__text", CODE, pack(text_words))]
    if data_words:
        sections.append(("__cstring", S_CSTRING_LITERALS, pack(data_words)))
    blob, layout = build_macho([("__TEXT", 5, sections)])
    path = tmp_path / name
    path.write_bytes(blob)
    return str(path), layout


def exact(words):
    return [(w, WORD_MASK) for w in words]


class TestLocateAnchors:
    def test_a_window_found_once_votes_for_the_hook_point_it_implies(self, tmp_path):
        window = fill(6)
        path, lay = macho(tmp_path, [NOP] * 10 + window + [NOP] * 3)
        base = lay["__TEXT,__text"][0]
        body = ro.Fingerprint("after", exact(window), -8, kind="body")      # the hook point is 2 words before it

        (loc,) = ro.locate_anchors(path, [body])

        assert loc.votes == [base + 40 - 8] and not loc.generic

    def test_a_window_that_is_not_there_votes_for_nothing(self, tmp_path):
        path, _ = macho(tmp_path, [NOP] * 20)

        (loc,) = ro.locate_anchors(path, [ro.Fingerprint("after", exact(fill(6)), 0, kind="body")])

        assert loc.votes == [] and not loc.generic

    def test_a_window_found_everywhere_is_generic_and_says_nothing(self, tmp_path):
        path, _ = macho(tmp_path, [NOP] * (ro.MAX_ANCHOR_HITS + 5))

        (loc,) = ro.locate_anchors(path, [ro.Fingerprint("after", exact([NOP, NOP]), 0, kind="body")])

        assert loc.generic and loc.votes == []

    def test_matches_in_data_do_not_vote(self, tmp_path):
        window = fill(6)
        path, lay = macho(tmp_path, [NOP] * 4 + window, data_words=window)
        base = lay["__TEXT,__text"][0]

        (loc,) = ro.locate_anchors(path, [ro.Fingerprint("after", exact(window), 0, kind="body")])

        assert loc.votes == [base + 16]                      # not the copy in __cstring

    def test_a_call_site_votes_for_where_its_call_lands(self, tmp_path):
        base = macho(tmp_path, [NOP])[1]["__TEXT,__text"][0]
        text = [NOP] * 4 + [si.MOV_FP_SP, si.bl(base + 20, base + 4 * 40), ADD_X, NOP]
        path, lay = macho(tmp_path, text + [NOP] * 40)
        assert lay["__TEXT,__text"][0] == base
        window = [(si.MOV_FP_SP, WORD_MASK), (si.bl(0, 0) & BL_MASK, BL_MASK), (ADD_X, WORD_MASK)]
        caller = ro.Fingerprint("after", window, 0, kind="caller", xref=1)

        (loc,) = ro.locate_anchors(path, [caller])

        assert loc.votes == [base + 4 * 40]

    def test_a_call_that_goes_backwards_votes_for_a_lower_offset(self, tmp_path):
        base = macho(tmp_path, [NOP])[1]["__TEXT,__text"][0]
        text = [NOP] * 30 + [si.MOV_FP_SP, si.bl(base + 124, base + 8), ADD_X, NOP]
        path, _ = macho(tmp_path, text)
        window = [(si.MOV_FP_SP, WORD_MASK), (si.bl(0, 0) & BL_MASK, BL_MASK), (ADD_X, WORD_MASK)]

        (loc,) = ro.locate_anchors(path, [ro.Fingerprint("after", window, 0, kind="caller", xref=1)])

        assert loc.votes == [base + 8]

    def test_no_anchors_no_work(self, tmp_path):
        assert ro.locate_anchors(str(tmp_path / "does-not-need-to-exist"), []) == []


ADD_X = 0x91004000                                           # add x0, x0, #0x10


# --------------------------------------------------------------------------
# judge() / vote_confidence(): the rules
# --------------------------------------------------------------------------

class TestJudge:
    def loc(self, kind, votes, generic=False):
        return ro.Located(fake_anchor(kind), votes, generic)

    @pytest.mark.parametrize("kind, votes, generic, offset, verdict", [
        ("body", [0x100], False, 0x100, "agree"),
        ("body", [0x100, 0x900], False, 0x100, "agree-weak"),
        ("body", [0x900], False, 0x100, "conflict"),
        ("body", [0x900, 0xA00], False, 0x100, "elsewhere"),
        ("body", [], False, 0x100, "absent"),
        ("body", [], True, 0x100, "generic"),
        ("caller", [0x100], False, 0x100, "agree"),
        ("caller", [0x900], False, 0x100, "conflict"),
        ("caller", [], False, 0x100, "absent"),
    ])
    def test_verdict(self, kind, votes, generic, offset, verdict):
        assert ro.judge(self.loc(kind, votes, generic), offset)[0] == verdict

    def test_the_detail_names_where_the_anchor_points_instead(self):
        _verdict, detail = ro.judge(self.loc("caller", [0x4bf8]), 0x100)

        assert "lands at 0x4bf8" in detail and "not here" in detail

    @pytest.mark.parametrize("verdict, kind, status", [
        ("agree", "body", "pass"), ("agree-weak", "caller", "pass"),
        ("conflict", "body", "fail"), ("conflict", "caller", "fail"),
        ("absent", "body", "fail"), ("elsewhere", "entry", "fail"),
        ("absent", "caller", "n/a"), ("elsewhere", "caller", "n/a"),     # a call site that went says nothing about the function
        ("generic", "body", "n/a"),
    ])
    def test_status_of_a_vote(self, verdict, kind, status):
        assert ro._vote_status(ro.Vote(fake_anchor(kind), verdict, "")) == status


def votes_of(*pairs):
    return [ro.Vote(fake_anchor(kind), verdict, "") for kind, verdict in pairs]


class TestVoteConfidence:
    @pytest.mark.parametrize("base, pairs, expected", [
        # votes never raise a grade ...
        ("HIGH", [("entry", "agree"), ("body", "agree"), ("caller", "agree")], "HIGH"),
        ("MEDIUM", [("entry", "agree"), ("body", "agree"), ("caller", "agree")], "MEDIUM"),
        ("LOW", [("entry", "agree"), ("body", "agree"), ("caller", "agree")], "LOW"),
        ("HIGH", [("entry", "agree")], "HIGH"),                               # nothing else to vote
        ("HIGH", [("entry", "agree-weak"), ("body", "agree-weak")], "HIGH"),
        # ... an anchor found in one place that points elsewhere is a conflict ...
        ("HIGH", [("entry", "agree"), ("body", "conflict")], "LOW"),
        ("MEDIUM", [("entry", "agree"), ("caller", "conflict")], "LOW"),
        ("HIGH", [("entry", "agree"), ("body", "agree"), ("caller", "conflict"), ("caller", "agree")], "LOW"),
        # ... a window of the function's code that isn't where it should be is not a conflict, but caps HIGH ...
        ("HIGH", [("entry", "agree"), ("body", "absent")], "MEDIUM"),
        ("HIGH", [("entry", "agree"), ("body", "elsewhere")], "MEDIUM"),
        ("HIGH", [("entry", "agree"), ("body", "agree"), ("body", "absent")], "MEDIUM"),
        ("MEDIUM", [("entry", "agree"), ("body", "absent")], "MEDIUM"),
        # ... while call sites that went away, or anchors too common to count, say nothing.
        ("HIGH", [("entry", "agree"), ("caller", "absent"), ("caller", "elsewhere")], "HIGH"),
        ("HIGH", [("entry", "agree"), ("body", "generic")], "HIGH"),
        # a mid-function hook point: the code in front of it and the code after it
        ("HIGH", [("before", "agree"), ("forward", "agree")], "HIGH"),
        ("HIGH", [("before", "agree"), ("forward", "conflict")], "LOW"),
        ("HIGH", [("before", "agree"), ("forward", "absent")], "MEDIUM"),
    ])
    def test_grade(self, base, pairs, expected):
        assert ro.vote_confidence(base, votes_of(*pairs))[0] == expected

    @pytest.mark.parametrize("pairs, expected", [
        # proposed by other anchors: the main fingerprint doesn't match here
        ([("entry", "absent"), ("body", "agree"), ("body", "agree")], "MEDIUM"),
        ([("entry", "absent"), ("body", "agree"), ("body", "agree"), ("caller", "agree")], "MEDIUM"),
        ([("entry", "absent"), ("body", "agree")], "LOW"),                    # one witness is not a vote
        ([("entry", "absent"), ("caller", "agree"), ("caller", "agree")], "LOW"),    # call sites never nominate
        ([("entry", "elsewhere"), ("body", "agree"), ("body", "agree")], "MEDIUM"),
    ])
    def test_a_candidate_the_main_fingerprint_does_not_back(self, pairs, expected):
        assert ro.vote_confidence("HIGH", votes_of(*pairs))[0] == expected

    def test_the_reason_is_given_when_the_grade_drops(self):
        _grade, why = ro.vote_confidence("HIGH", votes_of(("entry", "agree"), ("body", "conflict")))

        assert "body" in why and "somewhere else" in why
        assert ro.vote_confidence("HIGH", votes_of(("entry", "agree")))[1] == ""


# --------------------------------------------------------------------------
# End to end on the synthetic build (tests/synth_image.py: 300 functions, the
# hook at the entry of the 150th)
# --------------------------------------------------------------------------

N_FUNCS, TARGET = 300, 150
OLD_ORDER = list(range(N_FUNCS))


@pytest.fixture(scope="module")
def old_image():
    return si.Image(si.make_functions(seed=7, n_funcs=N_FUNCS), OLD_ORDER)


def fresh_functions():
    return si.make_functions(seed=7, n_funcs=N_FUNCS)


def new_function(seed):
    return si.gen_function(random.Random(seed), N_FUNCS, 64)


def relocate(tmp_path, monkeypatch, capsys, old_image, new_image, *extra):
    old = old_image.write(tmp_path / "old.bin")
    new = new_image.write(tmp_path / "new.bin")
    return run_main(monkeypatch, capsys, old, hex(old_image.entry[TARGET]), new, *extra)


def found_line(offset, confidence):
    return "NEW FILE OFFSET: 0x%x  (confidence: %s)" % (offset, confidence)


def tally(out):
    """(agree, total) from the `anchor-vote` line."""
    m = re.search(r"anchor-vote: (\d+) of (\d+) anchors agree, (\d+) conflict, (\d+) do not confirm", out)
    assert m, out
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))


# -- the five scenarios ------------------------------------------------------

def scenario_unchanged():
    return si.Image(fresh_functions(), OLD_ORDER)


def scenario_neighbour_tail_edited():
    f = fresh_functions()
    tail = len(f[TARGET - 1]) - 4                       # the last body op, just above `ldp; ret`
    assert f[TARGET - 1][tail][0] == "raw"
    f[TARGET - 1][tail] = ("raw", si.add_imm(3, 4, 0x321))
    return si.Image(f, OLD_ORDER)


def scenario_target_rewritten():
    f = fresh_functions()
    f[TARGET] = new_function(999)
    return si.Image(f, OLD_ORDER)


def scenario_function_inserted_in_front():
    f = fresh_functions()
    f[N_FUNCS] = new_function(1234)
    return si.Image(f, OLD_ORDER[:TARGET] + [N_FUNCS] + OLD_ORDER[TARGET:])


def scenario_neighbours_swapped():
    order = OLD_ORDER[:]
    order[TARGET - 1], order[TARGET + 1] = order[TARGET + 1], order[TARGET - 1]
    return si.Image(fresh_functions(), order)


FIVE_SCENARIOS = {
    "unchanged": scenario_unchanged,
    "neighbour tail edited": scenario_neighbour_tail_edited,
    "target rewritten": scenario_target_rewritten,
    "function inserted in front": scenario_function_inserted_in_front,
    "neighbours swapped": scenario_neighbours_swapped,
}
SCENARIO_IDS = list(FIVE_SCENARIOS)


class TestFiveScenarioRegression:
    """The five situations from the review of the original algorithm, replayed on the
    same synthetic build. Whatever the anchors do, these answers must not change: the
    right address with HIGH confidence when the function only moved or its neighbours
    changed, and no answer at all when it was rewritten."""

    @pytest.mark.parametrize("anchors", ["all", "code", "none"])
    @pytest.mark.parametrize("name", SCENARIO_IDS)
    def test_scenario(self, tmp_path, monkeypatch, capsys, old_image, name, anchors):
        new = FIVE_SCENARIOS[name]()

        code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new, "--anchors", anchors)

        if name == "target rewritten":
            assert code == 1 and "No matches" in out
            assert "NEW FILE OFFSET" not in out
        else:
            assert code == 0, out
            assert found_line(new.entry[TARGET], "HIGH") in out
            assert "looks like a function entry" in out

    @pytest.mark.parametrize("name", [n for n in SCENARIO_IDS if n != "target rewritten"])
    def test_with_the_anchors_on_every_one_of_them_agrees(self, tmp_path, monkeypatch, capsys, old_image, name):
        new = FIVE_SCENARIOS[name]()

        _code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)
        agree, total, conflicts, unconfirmed = tally(out)

        assert (agree, conflicts, unconfirmed) == (total, 0, 0)
        assert total >= 4                                # the entry fingerprint, body windows and call sites
        assert "anchor call site 0x" in out and "anchor body +0x" in out

    @pytest.mark.parametrize("name", [n for n in SCENARIO_IDS if n != "target rewritten"])
    def test_the_code_anchors_alone_also_agree(self, tmp_path, monkeypatch, capsys, old_image, name):
        new = FIVE_SCENARIOS[name]()

        _code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new, "--anchors", "code")
        agree, total, conflicts, _ = tally(out)

        assert agree == total >= 3 and conflicts == 0
        assert "call site" not in out

    def test_a_rewritten_function_comes_with_a_lead_not_an_answer(self, tmp_path, monkeypatch, capsys, old_image):
        new = scenario_target_rewritten()

        code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

        assert code == 1 and "NEW FILE OFFSET" not in out
        assert "Lead, not an answer" in out and "0x%x" % new.entry[TARGET] in out
        assert "rewritten" in out

    def test_without_the_call_sites_a_rewritten_function_has_no_lead(self, tmp_path, monkeypatch, capsys, old_image):
        code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, scenario_target_rewritten(),
                                "--anchors", "code")

        assert code == 1 and "Lead" not in out


def original_fingerprint(old_path, old_offset, _mode, min_instrs, lookback, _lookahead):
    """The original algorithm, for the tests below: whatever position-independent words
    sit in front of the hook point - at a function entry, the tail of the function before it."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    with open(old_path, "rb") as f:
        data = f.read()
    words, at = [], old_offset - 4
    while at >= old_offset - lookback:
        insn = next(md.disasm(data[at:at + 4], at), None)
        if insn is None or ro.is_pc_relative(insn):
            break
        words.insert(0, data[at:at + 4])
        at -= 4
    assert len(words) >= min_instrs
    return ro.Fingerprint.from_bytes(b"".join(words))


class TestTheScenariosCatchTheOriginalAlgorithm:
    """A regression suite is only worth something if it fails on the bug. Swap the
    fingerprint back to the neighbour's tail and the five scenarios above go wrong in
    exactly the ways that were reported - and, with the anchors on, the votes still
    refuse to call the wrong answer a good one."""

    @pytest.fixture(autouse=True)
    def _original(self, monkeypatch):
        monkeypatch.setattr(ro, "choose_fingerprint", original_fingerprint)

    def result(self, tmp_path, monkeypatch, capsys, old_image, name, anchors):
        new = FIVE_SCENARIOS[name]()
        code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new, "--anchors", anchors)
        answer = re.search(r"NEW FILE OFFSET: 0x([0-9a-f]+)  \(confidence: (\w+)\)", out)
        return new.entry[TARGET], code, out, (int(answer.group(1), 16), answer.group(2)) if answer else None

    @pytest.mark.parametrize("name", ["function inserted in front", "neighbours swapped"])
    def test_alone_it_answers_with_the_wrong_function_and_no_alarm(
            self, tmp_path, monkeypatch, capsys, old_image, name):
        truth, code, _out, answer = self.result(tmp_path, monkeypatch, capsys, old_image, name, "none")

        assert code == 0 and answer[0] != truth and answer[1] in ("HIGH", "MEDIUM")

    def test_alone_it_loses_the_target_when_the_neighbour_changes(self, tmp_path, monkeypatch, capsys, old_image):
        _truth, code, out, answer = self.result(
            tmp_path, monkeypatch, capsys, old_image, "neighbour tail edited", "none")

        assert code == 1 and answer is None and "No matches" in out

    @pytest.mark.parametrize("name", ["function inserted in front", "neighbours swapped"])
    def test_the_votes_turn_that_wrong_answer_into_a_LOW_one(self, tmp_path, monkeypatch, capsys, old_image, name):
        truth, code, out, answer = self.result(tmp_path, monkeypatch, capsys, old_image, name, "all")

        assert code == 0 and answer[0] != truth and answer[1] == "LOW"
        assert "somewhere else" in out and "Check this one in Ghidra" in out

    def test_the_votes_find_the_target_the_neighbour_fingerprint_lost(self, tmp_path, monkeypatch, capsys, old_image):
        truth, code, out, answer = self.result(
            tmp_path, monkeypatch, capsys, old_image, "neighbour tail edited", "all")

        assert code == 0 and answer == (truth, "MEDIUM")
        assert "proposed by the anchors" in out


# -- what the votes decide ---------------------------------------------------

def swap_calls(functions, ids, old, new):
    for fid in ids:
        functions[fid] = [("bl", new) if op == ("bl", old) else op for op in functions[fid]]


def callers_of(functions, target):
    return [fid for fid, ops in functions.items() if any(op == ("bl", target) for op in ops)]


def test_the_synthetic_target_has_two_callers():
    assert callers_of(fresh_functions(), TARGET) == [12, 250]       # the call-site tests rely on it


def test_a_copy_nobody_calls_is_outvoted_by_the_call_sites(tmp_path, monkeypatch, capsys, old_image):
    f = fresh_functions()
    f[N_FUNCS] = copy.deepcopy(f[TARGET])               # same code, once more, and nobody calls it
    new = si.Image(f, OLD_ORDER + [N_FUNCS])

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

    assert code == 0 and found_line(new.entry[TARGET], "MEDIUM") in out
    assert "outvoted file offset 0x%x" % new.entry[N_FUNCS] in out
    assert "anchor-tiebreak" in out and "only call sites do" in out


def test_without_call_sites_the_same_copy_is_ambiguous(tmp_path, monkeypatch, capsys, old_image):
    f = fresh_functions()
    f[N_FUNCS] = copy.deepcopy(f[TARGET])
    new = si.Image(f, OLD_ORDER + [N_FUNCS])

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new, "--anchors", "code")

    assert code == 1 and "More than one match" in out and "could not settle it" in out
    assert "candidate file offset: 0x%x" % new.entry[TARGET] in out
    assert "candidate file offset: 0x%x" % new.entry[N_FUNCS] in out


def test_a_copy_that_starts_the_same_but_differs_in_the_body_is_settled_by_the_body_windows(
        tmp_path, monkeypatch, capsys, old_image):
    # The classic generic-instantiation case: the first 16 instructions are the same, so the entry
    # fingerprint matches both; the rest of the body only matches the real one.
    f = fresh_functions()
    ops, words = [], 0
    for op in f[TARGET]:
        if words >= 16:
            break
        ops.append(op)
        words += si._SIZE[op[0]]
    f[N_FUNCS] = ops + [("raw", si.mul(1, 2, 3))] * 20 + [("raw", si.LDP_FP_LR), ("raw", si.RET)]
    new = si.Image(f, OLD_ORDER + [N_FUNCS])

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new, "--anchors", "code")

    assert code == 0 and found_line(new.entry[TARGET], "HIGH") in out     # decided by the function's own code
    assert "outvoted file offset 0x%x" % new.entry[N_FUNCS] in out
    assert "only call sites" not in out


def test_a_clone_called_from_some_of_the_places_stays_ambiguous(tmp_path, monkeypatch, capsys, old_image):
    f = fresh_functions()
    f[N_FUNCS] = copy.deepcopy(f[TARGET])
    swap_calls(f, [250], TARGET, N_FUNCS)               # one caller was pointed at the clone
    new = si.Image(f, OLD_ORDER + [N_FUNCS])

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

    assert code == 1 and "More than one match" in out and "could not settle it" in out


def test_call_sites_that_now_call_something_else_make_the_answer_LOW(tmp_path, monkeypatch, capsys, old_image):
    # The old code is still there at the same place, but every caller now calls a new function.
    f = fresh_functions()
    f[N_FUNCS] = new_function(4242)
    swap_calls(f, callers_of(f, TARGET), TARGET, N_FUNCS)
    new = si.Image(f, OLD_ORDER + [N_FUNCS])

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

    assert code == 0 and found_line(new.entry[TARGET], "LOW") in out
    assert "lands at 0x%x - not here" % new.entry[N_FUNCS] in out
    assert "Check this one in Ghidra" in out
    assert tally(out)[2] == 2                           # both call sites disagree


def test_the_same_code_without_the_call_site_anchors_gets_no_alarm(tmp_path, monkeypatch, capsys, old_image):
    f = fresh_functions()
    f[N_FUNCS] = new_function(4242)
    swap_calls(f, callers_of(f, TARGET), TARGET, N_FUNCS)
    new = si.Image(f, OLD_ORDER + [N_FUNCS])

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new, "--anchors", "code")

    assert code == 0 and found_line(new.entry[TARGET], "HIGH") in out    # what the call sites exist to catch


def test_a_tail_moved_into_a_function_of_its_own_makes_the_answer_LOW(tmp_path, monkeypatch, capsys, old_image):
    f = fresh_functions()
    ops = f[TARGET]
    f[N_FUNCS] = [("raw", si.STP_FP_LR), ("raw", si.MOV_FP_SP)] + ops[-14:]     # the end of the target, outlined
    f[TARGET] = ops[:-14] + [("raw", si.mul(1, 2, 3))] * 3 + [("raw", si.LDP_FP_LR), ("raw", si.RET)]
    new = si.Image(f, OLD_ORDER + [N_FUNCS])

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

    assert code == 0 and found_line(new.entry[TARGET], "LOW") in out
    assert "found in one place only, and that puts the hook point at" in out
    assert "somewhere else (body +0x" in out


def test_a_changed_start_of_the_function_is_found_by_the_body_windows(tmp_path, monkeypatch, capsys, old_image):
    f = fresh_functions()
    assert f[TARGET][3][0] == "raw"
    f[TARGET][3] = ("raw", si.add_imm(7, 7, 0x111))     # inside the entry fingerprint, nothing else touched
    new = si.Image(f, OLD_ORDER)

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

    assert code == 0 and found_line(new.entry[TARGET], "MEDIUM") in out
    assert "proposed by the anchors" in out
    assert "[fail] anchor entry: not found in the new build" in out
    assert "the start of the function changed?" in out


def test_without_anchors_the_same_change_is_no_match(tmp_path, monkeypatch, capsys, old_image):
    f = fresh_functions()
    f[TARGET][3] = ("raw", si.add_imm(7, 7, 0x111))
    new = si.Image(f, OLD_ORDER)

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new, "--anchors", "none")

    assert code == 1 and "No matches" in out


def test_a_body_that_changed_in_the_middle_is_graded_down_by_its_window(tmp_path, monkeypatch, capsys, old_image):
    # One word inside the middle window (words 25..32) differs: the entry fingerprint and the tail
    # window still match and the mnemonic sequence is 97% alike, so only that window notices.
    f = fresh_functions()
    ops, words = f[TARGET], 0
    for i, op in enumerate(ops):
        if 26 <= words <= 31 and op[0] == "raw":
            ops[i] = ("raw", si.add_imm(9, 9, 0x2AB))
            break
        words += si._SIZE[op[0]]
    else:
        pytest.fail("no plain op inside words 26..31 of the synthetic target")
    new = si.Image(f, OLD_ORDER)

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, new)

    assert code == 0 and found_line(new.entry[TARGET], "MEDIUM") in out
    assert "[fail] anchor body +0x64: not found in the new build" in out
    assert "the body changed?" in out


# -- options -----------------------------------------------------------------

def test_anchors_none_is_the_main_fingerprint_alone(tmp_path, monkeypatch, capsys, old_image):
    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, scenario_unchanged(), "--anchors", "none")

    assert code == 0 and found_line(scenario_unchanged().entry[TARGET], "HIGH") in out
    assert "anchor-vote" not in out and "[pass] anchor " not in out and "Anchors that vote" not in out


def test_anchors_code_does_not_scan_the_binary_for_call_sites(tmp_path, monkeypatch, capsys, old_image):
    def boom(*_a, **_k):
        raise AssertionError("scanned for call sites")

    monkeypatch.setattr(ro, "find_call_sites", boom)

    code, _out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, scenario_unchanged(), "--anchors", "code")

    assert code == 0


def test_no_validate_does_not_run_the_anchors(tmp_path, monkeypatch, capsys, old_image):
    def boom(*_a, **_k):
        raise AssertionError("built anchors")

    monkeypatch.setattr(ro, "build_anchors", boom)

    code, out, _ = relocate(tmp_path, monkeypatch, capsys, old_image, scenario_unchanged(), "--no-validate")

    assert code == 0 and "NEW FILE OFFSET" in out


def test_an_unknown_anchor_scope_is_a_usage_error(tmp_path, monkeypatch, capsys, old_image):
    code, _out, err = relocate(tmp_path, monkeypatch, capsys, old_image, scenario_unchanged(), "--anchors", "some")

    assert code == 2 and "--anchors" in err


def test_a_function_that_is_entirely_inside_the_entry_fingerprint_says_so(tmp_path, monkeypatch, capsys):
    # Short function, no callers: nothing else to vote with - the main fingerprint decides alone.
    func = [STP, MOV_FP] + fill(4) + [LDP, RET]
    old, lay = macho(tmp_path, [NOP, RET] + func, name="old.bin")
    new, _ = macho(tmp_path, [NOP] * 3 + [RET] + func + [NOP], name="new.bin")
    base = lay["__TEXT,__text"][0]

    code, out, _ = run_main(monkeypatch, capsys, old, hex(base + 2 * 4), new)

    assert code == 0 and found_line(base + 4 * 4, "HIGH") in out
    assert "No anchors besides the main fingerprint" in out


# -- a hook point in the middle of a function --------------------------------

class TestMidFunctionHook:
    BEFORE = [STP, MOV_FP] + fill(4, 1)              # position-independent run in front of the hook point
    AFTER = fill(5, 2) + [LDP, RET]                  # the code behind it

    def old(self, tmp_path):
        path, lay = macho(tmp_path, [RET] + self.BEFORE + self.AFTER, name="old.bin")
        base = lay["__TEXT,__text"][0]
        return path, base, base + 4 * (1 + len(self.BEFORE))

    def test_the_code_in_front_and_the_code_behind_agree(self, tmp_path, monkeypatch, capsys):
        old, base, hook = self.old(tmp_path)
        new, _ = macho(tmp_path, [NOP] * 3 + [RET] + self.BEFORE + self.AFTER + [NOP] * 3)

        code, out, _ = run_main(monkeypatch, capsys, old, hex(hook), new)

        assert code == 0 and found_line(base + 4 * (4 + len(self.BEFORE)), "HIGH") in out
        assert "[pass] anchor before" in out and "[pass] anchor forward" in out

    def test_they_point_at_different_places_so_the_answer_is_LOW(self, tmp_path, monkeypatch, capsys):
        old, base, hook = self.old(tmp_path)
        elsewhere = fill(4, 7) + [LDP, RET]
        new, _ = macho(tmp_path, [RET] + self.BEFORE + elsewhere + [NOP] * 8 + self.AFTER)

        code, out, _ = run_main(monkeypatch, capsys, old, hex(hook), new)

        assert code == 0 and found_line(base + 4 * (1 + len(self.BEFORE)), "LOW") in out
        assert "[fail] anchor forward" in out and "somewhere else (forward)" in out
