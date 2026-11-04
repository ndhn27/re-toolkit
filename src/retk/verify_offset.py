"""
verify_offset.py

Dynamic verification: spawns the target app, trial-hooks one or more CANDIDATE
offsets with the bundled dist/verify_hook.js, lets you use the app until they have
been called enough, and reports - per candidate - whether it is VERIFIED: the hook
fired, and every record it handed back, read through the profile's layout, was valid
(a real class pointer, readable strings, the profile's `expect` kept).

That is the step after retk relocate. A byte match says the code at an
address looks like the old function's; it cannot say the address is what the app
calls, or that the record layout still holds. Here the candidate runs, and the
answer is one of (retk/verification.py has the exact rules):

    VERIFIED        fired, enough valid records, something in them that could tell
    WEAK            fired, nothing contradicts the layout, but too little to say
    REJECTED        fired and the records contradict the layout - or it was refused
                    as not hookable (not aligned / not executable / beyond the module).
                    When the whole layout fits shifted, the report says the LAYOUT
                    moved, not that the candidate is wrong
    NOT EXERCISED   never called (use the app so the code path runs), or every call
                    returned a failure
    CRASHED         the app died with the hooks installed

Where the candidates come from (any mix; duplicates are hooked once):

    --from-relocate PATH   a relocate_offset.py --json report: every accepted
                           candidate, so an AMBIGUOUS relocation is settled by
                           running them, not by guessing
    --candidate RVA        an RVA to try (repeatable)
    --offset KEY=HEX / the profile's offsets
                           with neither of the above, the offset the profile holds for
                           --key (default table_a): "does my current offset still work
                           on this build?"

Candidates are RVAs, like every profile offset (README.md's "RVA vs file offset");
relocate_offset.py prints and writes the RVA next to the file offset. A candidate in
a container it cannot convert has no RVA in the report, and this driver says so
instead of hooking a guess.

What is read is the record named by --record (default: TableARecord for table_a,
TableBRecord for table_b), through the profile's layout; the agent assumes the dump
agents' convention (the record is args[0], success is a zero low 32 bits of the return
value).

    --min-records N      records a candidate must hand back to be VERIFIED (default 3)
    --wait SECONDS       how long to wait for the app to call them (default 90; 0 = until
                         you press Enter). It also ends when every hooked candidate has
                         enough records, or at Enter on a terminal
    --layout-tolerance F as in run_dump.py
    --json PATH          also write the verdict (it names real offsets - keep it out of
                         git; `verify*.json` is ignored by this repo's .gitignore)

Exit status: 0 verified; 3 every candidate rejected or crashed; 4 not verified (weak, not
exercised, a mix); 5 ambiguous (more than one verified); 2 usage errors. If it hooks several
candidates and the app crashes, run them one at a time with --candidate: a crash cannot be
attributed to one of several.

Usage:
    retk relocate OLD NEW_OFFSET NEW --json relocate_new.json
    retk verify --profile myapp --from-relocate relocate_new.json
    retk verify --profile myapp --candidate 0xab68fc8 --candidate 0xab69100
    retk verify --profile myapp                 # the profile's own table_a offset
"""
import argparse
import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import frida

from . import layout_check, resources, verification
from ._common import (AgentInitError, add_override_args, is_gitignored, load_agent_source,
                     resolve_settings, spawn_agent, wait_for_enter)
from .profiles import parse_offset

AGENT_PATH = resources.agent_path("verify_hook.js")

# The record each offset key reads, for the keys the dump agents use. Any other key needs --record.
DEFAULT_RECORDS = {"table_a": "TableARecord", "table_b": "TableBRecord"}
DEFAULT_WAIT = 90.0
POLL_SECONDS = 1.0
MAX_CANDIDATES = 16
REPORT_VERSION = 1             # the relocate_offset.py --json format this reads


class CandidateError(ValueError):
    """The candidates could not be put together (bad report, no RVA, none given)."""


class NotAVerifyAgent(RuntimeError):
    """The loaded agent has no getVerification(): it is not dist/verify_hook.js."""


def on_message(message, data):
    if message.get("type") == "error":
        print("[agent error]", message.get("stack") or message.get("description"))
    elif message.get("type") == "send":
        print(message.get("payload"))


# --- candidates ---------------------------------------------------------------

def load_relocate_report(path):
    """[(rva, label)] for every accepted candidate of a relocate_offset.py --json report."""
    try:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise CandidateError(f"{path}: {e}") from e
    if not isinstance(report, dict) or report.get("version") != REPORT_VERSION or not isinstance(
            report.get("candidates"), list):
        raise CandidateError(f"{path}: not a relocate_offset.py --json report (version {REPORT_VERSION})")
    if not report["candidates"]:
        raise CandidateError(f"{path}: relocate_offset.py found no candidate (result: {report.get('result')}) - "
                             f"there is nothing to verify")
    out = []
    for c in report["candidates"]:
        label = f"relocate {c.get('confidence')}, file offset {c.get('file_offset')}"
        if c.get("rva") is None:
            raise CandidateError(
                f"{path}: the candidate at file offset {c.get('file_offset')} has no RVA - relocate_offset.py "
                f"could not convert it (not a Mach-O / ELF it understands). Convert it yourself "
                f"(README.md, \"RVA vs file offset\") and pass it as --candidate RVA")
        try:
            out.append((parse_offset(c["rva"]), label))
        except (argparse.ArgumentTypeError, KeyError) as e:
            raise CandidateError(f"{path}: bad rva {c.get('rva')!r} ({e})") from e
    return out


def gather_candidates(report_candidates, cli_candidates, profile_offset, key):
    """The candidates to hook, as [{"id", "rva", "label"}], first source first, each RVA once."""
    found = list(report_candidates)
    found += [(rva, "--candidate") for rva in cli_candidates]
    if not found and profile_offset:
        found = [(profile_offset, f"the profile's {key}")]
    if not found:
        raise CandidateError(f"no candidate to verify: pass --from-relocate PATH or --candidate RVA, or set "
                             f"`{key}` in the profile / --offset {key}=HEX to check the offset it holds")
    seen, out = set(), []
    for rva, label in found:
        if rva in seen:
            continue
        seen.add(rva)
        out.append({"id": f"c{len(out)}", "rva": rva, "label": label})
    if len(out) > MAX_CANDIDATES:
        raise CandidateError(f"{len(out)} candidates is more than {MAX_CANDIDATES}: hooking that many at once "
                             f"says little about any of them - narrow it down")
    return out


def pick_record(params, key, record):
    """The record to read: --record, else the one `key` is known for. Checks the profile defines it."""
    name = record or DEFAULT_RECORDS.get(key)
    if not name:
        raise CandidateError(f"which record does `{key}` hand back? pass --record NAME")
    known = sorted(((params.get("layouts") or {}).get("records") or {}))
    if not known:
        raise CandidateError("the profile has no `layouts`: verification reads the record through its layout "
                             "(README.md, \"Profiles\")")
    if name not in known:
        raise CandidateError(f"the profile's layouts define no record {name!r} (it has: {', '.join(known)}) - "
                             f"pass --record NAME")
    return name


# --- running ------------------------------------------------------------------

def require_verify_agent(run, agent_path):
    """Fail BEFORE the app is resumed if the agent is not the verification agent."""
    try:
        run.script.exports_sync.get_verification()
    except Exception as e:
        raise NotAVerifyAgent(
            f"{Path(agent_path).name} exposes no getVerification() ({e}) - this driver loads "
            f"dist/verify_hook.js (`npm run build`)") from e


def fetch(script):
    """The agent's verification so far, or None if it cannot be asked (the app died, the agent is old)."""
    try:
        return script.exports_sync.get_verification()
    except Exception:
        return None


def hooked(snapshot):
    return [c for c in snapshot["candidates"] if c.get("hooked")]


def enough(snapshot, min_records):
    """True when there is nothing more to wait for: the module is loaded and every candidate that could be
    hooked has handed back `min_records` records (or none could be hooked at all)."""
    if not snapshot.get("module_loaded"):
        return False
    return all((c.get("health") or {}).get("calls", 0) >= min_records for c in hooked(snapshot))


def progress(snapshot, labels):
    """One line: how far each candidate has got, e.g. `c0 0x1234: 12 calls, 9 records | c1 0x1240: 0 calls`."""
    if not snapshot.get("module_loaded"):
        return "waiting for the module to load"
    parts = []
    for c in snapshot["candidates"]:
        if c.get("error"):
            parts.append(f"{c['id']} 0x{c['rva']:x}: refused")
        else:
            records = (c.get("health") or {}).get("calls", 0)
            parts.append(f"{c['id']} 0x{c['rva']:x}: {c.get('enters', 0)} call(s), {records} record(s)")
    return " | ".join(parts)


def watch(script, gone, min_records, wait, labels, poll=POLL_SECONDS, clock=time.monotonic):
    """Poll the agent until every hooked candidate has enough records, `wait` seconds have passed (0: never),
    the session ended (`gone` is set) or the user pressed Enter. Returns the last snapshot (None if the agent
    could never be asked)."""
    deadline = clock() + wait if wait else None
    last, printed = None, None
    while True:
        snap = None if gone.is_set() else fetch(script)
        if snap is not None:
            last = snap
            line = progress(snap, labels)
            if line != printed:
                print(f"[~] {line}")
                printed = line
            if enough(snap, min_records):
                print("[*] Every hooked candidate has enough records.")
                break
        if gone.is_set():
            break
        remaining = None if deadline is None else deadline - clock()
        if remaining is not None and remaining <= 0:
            print(f"[*] --wait {wait:g} s is up.")
            break
        step = poll if remaining is None else min(poll, remaining)
        try:
            how = wait_for_enter(gone, poll=min(0.25, step), timeout=step)
        except KeyboardInterrupt:
            print("\n[*] Interrupted - judging what was seen so far.")
            break
        if how in ("enter", "stop"):
            break
    if not gone.is_set():
        final = fetch(script)          # one last look: calls may have arrived since the last poll
        if final is not None:
            last = final
    return last


def write_report(path, settings, record, candidates, result):
    out = {
        "meta": {"profile": settings.profile.name if settings.profile else None, "target": settings.target,
                 "module": settings.params["module"], "record": record,
                 "candidates": [{"id": c["id"], "rva": hex(c["rva"]), "label": c["label"]} for c in candidates],
                 "verified_at": datetime.now(timezone.utc).isoformat()},
        **result.as_json(),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[+] Wrote {path}")


def positive_int(text):
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text!r}") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {text!r}")
    return value


def seconds(text):
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be 0 or more, got {text!r}")
    return value


def fraction(text):
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not 0 <= value <= 1:
        raise argparse.ArgumentTypeError(f"must be between 0 and 1, got {text!r}")
    return value


def main(argv=None, prog=None):
    ap = argparse.ArgumentParser(
        prog=prog,
        description="Trial-hook candidate offsets in the running app and say which are VERIFIED: called, and "
                    "handing back records that fit the profile's layout (see the module docstring).")
    add_override_args(ap, offsets=True)
    ap.add_argument("--from-relocate", metavar="PATH",
                    help="a relocate_offset.py --json report: verify every candidate in it")
    ap.add_argument("--candidate", metavar="RVA", action="append", type=parse_offset, default=[],
                    help="an RVA to try, hex (repeatable)")
    ap.add_argument("--key", default="table_a", metavar="KEY",
                    help="the profile offset to check when no candidate is given (default: table_a)")
    ap.add_argument("--record", metavar="NAME",
                    help="the record the hooked function hands back (default: TableARecord for table_a, "
                         "TableBRecord for table_b)")
    ap.add_argument("--min-records", type=positive_int, default=verification.DEFAULT_MIN_RECORDS, metavar="N",
                    help=f"records a candidate must hand back to be VERIFIED (default: "
                         f"{verification.DEFAULT_MIN_RECORDS})")
    ap.add_argument("--wait", type=seconds, default=DEFAULT_WAIT, metavar="SECONDS",
                    help=f"how long to wait for the app to call the candidates (default: {DEFAULT_WAIT:g}; "
                         f"0 = until you press Enter)")
    ap.add_argument("--layout-tolerance", type=fraction, default=layout_check.DEFAULT_TOLERANCE, metavar="F",
                    help="fraction of reads (0-1) that may contradict a layout check before it fails "
                         f"(default: {layout_check.DEFAULT_TOLERANCE})")
    ap.add_argument("--agent", default=None, metavar="PATH|NAME",
                    help=f"bundled verification agent, as a path or just its name (default: {Path(AGENT_PATH).name})")
    ap.add_argument("--json", metavar="PATH", help="also write the verdict to PATH")
    args = ap.parse_args(argv)
    args.agent = resources.resolve_agent(args.agent) if args.agent else AGENT_PATH
    try:                                     # first: an install built without Node has no agent, and that is the whole answer
        source = load_agent_source(args.agent)
    except FileNotFoundError as e:
        sys.exit(f"[!] {e}")
    settings = resolve_settings(args)

    try:
        from_report = load_relocate_report(args.from_relocate) if args.from_relocate else []
        candidates = gather_candidates(from_report, args.candidate, settings.offsets.get(args.key), args.key)
        record = pick_record(settings.params, args.key, args.record)
    except CandidateError as e:
        sys.exit(f"[!] {e}")

    settings.params["verify"] = {"record": record,
                                 "candidates": [{"id": c["id"], "rva": c["rva"]} for c in candidates]}
    labels = {c["id"]: c["label"] for c in candidates}
    for c in candidates:
        print(f"[i] {c['id']}: RVA 0x{c['rva']:x}  ({c['label']})")
    print(f"[i] record = {record}, min records = {args.min_records}")

    if args.json and is_gitignored(args.json) is False:
        print(f"[!] --json {args.json} is NOT covered by .gitignore, and it names real offsets. "
              f"Keep it out of git - or use a verify*.json name.")

    device = frida.get_device_manager().add_remote_device(settings.remote_addr)

    gone = threading.Event()
    why_gone = []

    def on_detached(reason, crash=None):
        # "application-requested" is our own detach at the end; anything else ended the session under us.
        if reason != "application-requested":
            why_gone.append(reason)
            gone.set()
            print(f"[!] Session detached, reason: {reason}")

    print(f"[*] Spawning {settings.target}...")
    try:
        with spawn_agent(device, settings.target, source, on_message, on_detached,
                         params=settings.params) as run:
            require_verify_agent(run, args.agent)
            run.resume()
            print(f"[*] Spawned and resumed, pid={run.pid}")
            print("[*] Use the app so the code that calls the candidates runs (open the screen that loads the "
                  "table).")
            print("[*] " + (f"Waiting up to {args.wait:g} s" if args.wait else "Waiting")
                  + "; press Enter to judge what was seen so far.\n")
            snapshot = watch(run.script, gone, args.min_records, args.wait, labels, poll=POLL_SECONDS)
    except (AgentInitError, NotAVerifyAgent) as e:
        sys.exit(f"[!] {e} (the app was not left running)")

    reason = why_gone[0] if why_gone else None
    crashed = reason if reason == "process-terminated" else None
    result = verification.judge(snapshot, args.min_records, args.layout_tolerance, crashed=crashed,
                                labels=labels, ended=reason)
    print()
    for line in verification.render(result):
        print(line)
    if args.json:
        write_report(args.json, settings, record, candidates, result)
    if result.exit_code:
        sys.exit(result.exit_code)


if __name__ == "__main__":
    main()
