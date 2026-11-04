"""
check_identifiers.py

Blocks names taken from a REAL target from reaching git.

Offsets and package ids need no guard: they live in a profile kept outside git
(profiles.py), and no agent or driver contains one. A class, method or field
name is different - it can still slip into a doc, a test or a comment. This
checker knows what the real names ARE, and fails if one shows up anywhere in
the tree.

How it knows them without the repo containing them
--------------------------------------------------
tools/identifier_denylist.txt holds SHA-256 digests, not names. Each digest is
of a normalized name: lower-cased, every separator and case boundary removed
(`DeviceFooBar`, `device_foo_bar`, `DEVICE-FOO-BAR` and `deviceFooBar` all
normalize to `devicefoobar`). So committing the list does not publish what is
on it, and the checker still catches a name however it is spelled.

What is checked
---------------
Every text file in the tree (tracked, plus untracked-but-not-ignored; with
--staged, the staged blobs) AND every file/directory name. Text is cut into
identifier chains (`[A-Za-z0-9]` runs joined by `_` or `-`), each chain into
sub-words at `_`/`-`, camelCase and letter/digit boundaries, and every run of up
to 8 consecutive sub-words is normalized, hashed and looked up. So a listed
name is found as a whole identifier (`DeviceFooBar`), inside a longer one
(`getDeviceFooBarEntry`, `dump_device_foo_bar_list.js`), and in any casing or
separator style.

What it does NOT do
-------------------
  - Prose. "device foo bar" written as separate words is not an identifier
    chain, so it is not matched. Rewrite prose by hand; the pre-commit hook is
    for the accidents that happen when code is pasted in.
  - Anything it was never told about: it can only catch names that are on the
    list. A name that is renamed in a way that keeps it recognizable
    (`DeviceFooBarX`) is caught; a different word for the same idea is not.
  - Git history. Removing a name from the tree does not remove it from commits
    that already contain it.
  - Hash look-ups are not secrecy: a short, guessable name can be recovered
    from its digest by someone who tries enough guesses. The list keeps the
    names out of casual view (grep, code search, a reviewer's eyes); it is not
    encryption. Keep anything that must stay private in a private profile.

Maintaining the list
--------------------
    python tools/check_identifiers.py --add NameOne name_two ...
    python tools/check_identifiers.py --add-file profiles/myapp/names.txt
    python tools/check_identifiers.py --hash NameOne        # print digest, write nothing

`--add` normalizes the names and appends their digests (skipping ones already
listed); it prints how many it added, never the names. A name can be a whole
identifier or a distinctive compound from inside one (`foo_bar`).
`--add-file` reads one name per line (blank lines and `#` comments ignored).
Keep that file in your private profile, not in the repo.

A private plain-text list can also be checked WITHOUT being hashed into the
repo: `--denylist-file PATH` (or $RE_TOOLKIT_DENYLIST) names a file with one
name per line, checked in addition to the committed digests.

Failures print `file:line` and the first 8 hex digits of the matching digest,
not the name (CI logs are often public). Re-run locally with `--show` to see
the matching text.

Wired in two places, both calling this same script:
  - .githooks/pre-commit (staged files only)
  - .github/workflows/ci.yml, job `names` (whole tree, every push/PR)

Usage:
    python3 tools/check_identifiers.py            # whole tree (git-aware)
    python3 tools/check_identifiers.py --staged   # staged files only
    python3 tools/check_identifiers.py --show     # print the matching text

Exit status: 0 = clean, 1 = a listed name was found, 2 = bad usage/list.

Zero third-party dependencies on purpose - this runs in a bare pre-commit hook
and a minimal CI job.
"""
import argparse
import bisect
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DENYLIST_PATH = Path(__file__).resolve().parent / "identifier_denylist.txt"
ENV_DENYLIST_FILE = "RE_TOOLKIT_DENYLIST"

# Longest run of sub-words tried as one name. Real class/method names are
# 2-6 words; 8 leaves headroom without making every long identifier expensive.
MAX_WINDOW = 8

# Directories that hold generated or private material, never source.
SKIP_DIRS = {"node_modules", "dist", "build", "profiles", ".git", "__pycache__", ".pytest_cache"}

_CHAIN_RE = re.compile(r"[A-Za-z0-9]+(?:[_\-][A-Za-z0-9]+)*")
_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_HEADER = """\
# SHA-256 digests of normalized names (lower-case letters and digits only).
# One per line. These are NOT the names - see tools/check_identifiers.py for
# what is checked, what is not, and how to add to this list. Do not write
# plain names in this file.
"""


class DenylistError(ValueError):
    pass


# ---------------------------------------------------------------------------
# normalization + matching
# ---------------------------------------------------------------------------

def normalize(name):
    """`DeviceFooBar` / `device_foo_bar` / `DEVICE-FOO-BAR` -> `devicefoobar`.
    Only letters and digits survive; case and separators are dropped."""
    return "".join(ch for ch in str(name).lower() if ch.isalnum() and ch.isascii())


def digest(name):
    return hashlib.sha256(normalize(name).encode("ascii")).hexdigest()


def _subwords(chain):
    words = []
    for part in re.split(r"[_\-]", chain):
        words += _WORD_RE.findall(part)
    return words


def find_in_text(text, denied):
    """[(line, digest, chain)] for every denied name found in `text`, where
    `chain` is the whole identifier it was found in. `denied` is a set of hex
    digests. One finding per (line, digest)."""
    newlines = [i for i, ch in enumerate(text) if ch == "\n"]
    found, seen = [], set()
    for m in _CHAIN_RE.finditer(text):
        chain = m.group(0)
        words = [w.lower() for w in _subwords(chain)]
        line = bisect.bisect_left(newlines, m.start()) + 1
        for i in range(len(words)):
            acc = ""
            for j in range(i, min(len(words), i + MAX_WINDOW)):
                acc += words[j]
                d = hashlib.sha256(acc.encode("ascii")).hexdigest()
                if d in denied and (line, d) not in seen:
                    seen.add((line, d))
                    found.append((line, d, chain))
    return found


# ---------------------------------------------------------------------------
# the list
# ---------------------------------------------------------------------------

def load_digests(path=DENYLIST_PATH):
    """The set of digests in `path`. A line that isn't a 64-hex digest is an
    error (it would mean a plain name was written there)."""
    digests = set()
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return digests
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not _DIGEST_RE.fullmatch(line):
            raise DenylistError(f"{path}:{n}: not a SHA-256 digest - the list must hold digests, never names")
        digests.add(line)
    return digests


def load_plain_names(path):
    """Digests of the names in a plain one-per-line file (kept private)."""
    out = set()
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            norm = normalize(line)
            if norm:
                out.add(hashlib.sha256(norm.encode("ascii")).hexdigest())
    return out


def add_names(names, path=DENYLIST_PATH):
    """Append the digests of `names` to the list (creating it with its header).
    Returns how many were new."""
    have = load_digests(path)
    fresh = []
    for name in names:
        if not normalize(name):
            raise DenylistError(f"{name!r} has no letters or digits")
        d = digest(name)
        if d not in have and d not in fresh:
            fresh.append(d)
    if fresh:
        p = Path(path)
        existing = p.read_text(encoding="utf-8") if p.exists() else _HEADER
        if not existing.endswith("\n"):
            existing += "\n"
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(existing + "".join(d + "\n" for d in fresh))
    return len(fresh)


# ---------------------------------------------------------------------------
# which files
# ---------------------------------------------------------------------------

def _git(*args):
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, check=True)


def _split_z(raw):
    return [os.fsdecode(p) for p in raw.split(b"\0") if p]


def _staged_paths():
    """Repo-relative paths staged for commit, everything except deletions.
    `-z` so odd/non-ASCII names aren't C-quoted; `--no-renames` + `d` so the
    result doesn't depend on diff.renames and includes A/C/M/R/T alike."""
    return _split_z(_git("diff", "--cached", "--name-only", "-z", "--no-renames",
                         "--diff-filter=d").stdout)


def _all_paths():
    """Every file that could be committed: tracked + untracked-not-ignored (so a
    git-ignored local file isn't flagged). Falls back to walking the tree when
    this isn't a git checkout."""
    try:
        return _split_z(_git("ls-files", "-z", "--cached", "--others", "--exclude-standard").stdout)
    except (OSError, subprocess.CalledProcessError):
        rels = []
        for root, dirs, files in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            for f in files:
                rels.append((Path(root) / f).relative_to(REPO_ROOT).as_posix())
        return rels


def _skipped(rel):
    return any(part in SKIP_DIRS for part in Path(rel).parts)


def _is_binary(data):
    return b"\0" in data[:8192]


def check_path_name(rel, denied, findings, show=False):
    """A denied name in a file or directory name."""
    for _line, d, chain in find_in_text(rel, denied):
        findings.append(_finding(rel, None, d, chain, show))


def check_file(rel, denied, findings, staged=False, show=False):
    path = REPO_ROOT / rel
    data = None
    try:
        if staged:
            data = _git("show", f":0:{Path(rel).as_posix()}").stdout
        else:
            data = path.read_bytes()
    except Exception as e:  # unreadable: refuse to skip it silently
        if isinstance(e, FileNotFoundError) and not staged:
            return
        findings.append(f"{rel}: could not read {'staged ' if staged else ''}content "
                        f"({type(e).__name__}) - refusing to skip it")
        return
    if _is_binary(data):
        return
    text = data.decode("utf-8", errors="replace")
    for line, d, chain in find_in_text(text, denied):
        findings.append(_finding(rel, line, d, chain, show))


def _finding(rel, line, d, chain, show):
    where = f"{rel}:{line}" if line else f"{rel} (file name)"
    what = f"matches denylist entry {d[:8]}"
    if show:
        what += f" in {chain!r}"
    return f"{where}: {what}"


def scan(denied, staged=False, show=False):
    rels = _staged_paths() if staged else _all_paths()
    findings = []
    for rel in sorted(set(rels)):
        if _skipped(rel):
            continue
        check_path_name(rel, denied, findings, show)
        check_file(rel, denied, findings, staged=staged, show=show)
    return findings


# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Fail if a name from a real target (digest on tools/identifier_denylist.txt) "
                    "appears anywhere in the tree.")
    ap.add_argument("--staged", action="store_true", help="check staged files only (pre-commit)")
    ap.add_argument("--show", action="store_true", help="print the matching identifier too")
    ap.add_argument("--denylist", metavar="PATH", default=str(DENYLIST_PATH),
                    help="digest list to use (default: tools/identifier_denylist.txt)")
    ap.add_argument("--denylist-file", metavar="PATH", default=os.environ.get(ENV_DENYLIST_FILE),
                    help=f"also check the plain names in PATH, one per line (env: {ENV_DENYLIST_FILE})")
    ap.add_argument("--add", nargs="+", metavar="NAME", help="add names to the digest list and exit")
    ap.add_argument("--add-file", metavar="PATH", help="add the names in PATH (one per line) and exit")
    ap.add_argument("--hash", nargs="+", metavar="NAME", help="print the digest of each name and exit")
    args = ap.parse_args(argv)

    try:
        if args.hash:
            for name in args.hash:
                print(digest(name))
            return 0
        if args.add or args.add_file:
            names = list(args.add or [])
            if args.add_file:
                names += [ln.strip() for ln in Path(args.add_file).read_text(encoding="utf-8").splitlines()
                          if ln.strip() and not ln.strip().startswith("#")]
            n = add_names(names, args.denylist)
            print(f"added {n} digest(s) to {args.denylist}" if n else "nothing new to add")
            return 0
        denied = load_digests(args.denylist)
        if args.denylist_file:
            denied |= load_plain_names(args.denylist_file)
    except (DenylistError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if not denied:
        print("error: the denylist is empty - nothing to check against. "
              "Add names with --add (see the docstring).", file=sys.stderr)
        return 2

    findings = scan(denied, staged=args.staged, show=args.show)
    if findings:
        print("BLOCKED: a name from a real target is in the tree:\n", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        print("\nKeep real names in a private profile (docs/PROFILES.md) and use the "
              "neutral ones here. Re-run with --show locally to see what matched.", file=sys.stderr)
        return 1

    print(f"OK: none of the {len(denied)} listed names found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
