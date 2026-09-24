"""
check_placeholders.py

Safeguard for this "generic template" repo (see README.md): a real
Ghidra-derived offset or a real app's package/bundle id must never land in
git history, even by accident. The runtime `if (OFFSET === 0x0) throw ...`
guards in scripts/*.js only fire *after* something's been typed in; this
script is the automated backstop that runs *before* a real value can be
committed at all.

Why it looks at values, not just names
--------------------------------------
Earlier versions found an "offset-looking" *line* (`const NAME = VALUE;`)
and judged VALUE. Every round of review found another spelling that dodged
the line pattern: `export const`, a name like HOOK_RVA, the value on the
next line, a second declaration on the same line, a table or `[x][0]`
(which the old code deliberately skipped), a renamed file (git status `R`),
a type-hinted `FRIDA_OFFSET: int = ...` in config.py. Patching one shape at
a time can't converge, so the checks are layered so that no single
spelling matters:

  Layer 1 - by VALUE, independent of any syntax (JS/TS files):
      Any numeric literal >= ADDRESS_LITERAL_MIN (0x10000) anywhere in the
      file's raw text is a violation - in code, in a string (`ptr("0x...")`),
      in a comment, in a table, glued to an identifier (`hook_0xab68fc8`),
      or as a Ghidra/IDA auto-name (`FUN_00ab68fc8`, `sub_AB68FC8`).
      No identifier, keyword, line layout or wrapper function is involved,
      so there is nothing to spell differently. Exempt, because none of
      them is a function address and Frida agents use them: exact powers
      of two, all-ones masks (0x100000, 0xffffffff, 0x7fffffff), and a few
      file-format magics (Mach-O, fat Mach-O, ELF). Hex is looked for in
      comments too; plain decimals are not (there they're issue numbers,
      dates and URLs, not addresses), and neither are decimals that are
      part of a URL path, `#123` ref or UUID segment.

  Layer 2 - by NAME, for values too small for layer 1 (JS/TS files):
      A tokenizer (not a line regex) finds every `NAME = ...` where NAME
      contains "offset" or is an RVA (`HOOK_RVA`, `hookRva`), wherever it
      appears: after `export`, as the second declarator of a line, inside a
      destructuring default, as `this.offset = ...`. The right-hand side is
      read across lines until the statement really ends. Then:
        - a table (name ends in "Offsets", e.g. `const OFFSETS = {...}`)
          is allowed - it holds documented struct-layout constants (see
          docs/MEMORY_LAYOUT.md) - but every entry must be <= FIELD_OFFSET_MAX
          (0x1000). A hook address dropped into that table is blocked.
        - anything else whose right-hand side is an object/array literal
          is a violation (`const FRIDA_OFFSET = [0x..][0]` included).
        - a constant expression (only literals plus ptr/BigInt/Number/
          parseInt/...) must be zero, however it's spelled. An expression
          that reads other identifiers (`mod.base.add(FRIDA_OFFSET)`,
          `require("./local.js").offset`) is not judged: it can't hold a
          literal value, and layer 1 still covers any big literal in it.
      `for (...)` headers are skipped (`for (let offset = 8; ...)` loops
      are legitimate) and so are compound assignments like `offset += 8`.

  Python - tools/config.py (via the stdlib `ast`, not a regex):
      Every binding of TARGET, FRIDA_OFFSET, or an offset/RVA-named
      variable is found however it's written: plain, annotated
      (`FRIDA_OFFSET: int = ...`), chained, tuple-unpacked, augmented,
      walrus, `cfg["TARGET"] = ...`, over any number of lines. TARGET must
      fold to exactly "com.example.unitygame"; offsets must fold to zero.
      Anything the checker can't fold to a constant is a violation
      (allow-list, not block-list). The raw layer-1 scan also runs on the
      file's text, comments included. A file that doesn't parse is a
      violation rather than a guess.

Which files
-----------
  - every .js/.mjs/.cjs/.jsx/.ts/.mts/.cts/.tsx file anywhere in the repo
    (except node_modules/) - not just scripts/ and legacy/, otherwise moving
    a file is a bypass;
  - tools/config.py.
`--staged` takes the file list from the index (`git diff --cached -z
--no-renames --diff-filter=d`: everything staged except deletions, so
renames, copies, type changes and non-ASCII names are all included) and
reads each file's *staged* blob (`git show :path`), never the working
tree - so a value that's staged and then reset on disk is still caught, a
value that's only edited on disk isn't flagged, and a file that's staged
but no longer on disk can't be skipped.

What this does NOT do (no static check can; this one aims at "by accident",
not at someone deliberately obfuscating). A legitimate number that trips
layer 1 (a 100000 ms timeout, an AArch64 instruction word like 0xd65f03c0)
is meant to be rewritten as an expression (`100 * 1000`) or bytes, not
exempted - an exemption list is exactly the kind of gap this file used to
have:
  - a value assembled at runtime or split up (`0xab68 << 16 | 0xfc8`,
    `parseInt("ab68fc8", 16)` with no 0x prefix, scientific notation) -
    only a *named* constant expression is judged, and only unprefixed hex
    inside a table is;
  - a real offset below 0x10000 that isn't in an offset/RVA-named constant
    (a real function RVA that low is essentially not a thing);
  - real values in the README, docs, tools/*.py other than config.py, or
    tests/ (see README "Keeping real offsets out of git");
  - a renamed class/namespace (ExampleNamespace -> something real), or a
    real package id anywhere other than config.py's TARGET: unlike an
    offset there's no value to test, only a placeholder to diff against;
  - dynamic writes to config (`globals()["TARGET"] = ...`, `setattr`);
  - the tokenizer is not a full JS parser: a regex literal containing a
    quote can mis-pair strings on that line and hide a small (< 0x10000)
    named value there; layer 1 is raw text and is unaffected.

Wired in two places, both calling this same script:
  - .githooks/pre-commit (staged files only - install with
    `git config core.hooksPath .githooks`, see README.md)
  - .github/workflows/check-placeholders.yml (the whole tree on every push/
    PR - catches it even for someone who never installed the hook, or who
    used `git commit --no-verify`)

Usage:
    python3 tools/check_placeholders.py            # whole repo (git-aware)
    python3 tools/check_placeholders.py --staged   # staged files only

Exit status: 0 = clean, 1 = a real value was found.

Zero third-party dependencies on purpose - this has to run in a bare
pre-commit hook and a minimal CI job with no `pip install` step.
"""
import ast
import os
import re
import subprocess
import sys
from collections import namedtuple
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PLACEHOLDER_TARGET = "com.example.unitygame"

# Layer 1: any literal this large is treated as a real code address. Every
# numeric literal in scripts/ + legacy/ today is <= 0x1000 (record-field
# offsets, buffer sizes), so this has no false positives on the current
# tree; if a legitimate large constant ever trips it, write it as a power
# of two / all-ones mask, or raise this deliberately.
ADDRESS_LITERAL_MIN = 0x10000

# Layer 2: largest value allowed inside a `*Offsets` struct-layout table.
FIELD_OFFSET_MAX = 0x1000

JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx")
CONFIG_PY = "tools/config.py"

_HINT = (
    "\nThis repo is a generic template (see README.md) - real offsets and "
    "target\nids must never be committed. Reset the value to its placeholder "
    "before\ncommitting; keep your real value out of git entirely (pass it via "
    "--offset\n/ --target, $FRIDA_OFFSET / $FRIDA_TARGET, or a git-ignored "
    "local file instead\nof editing the source in place).\n"
    "\nIf a flagged number is really a size/timeout/instruction word rather "
    "than an\naddress, write it as an expression (`100 * 1000`) or as bytes, or "
    "a power of two.\n"
)


# ---------------------------------------------------------------------------
# small shared helpers
# ---------------------------------------------------------------------------

def _display(path):
    """Repo-relative path for messages when possible, else the raw path (tests
    pass in tmp_path fixtures that aren't under REPO_ROOT)."""
    try:
        return Path(path).relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def _int_or_none(s):
    """int(s) for '0x..', '0b..', '0o..', decimal (leading zeros too), else None."""
    for base in (0, 10):
        try:
            return int(s, base)
        except ValueError:
            continue
    return None


def _num_value(tok_text):
    """Value of a JS numeric token ('0xab_68', '17n', '1.5', '08'), or None."""
    s = tok_text.replace("_", "")
    if s[-1:] in ("n", "N"):
        s = s[:-1]
    v = _int_or_none(s)
    if v is not None:
        return v
    try:
        return float(s)
    except ValueError:
        return None


def _str_value(body, allow_bare_hex=False):
    """Numeric value of the *contents* of a string literal, or None if it
    isn't a number. `allow_bare_hex` also accepts 'ab68fc8' (no 0x)."""
    s = body.strip().replace("_", "")
    if not s:
        return None
    v = _int_or_none(s)
    if v is not None:
        return v
    if allow_bare_hex and re.fullmatch(r"[0-9a-fA-F]{5,}", s):
        return int(s, 16)
    return None


_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")


def _is_offset_name(name):
    """True for identifiers that say they hold an offset / RVA: anything
    containing 'offset' (FRIDA_OFFSET, OFFSET_GetFoo, offset), or an RVA as a
    whole word (HOOK_RVA, hookRva). Deliberately narrow - `addr`/`address`
    are ordinary names for locals (`const addr = mod.base.add(...)`) and
    config (REMOTE_ADDR); layer 1 covers big values there regardless."""
    if "offset" in name.lower():
        return True
    return "rva" in {w.lower() for w in _WORD_RE.findall(name)}


def _is_table_name(name):
    """A struct-layout table by naming convention: OFFSETS, fieldOffsets, ..."""
    return name.lower().endswith("offsets")


# ---------------------------------------------------------------------------
# Layer 1 - by value, raw text, no syntax involved
# ---------------------------------------------------------------------------

# 0x literals are matched even when glued to an identifier (hook_0xab68fc8).
_RAW_HEX_RE = re.compile(r"0[xX][0-9a-fA-F_]+")
# Decimal literals must stand alone: not part of an identifier (sha256), a
# URL path or issue ref (/123456, #123456) or a UUID segment (-123456789012).
_RAW_DEC_RE = re.compile(r"(?<![\w$./#-])\d[\d_]*[nN]?(?![\w$])")
# Ghidra / IDA auto-generated names carry the address: FUN_00ab68fc8, sub_AB68FC8.
_RAW_AUTONAME_RE = re.compile(
    r"(?<![\w$])(?:FUN|sub|loc|off|unk|LAB|DAT|PTR|thunk_FUN)_([0-9a-fA-F]{6,})(?![\w$])"
)


# File-format magics a Frida agent may legitimately compare against.
_KNOWN_MAGIC = {
    0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe,   # Mach-O
    0xcafebabe, 0xbebafeca, 0xdeadbeef,               # fat Mach-O / Java / classic
    0x464c457f, 0x7f454c46,                           # ELF
}


def _is_benign_large(v):
    """Exact power of two, all-ones mask, or a well-known magic number: never
    a function address."""
    return v & (v - 1) == 0 or v & (v + 1) == 0 or v in _KNOWN_MAGIC


def _large_literal_findings(text, dec_text=None):
    """[(line, shown, value)] for every address-sized literal in raw `text`.
    0x literals and Ghidra/IDA names are looked for everywhere, comments
    included (the likely accident is `// hooked at 0x...`). Decimals are
    looked for in `dec_text` (`text` with comments blanked out): in comments
    they're overwhelmingly issue numbers, dates and URLs, not addresses."""
    found = []
    dec_text = text if dec_text is None else dec_text
    for rx, src, conv in (
        (_RAW_HEX_RE, text, lambda m: _int_or_none(m.group(0).replace("_", ""))),
        (_RAW_DEC_RE, dec_text, lambda m: _int_or_none(m.group(0).rstrip("nN").replace("_", ""))),
        (_RAW_AUTONAME_RE, text, lambda m: int(m.group(1), 16)),
    ):
        for m in rx.finditer(src):
            v = conv(m)
            if v is not None and v >= ADDRESS_LITERAL_MIN and not _is_benign_large(v):
                found.append((_line_of(text, m.start()), m.group(0), v))
    return found


def _report_large_literals(text, disp, violations, already_reported_lines, dec_text=None):
    for line, shown, v in sorted(_large_literal_findings(text, dec_text)):
        if line in already_reported_lines:
            continue
        already_reported_lines.add(line)
        violations.append(
            f"{disp}:{line}: {shown} (= {v:#x}) "
            f"(a literal >= {ADDRESS_LITERAL_MIN:#x} looks like a real code "
            f"address - must not be committed, in code, strings or comments)")


# ---------------------------------------------------------------------------
# Layer 2 (JS/TS) - by name, on a token stream
# ---------------------------------------------------------------------------

_Tok = namedtuple("_Tok", "kind text nl_before pos")

_JS_TOKEN_RE = re.compile(
    r"""
      (?P<ws>[ \t\r\f\v]+)
    | (?P<nl>\n)
    | (?P<comment>//[^\n]*|/\*.*?\*/)
    | (?P<str>"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')
    | (?P<tpl>`(?:[^`\\]|\\.)*`)
    | (?P<num>0[xX][0-9a-fA-F_]+[nN]?|0[bB][01_]+[nN]?|0[oO][0-7_]+[nN]?
             |(?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d+)?[nN]?)
    | (?P<id>[A-Za-z_$][\w$]*)
    | (?P<punct>>>>=|\.\.\.|===|!==|\*\*=|<<=|>>=|>>>|&&=|\|\|=|\?\?=|=>|==|!=|<=|>=
               |&&|\|\||\?\?|\+\+|--|[+\-*/%&|^]=|<<|>>|\*\*|\?\.|.)
    """,
    re.VERBOSE | re.DOTALL,
)
# An unterminated quote/comment doesn't match str/comment and falls through
# to the single-character `punct` branch, so a stray quote (e.g. inside a
# regex literal) can't swallow the rest of the file.


def _js_tokens(text):
    toks, nl = [], False
    for m in _JS_TOKEN_RE.finditer(text):
        kind = m.lastgroup
        if kind == "ws":
            continue
        if kind == "nl":
            nl = True
            continue
        if kind == "comment":
            if "\n" in m.group(0):
                nl = True
            continue
        toks.append(_Tok(kind, m.group(0), nl, m.start()))
        nl = False
    return toks


def _blank(text, spans):
    """`text` with each (start, end) span replaced by spaces (newlines kept,
    so line numbers don't move)."""
    out, last = [], 0
    for a, b in spans:
        out.append(text[last:a])
        out.append(re.sub(r"[^\n]", " ", text[a:b]))
        last = b
    out.append(text[last:])
    return "".join(out)


def _js_without_comments(text):
    return _blank(text, [m.span() for m in _JS_TOKEN_RE.finditer(text)
                         if m.lastgroup == "comment"])


def _py_without_comments(text):
    import io
    import tokenize
    try:
        lines = text.splitlines(keepends=True)
        offs = [0]
        for ln in lines:
            offs.append(offs[-1] + len(ln))
        spans = []
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                spans.append((offs[tok.start[0] - 1] + tok.start[1],
                              offs[tok.end[0] - 1] + tok.end[1]))
        return _blank(text, spans)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return text


_OPEN, _CLOSE = {"(", "[", "{"}, {")", "]", "}"}
_BINARY_OPS = {
    "+", "-", "*", "/", "%", "&", "|", "^", "<", ">", "<<", ">>", ">>>", "**",
    "&&", "||", "??", "==", "===", "!=", "!==", "<=", ">=", "?", ":", "=", ".",
    "?.", "=>", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=",
    "**=", "&&=", "||=", "??=",
}
# Identifiers a *constant* right-hand side may use (wrappers and literals).
_CONST_WORDS = {
    "ptr", "BigInt", "Number", "parseInt", "parseFloat", "NativePointer",
    "int64", "uint64", "new", "null", "undefined", "true", "false",
}


def _continues(prev, tok):
    """Does `tok`, at the start of a new line, continue the expression that
    ends in `prev` (dangling operator, or a leading operator/call/index)?"""
    if prev.kind == "punct" and prev.text in _BINARY_OPS:
        return True
    if tok.kind == "punct" and (tok.text in _BINARY_OPS or tok.text in ("(", "[")):
        return True
    return tok.kind == "id" and tok.text in ("in", "instanceof")


def _rhs_tokens(toks, k):
    """Tokens of the right-hand side starting at index `k`: up to a `;` or `,`
    at nesting depth 0, a closing bracket of an enclosing construct, or a
    newline that doesn't continue the expression. Multi-line values and
    values on the line after `=` are included."""
    out, depth = [], 0
    while k < len(toks):
        t = toks[k]
        punct = t.kind == "punct"
        if depth == 0:
            if punct and (t.text in (";", ",") or t.text in _CLOSE):
                break
            if out and t.nl_before and not _continues(out[-1], t):
                break
        if punct and t.text in _OPEN:
            depth += 1
        elif punct and t.text in _CLOSE:
            depth -= 1
        out.append(t)
        k += 1
    return out


def _for_header_indexes(toks):
    """Token indexes inside `for (...)` headers - loop counters legitimately
    start at a non-zero `offset`."""
    skip = set()
    for i, t in enumerate(toks):
        if t.kind == "id" and t.text == "for":
            j = i + 1
            if j < len(toks) and toks[j].kind == "id" and toks[j].text == "await":
                j += 1
            if j < len(toks) and toks[j].text == "(":
                depth = 0
                for k in range(j, len(toks)):
                    if toks[k].kind != "punct":
                        continue
                    if toks[k].text == "(":
                        depth += 1
                    elif toks[k].text == ")":
                        depth -= 1
                        if depth == 0:
                            skip.update(range(j, k + 1))
                            break
    return skip


def _is_constant_expr(rhs):
    for t in rhs:
        if t.kind == "id" and t.text not in _CONST_WORDS:
            return False
        if t.kind == "tpl" and "${" in t.text:
            return False
    return True


def _over_field_cap(rhs):
    """Reason string if any numeric literal in `rhs` (numeric strings and
    unprefixed hex strings included) is above FIELD_OFFSET_MAX, else None."""
    for t in rhs:
        if t.kind == "num":
            v = _num_value(t.text)
        elif t.kind in ("str", "tpl"):
            v = _str_value(t.text[1:-1], allow_bare_hex=True)
        else:
            continue
        if v is not None and abs(v) > FIELD_OFFSET_MAX:
            return (f"{t.text} is above {FIELD_OFFSET_MAX:#x} - only small struct-field "
                    f"offsets are allowed in an offset-named value; this looks like a "
                    f"code address")
    return None


def _judge_rhs(name, rhs):
    """None if fine, else a short reason this RHS isn't an acceptable value
    for the offset-named variable `name`."""
    if not rhs:
        return None

    if _is_table_name(name):
        return _over_field_cap(rhs)

    if rhs[0].kind == "punct" and rhs[0].text in ("{", "["):
        return ("an offset must be a plain zero placeholder, not an object/array "
                "literal (only tables named *Offsets may be)")

    if not _is_constant_expr(rhs):
        # Reads other identifiers (`mod.base.add(FRIDA_OFFSET)`, a ternary):
        # not a bare literal, so it needn't be zero - but it still mustn't
        # smuggle in an address-sized number.
        return _over_field_cap(rhs)

    for t in rhs:
        if t.kind == "num":
            v = _num_value(t.text)
        elif t.kind in ("str", "tpl"):
            v = _str_value(t.text[1:-1])
        else:
            continue
        if v != 0:
            return "must stay a zero placeholder in git - this looks like a real offset"
    return None


def _shown(text, rhs):
    s = " ".join(text[rhs[0].pos:rhs[-1].pos + len(rhs[-1].text)].split())
    return s if len(s) <= 80 else s[:77] + "..."


def _named_js_findings(text):
    """[(line, name, shown_rhs, reason)] for offset-named `NAME = ...`."""
    toks = _js_tokens(text)
    skip = _for_header_indexes(toks)
    found = []
    for i in range(len(toks) - 1):
        t, nxt = toks[i], toks[i + 1]
        if t.kind != "id" or i in skip or not _is_offset_name(t.text):
            continue
        if not (nxt.kind == "punct" and nxt.text == "="):
            continue
        rhs = _rhs_tokens(toks, i + 2)
        reason = _judge_rhs(t.text, rhs)
        if reason:
            found.append((_line_of(text, t.pos), t.text, _shown(text, rhs), reason))
    return found


# ---------------------------------------------------------------------------
# reading files / choosing files
# ---------------------------------------------------------------------------

def _git(*args):
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, check=True)


def _read_text(path, staged, violations=None):
    """Content of `path`: the *staged* blob (`git show :path`, i.e. the index)
    when `staged`, otherwise whatever's on disk. Decoding never raises - a
    non-UTF-8 byte must not crash the hook. Returns None if unreadable (and
    records why, when `violations` is given, so it fails closed)."""
    try:
        if staged:
            try:
                rel = Path(path).relative_to(REPO_ROOT)
            except ValueError:
                rel = Path(path).resolve().relative_to(REPO_ROOT)
            data = _git("show", f":0:{rel.as_posix()}").stdout
        else:
            data = Path(path).read_bytes()
    except (OSError, subprocess.CalledProcessError) as e:
        if violations is not None and not (isinstance(e, FileNotFoundError) and not staged):
            violations.append(f"{_display(path)}: could not read {'staged' if staged else ''} "
                              f"content ({type(e).__name__}) - refusing to skip it")
        return None
    return data.decode("utf-8", errors="replace")


def _split_z(raw):
    return [os.fsdecode(p) for p in raw.split(b"\0") if p]


def _staged_paths():
    """Repo-relative paths staged for commit, everything except deletions.
    `-z` so odd/non-ASCII names aren't C-quoted (a quoted name would match no
    real file and be silently skipped); `--no-renames` + `d` so the result
    doesn't depend on diff.renames and includes A/C/M/R/T alike."""
    out = _git("diff", "--cached", "--name-only", "-z", "--no-renames",
               "--diff-filter=d").stdout
    return _split_z(out)


def _all_paths():
    """Every file that could be committed: tracked + untracked-not-ignored
    (so a git-ignored local file holding your real offset isn't flagged).
    Falls back to walking the tree when this isn't a git checkout."""
    try:
        return _split_z(_git("ls-files", "-z", "--cached", "--others",
                             "--exclude-standard").stdout)
    except (OSError, subprocess.CalledProcessError):
        rels = []
        for root, dirs, files in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            for f in files:
                rels.append((Path(root) / f).relative_to(REPO_ROOT).as_posix())
        return rels


def _is_js_path(rel):
    p = Path(rel)
    return rel.lower().endswith(JS_EXTENSIONS) and "node_modules" not in p.parts


# ---------------------------------------------------------------------------
# per-file checks
# ---------------------------------------------------------------------------

def check_js_file(path, violations, staged=False):
    """Append a violation for every real-looking offset in a JS/TS file: any
    address-sized literal (layer 1) and any offset-named assignment whose
    value isn't a zero placeholder (layer 2), however it's spelled."""
    text = _read_text(path, staged, violations)
    if text is None:
        return
    disp = _display(path)
    reported = set()
    for line, name, shown, reason in _named_js_findings(text):
        reported.add(line)
        violations.append(f"{disp}:{line}: {name} = {shown} ({reason})")
    _report_large_literals(text, disp, violations, reported, _js_without_comments(text))


_UNKNOWN = object()  # a binding whose value the checker can't see


def _py_bindings(tree):
    """Yield (name, value_node_or_UNKNOWN, lineno, augmented) for every place
    the tree binds a name: `=`, annotated, chained, tuple-unpacked, `+=`,
    walrus, and constant-string subscripts (`cfg["TARGET"] = ...`)."""

    def flatten(target, value):
        if isinstance(target, ast.Name):
            yield target.id, value
        elif isinstance(target, ast.Attribute):
            yield target.attr, value
        elif (isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant)
              and isinstance(target.slice.value, str)):
            yield target.slice.value, value
        elif isinstance(target, (ast.Tuple, ast.List)):
            paired = (isinstance(value, (ast.Tuple, ast.List))
                      and len(value.elts) == len(target.elts)
                      and not any(isinstance(e, ast.Starred) for e in value.elts + target.elts))
            for idx, elt in enumerate(target.elts):
                yield from flatten(elt, value.elts[idx] if paired else _UNKNOWN)
        elif isinstance(target, ast.Starred):
            yield from flatten(target.value, _UNKNOWN)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                for name, val in flatten(tgt, node.value):
                    yield name, val, node.lineno, False
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            for name, val in flatten(node.target, node.value):
                yield name, val, node.lineno, False
        elif isinstance(node, ast.AugAssign):
            for name, val in flatten(node.target, node.value):
                yield name, val, node.lineno, True
        elif isinstance(node, ast.NamedExpr):
            for name, val in flatten(node.target, node.value):
                yield name, val, node.lineno, False


def _py_fold(node):
    """Fold a constant expression (literals, unary/binary ops on ints,
    str concatenation) to (True, value); (False, None) if it isn't one."""
    if node is _UNKNOWN:
        return False, None
    if isinstance(node, ast.Constant):
        return True, node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd, ast.Invert)):
        ok, v = _py_fold(node.operand)
        if ok and type(v) is int:
            return True, {ast.USub: -v, ast.UAdd: v, ast.Invert: ~v}[type(node.op)]
    if isinstance(node, ast.BinOp):
        ok1, a = _py_fold(node.left)
        ok2, b = _py_fold(node.right)
        if ok1 and ok2:
            if isinstance(node.op, ast.Add) and type(a) is str and type(b) is str:
                return True, a + b
            if type(a) is int and type(b) is int:
                op = type(node.op)
                try:
                    if op is ast.Add: return True, a + b
                    if op is ast.Sub: return True, a - b
                    if op is ast.Mult: return True, a * b
                    if op is ast.FloorDiv: return True, a // b
                    if op is ast.Mod: return True, a % b
                    if op is ast.BitOr: return True, a | b
                    if op is ast.BitAnd: return True, a & b
                    if op is ast.BitXor: return True, a ^ b
                    if op is ast.LShift and 0 <= b <= 64: return True, a << b
                    if op is ast.RShift and 0 <= b <= 64: return True, a >> b
                    if op is ast.Pow and 0 <= b <= 64: return True, a ** b
                except ZeroDivisionError:
                    pass
    return False, None


def _py_is_zero(node):
    ok, v = _py_fold(node)
    if not ok:
        return False
    if type(v) is int:
        return v == 0
    if isinstance(v, str):
        return _str_value(v) == 0
    return False


def _py_src(text, node):
    if node is _UNKNOWN:
        return "<not a literal>"
    return " ".join((ast.get_source_segment(text, node) or ast.unparse(node)).split())


def check_config_py(path, violations, staged=False):
    """Append a violation if tools/config.py's TARGET or FRIDA_OFFSET (or any
    offset/RVA-named variable) isn't its placeholder, however it's bound."""
    if not staged and not Path(path).exists():
        return
    text = _read_text(path, staged, violations)
    if text is None:
        return
    disp = _display(path)
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as e:
        violations.append(
            f"{disp}:{getattr(e, 'lineno', 1) or 1}: can't parse "
            f"({getattr(e, 'msg', e)}) - refusing to guess whether TARGET / "
            f"FRIDA_OFFSET are still placeholders")
        return

    reported = set()
    for name, value, lineno, augmented in sorted(_py_bindings(tree), key=lambda b: b[2]):
        low = name.lower()
        if low == "target":
            ok = not augmented and _py_fold(value) == (True, PLACEHOLDER_TARGET)
            if not ok:
                shown = _py_src(text, value)
                violations.append(
                    f'{disp}:{lineno}: {name} = {shown} '
                    f'(must stay "{PLACEHOLDER_TARGET}" in git - this looks like a real target)')
                reported.add(lineno)
        elif _is_offset_name(name):
            if not _py_is_zero(value):
                shown = _py_src(text, value)
                violations.append(
                    f"{disp}:{lineno}: {name} = {shown} "
                    f"(must stay a zero placeholder in git - this looks like a real offset)")
                reported.add(lineno)
    _report_large_literals(text, disp, violations, reported, _py_without_comments(text))


# ---------------------------------------------------------------------------

def main(argv):
    staged_only = "--staged" in argv
    rels = _staged_paths() if staged_only else _all_paths()

    violations = []
    for rel in sorted(set(rels)):
        path = REPO_ROOT / rel
        if _is_js_path(rel):
            check_js_file(path, violations, staged=staged_only)
        elif rel == CONFIG_PY:
            check_config_py(path, violations, staged=staged_only)

    if violations:
        print(
            "BLOCKED: this looks like a real offset or target, not this "
            "template's placeholder:\n",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        print(_HINT, file=sys.stderr)
        return 1

    print("OK: no real offsets or targets found.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
