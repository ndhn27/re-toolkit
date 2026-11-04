[← Back to README](../README.md)

# Keeping real values out of git

There is little left to guard, because the design keeps real values out of the
tree rather than scanning for them:

- **Offsets, the package id and layouts** are in your profile, outside git
  (in your user data directory; the repo's `profiles/` is git-ignored as a backstop). `scripts/` holds none, the
  template profile holds only `0x0` and made-up names, and a test
  (`test_layouts.py`) fails if a script grows a hex literal above `0xfff`, a
  `FRIDA_OFFSET`/`OFFSET_*` constant or a hard-coded `.add(0x…)`; CI runs the
  same kind of check on the built bundles.
- **Exported dumps** carry the real target and offsets in `meta`: `records*.json`
  is git-ignored, and `retk dump` warns about an `--out` that isn't.
- **Names from a real target — `tools/check_identifiers.py`** — the one thing
  that can still leak by typing it. A class, method or field name has no
  placeholder to diff against, so this checker knows the real names and fails
  if one appears anywhere — in any text file, or in a file or directory name.
  The list it checks against, `tools/identifier_denylist.txt`, holds only
  SHA-256 digests of normalized names (lower-cased, separators and case
  boundaries removed), so `DeviceFooBar`, `device_foo_bar` and `DEVICE-FOO-BAR`
  are all one entry, a name is caught inside a longer identifier too
  (`getDeviceFooBarEntry`, `dump_device_foo_bar_list.js`), and the list can be
  committed without saying what is on it. Add names with `--add` / `--add-file`
  (see the script's docstring); failures print `file:line` and a digest prefix,
  not the name, so a public CI log doesn't repeat it. It does not read prose
  ("device foo bar" as separate words), and a digest is not secrecy — a
  guessable name can be recovered by guessing. It is a guard against
  accidents, not a vault, and it is optional: without a denylist the repo works
  the same.

What nothing here can catch is a person pasting a real value into a README,
a doc comment or a test: no scanner reliably tells a real address from a made-up
one in prose, which is why the checks above don't try, and why the values are
kept out of the places where they would otherwise have to live. And neither
check looks at git history: a name or offset that was ever committed stays in
the commits that contain it, so if one has been pushed, removing it from the
tree is not enough (rewrite the history, or publish from a fresh repository).

The name check runs in two places:

- **Locally**, as a pre-commit hook. Install once per clone (from the repo
  root):

  ```bash
  git config core.hooksPath .githooks
  ```

- **In CI**, via `.github/workflows/ci.yml`, a backstop for a clone that never
  installed the hook, or a commit made with `--no-verify`. The same workflow
  runs `ruff check .`, `pytest` (Python 3.9 and the latest 3.x, against the pinned
  Frida, with Node installed and `npm run build` done first so the tests that
  execute the agents - and the shipped `dist/` bundles - run too, and a C compiler
  so the real-Frida tests do — they fail rather than skip in CI) and a full
  `npm run build`, checking that every bundle exposes `init` and carries no
  address.
