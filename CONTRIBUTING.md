# Contributing to re-toolkit

Thanks for your interest. `retk` is observe-only Frida tooling for inspecting how Unity + IL2CPP apps load their configuration tables. It runs inside another process, so it has a few ground rules that matter more than usual. Please read [What belongs here](#what-belongs-here) before you start.

## What belongs here

**In scope**

- Bug fixes, better error messages, and clearer docs.
- Support for more platforms and architectures, with tests. Only iOS has been exercised so far, and `retk relocate` is AArch64-only.
- Better layout checks, schema-drift detection, and safer verification of relocated offsets.
- Test coverage, especially for the real-Frida and packaging paths.

**Out of scope**

- **Anything that changes the target.** The tool is observe-only: it never modifies the binary on disk, and its hooks never change the app's arguments, return values or data. Changes that use `Interceptor.replace`, `retval.replace`, or argument rewriting will not be accepted.
- **Tooling aimed at a specific named app or its userbase.** This repository is a generic template, and it stays one.
- **Real target values of any kind**: package ids, offsets, record layouts, class / method / field names, or dumps. See the next section.

## Real values never go in the repository

This is the rule that matters most. The package id, the offsets and the layouts of a real app live in **your private profile**, outside git (see [docs/PROFILES.md](docs/PROFILES.md)). Everything in the repo must stay generic: [`profile.example.json`](profile.example.json) uses made-up names, offsets of `0x0` and synthetic layouts.

That means no real values in code, tests, docs, comments, commit messages, issues or pull request descriptions. Several automatic checks help, but none of them replaces care:

- `tests/test_layouts.py` fails if a script under `scripts/` grows a hex literal above `0xfff`, a `FRIDA_OFFSET` / `OFFSET_*` constant, or a hard-coded `.add(0x…)`.
- The `build` job in CI fails if a built bundle contains a long hex literal.
- `tools/check_identifiers.py` fails if a name from a real target appears in any text file, or in a file or directory name. It compares against SHA-256 digests in `tools/identifier_denylist.txt`, so the list does not reveal the names.
- `.gitignore` already excludes `records*.json`, `relocate*.json`, `verify*.json`, `diff_records*.json` and `profiles/`, because those outputs name a real target.

None of these can read prose, and none looks at git history. If a real value was ever committed, deleting it from the tree is not enough: the history must be rewritten, or the work published from a fresh repository. Details: [docs/KEEPING_VALUES_OUT_OF_GIT.md](docs/KEEPING_VALUES_OUT_OF_GIT.md).

## Getting set up

You need Python 3.9+, Node.js 20+ with npm, and a C compiler (the real-Frida tests build a small native program).

```bash
git clone https://github.com/ndhn27/re-toolkit && cd re-toolkit
pip install -r requirements-dev.txt     # runtime requirements + pytest + ruff + mypy
npm ci && npm run build                 # builds dist/ - what the tests and a checkout load
git config core.hooksPath .githooks     # once per clone: the name-check pre-commit hook
```

Run the checks CI runs:

```bash
python3 tools/check_identifiers.py      # no real-target names in the tree
ruff check .                            # lint
mypy                                    # type check (src/ and tools/; config in pyproject.toml)
pytest -rs                              # the test suite; -rs lists anything that was skipped
```

No device and no real binary are needed to run the tests. To make a skipped real-Frida test fail the way it does in CI, set the same variables:

```bash
CI=1 REQUIRE_REAL_FRIDA=1 REQUIRE_DIST=1 pytest -rs
```

What each test file covers is described in [docs/TESTING.md](docs/TESTING.md).

### Things to know about the toolchain

- **Frida is pinned to exact versions** (`frida==17.25.1`, `frida-tools==14.11.0` in `requirements.txt`). The Python `frida` and the `frida-server` on the device should be the same release. To move a pin, change both lines, run `pytest` (`tests/test_frida_real.py` runs the agents under the pinned Frida), run `npm run build`, and update the version in the docs and README badge.
- **Python 3.9 is the oldest supported version**, so avoid newer syntax and APIs such as `zip(strict=...)`. Ruff is configured for `py39` and looks for real mistakes (unused names, bugbear, stale `noqa`), not style.
- **Agents are bundled.** The sources in `scripts/` are bundled into `dist/` by `frida-compile`, and `dist/` is what retk actually loads. After editing anything in `scripts/`, run `npm run build`.
- **Adding an agent** means a new `build:*` entry in `package.json` (and in the `build` script), an update to [docs/AGENTS.md](docs/AGENTS.md), and an `init` export, since CI checks that every bundle exposes one. Files starting with `_` are shared helpers and are not bundled on their own.

## Pull requests

- **One change per PR.** A bug fix and a refactor are two PRs. For anything large, please open an issue first so we can agree on the approach.
- **Add a test** for every behaviour change or bug fix. A bug found on a real device should get a regression test that fails without the fix.
- **Prefer the strongest kind of test available.** Fake-process tests are fast but know nothing about real Frida behaviour; if you touch how an agent behaves under Frida, extend `tests/test_frida_real.py` too.
- **Update the docs** that describe what you changed, and [docs/TESTING.md](docs/TESTING.md) if you add or rename a test file.
- **Add a line to [CHANGELOG.md](CHANGELOG.md)** under a new `## [Unreleased]` heading, in the existing `Added` / `Changed` / `Fixed` style. Please don't bump `__version__`; a release is a git tag plus a bump in `src/retk/__init__.py`, done by the maintainer.
- **Don't bypass the hook.** `--no-verify` skips the name check. CI will catch it anyway, but by then the name is already in your commit.
- **CI must be green.** It runs four jobs: `names`, `tests` (Python 3.9 and the latest 3.x), `build`, and `package` (builds the wheel and installs it into an empty environment on Ubuntu and Windows).

Commit messages: a short imperative summary line, and a body explaining *why* when it is not obvious.

## Reporting a bug

Please include:

- the exact command, its output, and `retk --version`;
- your platform, whether the target is iOS or Android, and the architecture;
- the Python `frida` version and the `frida-server` version on the device;
- whether the problem reproduces on the synthetic targets in `tests/native/`, which is the best report because anyone can run it.

**Redact before you post.** Package ids, offsets, class / method / field names, and the contents of `records*.json`, `relocate*.json`, `verify*.json` or `diff_records*.json` all identify a real app. Replace them with placeholders; describe the *shape* of a record layout rather than pasting it.

**Security problems** should not go in a public issue. See [SECURITY.md](SECURITY.md).

## Legal

Runtime reverse engineering of a third-party app may conflict with its Terms of Service and with the laws where you live. Only work on software you are allowed to analyze, and don't contribute material taken from one.

By submitting a contribution you agree that it is licensed under the project's [MIT License](LICENSE).
