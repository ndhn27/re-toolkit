# Maintaining re-toolkit

Everything a second person needs in order to keep this project going: what to run, how a release
is made, and where things live. It exists because one person currently holds all of it, and a
project that only one person can release is one unavailable person away from being stuck.

## What there is to know

- **There are no secrets in the repository, and none are needed to build or test it.** Real target
  values live in each user's private profile, outside git ([PROFILES.md](PROFILES.md)). CI uses no
  repository secrets and no publish token: a release is a git tag and a GitHub release, not an
  upload to a package index.
- **The checks** are the four CI jobs in `.github/workflows/ci.yml` (`names`, `tests`, `build`,
  `package`). Locally: `python3 tools/check_identifiers.py`, `ruff check .`, `mypy`, `pytest -rs`
  ([CONTRIBUTING.md](../CONTRIBUTING.md#getting-set-up)).
- **The two pins that need care** are Frida (`requirements.txt`, must match the `frida-server` on the
  device) and the Python floor (3.9, which is also why mypy is held below 2 in
  `requirements-dev.txt`). How to move the Frida pin is in CONTRIBUTING.md.
- **The name guard** (`tools/check_identifiers.py` and `tools/identifier_denylist.txt`) compares
  digests, so a maintainer does not need to know the names it protects. Do not add a name in clear
  text anywhere; see [KEEPING_VALUES_OUT_OF_GIT.md](KEEPING_VALUES_OUT_OF_GIT.md).

## Making a release

1. Everything for the release is merged and CI is green on `main`.
2. In one commit:
   - bump `__version__` in `src/retk/__init__.py` (the only place; `pyproject.toml` reads it),
   - turn `## [Unreleased]` in `CHANGELOG.md` into `## [x.y.z] - YYYY-MM-DD` and add its link line at
     the bottom (`[x.y.z]: .../compare/v<previous>...vx.y.z`),
   - if the minor version changed, update the supported-versions table in `SECURITY.md`.
3. `pytest tests/test_release_consistency.py` - it fails if any of those three disagree.
4. Build the source tree you are about to ship and look at what is in it, not at what you meant to
   put in it:

   ```bash
   python -m build --wheel --outdir wheelhouse
   python -m venv /tmp/retk-check && /tmp/retk-check/bin/pip install wheelhouse/*.whl
   /tmp/retk-check/bin/retk --version        # must print the number you are releasing
   ```

   If you hand over an archive of the tree (a zip, a tarball), run the same check on the archive:
   unpack it into an empty folder and run `pytest tests/test_release_consistency.py` there. The
   version that matters is the one inside the file that gets delivered.
5. Tag and publish: `git tag vx.y.z && git push origin vx.y.z`, then create the GitHub release from
   that tag with the changelog section as its notes.

## Adding a maintainer

A second maintainer is the only real fix for a single point of failure; documentation only makes the
handover possible. To add one:

1. Give them **Write** (or **Maintain**) access to the repository, and make sure branch protection on
   `main` requires the four CI jobs.
2. Have them make the next release by following the list above, with the current maintainer
   reviewing. A release that someone else can reproduce from this file is the test that the file is
   enough; fix this file where it is not.
3. Add them as the security contact for private vulnerability reports (repository settings, Security).
