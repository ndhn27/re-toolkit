# Security Policy

## Supported versions

`retk` is a small research tool. Only the latest release receives security fixes.

| Version | Supported |
| --- | --- |
| 1.1.x | ✅ |
| < 1.1 | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private reporting:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Describe the problem and how to reproduce it.

(Direct link: <https://github.com/ndhn27/re-toolkit/security/advisories/new>)

Useful things to include:

- what you found and what an attacker could do with it;
- the command line, `retk --version`, the platform, and the Python `frida` / `frida-server` versions;
- a minimal proof of concept built from **synthetic** data, such as a small crafted binary or JSON file. Please do not send real app binaries, dumps or profiles.

This is a personal project maintained in spare time. I aim to acknowledge a report within **7 days** and to say what I plan to do within **30 days**, but these are goals, not guarantees. I'm glad to credit you in the fix unless you prefer to stay anonymous.

## What is in scope

`retk` injects an agent into another process, parses binaries and JSON files it did not create, and writes files into your user data directory. The interesting problems are in how it treats those inputs and outputs:

- **Breaking the observe-only guarantee.** The tool is documented as never modifying the binary on disk and never changing an app's arguments, return values or data. A code path that does so is a security-relevant bug.
- **Parsing untrusted input.** A crafted Mach-O (thin or fat) or ELF given to `retk relocate`, or a crafted profile, build-cache entry, `records.json` or relocate/verify output given to `retk profile`, `retk diff` or `retk verify`, that causes a crash, runaway memory or CPU use, an endless loop, or a read or write outside the intended data.
- **File handling.** Output written somewhere other than the path the user asked for, unsafe handling of the profile and build-cache directories (path traversal, symlink following, unsafe temporary files), or a profile or build id that can escape its directory.
- **Code or command execution** triggered by data from a profile, a dump or the target process rather than by the user's own command line.
- **Leaking real values.** Anything that causes a real target's package id, offsets, layouts or names to be written to a tracked location, a log, or a CI output. This includes a defect in `tools/check_identifiers.py` that prints a name instead of a digest prefix.
- **The install and build chain.** A problem in how `pip install .` builds the agents (`setup.py` runs `npm ci` and `npm run build`), in the wheel contents, or in the pinned dependencies and `package-lock.json`.

## What is out of scope

- **Using the tool on an app you are not authorized to analyze.** That is a legal and Terms-of-Service matter between you and the app's owner. See the scope note in the [README](README.md).
- **Weaknesses in the target app** that the tool lets you observe. Inspecting a running app is the purpose of the tool.
- **Bugs in Frida, `frida-server`, Capstone, Ghidra or other upstream software.** Please report those upstream. If retk makes such a bug easier to hit, that part is in scope.
- **A hostile or exposed `frida-server`.** The controller trusts what its own `frida-server` returns, and a server on an open network port can already do far more than retk can. Reach it over a link you control (USB, or a local forward). The default is `127.0.0.1:27042`.
- **Side effects of runtime instrumentation that the README already documents**, such as in-memory hook rewriting, scratch allocations in the target, and class initialisation caused by calling the runtime's IL2CPP API.
- **Reports with no demonstrated impact**, such as scanner output with no way to trigger it.

## Using the tool safely

- Keep real values in your private profile. Install the pre-commit hook once per clone (`git config core.hooksPath .githooks`) and don't write dumps or `--json` outputs into a tracked directory; they name the target and its offsets.
- Treat binaries, profiles and dumps you did not create yourself as untrusted input, and analyze them on a machine or VM you can afford to lose.
- Keep the Python `frida` and the device's `frida-server` on the same release, and don't expose `frida-server` to a network you don't control.
- `pip install .` runs `npm ci` and a build step. Install from a checkout you have looked at, in a virtual environment, rather than from an unreviewed copy.
- If a real name or offset has already been pushed, removing it from the tree does not remove it from the history. Rewrite the history or publish from a fresh repository.

## Disclosure

Once a fix is released I'll publish a GitHub security advisory describing the problem, the affected versions and the fixed version. If you want to publish your own write-up, please give me a reasonable amount of time to ship a fix first.
