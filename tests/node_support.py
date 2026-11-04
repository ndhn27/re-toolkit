"""
Running the real scripts/*.js under Node, against tests/frida_harness.mjs.

Shared by the test modules that check what the agents do (test_layouts.py,
test_canary.py): a copy of scripts/ that Node can import as ES modules, and a
runner that sends the harness one JSON request and returns its one JSON answer.
"""
import base64
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
HARNESS = Path(__file__).resolve().parent / "frida_harness.mjs"


def require_node():
    """Skip when node is missing - or fail when $CI is set, so CI can't silently stop running these."""
    if shutil.which("node"):
        return
    if os.environ.get("CI"):
        pytest.fail("node is required to run these tests in CI")
    pytest.skip("node is not installed")


def copy_scripts(dest):
    """A copy of scripts/, exactly as shipped, that Node can import as ES modules."""
    dest = Path(dest)
    (dest / "package.json").write_text('{"type": "module"}\n', encoding="utf-8")
    for src in SCRIPTS_DIR.glob("*.js"):
        shutil.copy(src, dest / src.name)
    return dest


def run_harness(scripts_dir, image, **request):
    payload = dict(request, scriptsDir=str(scripts_dir),
                   image=base64.b64encode(bytes(image)).decode("ascii"))
    proc = subprocess.run(["node", str(HARNESS)], input=json.dumps(payload),
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)
