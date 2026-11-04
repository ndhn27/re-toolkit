"""
Importing a retk driver module afresh, against whatever `frida` is in sys.modules at that moment.

The driver tests put a stub `frida` into sys.modules and then need `retk.run_dump` (or list_exports,
verify_offset) imported again, so that its `import frida` binds the stub. A package makes that one step
harder than a bare module was: after the import the package object keeps the module as an ATTRIBUTE
(`retk.run_dump`), and `from retk import run_dump` in another test would find that stale, stub-bound one
even after sys.modules was cleaned. Both places are therefore saved and put back.
"""
import importlib
import sys
import types

import retk


def import_fresh(monkeypatch, name):
    """retk.<name>, imported anew now; sys.modules and the retk package are restored when the test ends."""
    full = f"retk.{name}"
    monkeypatch.setitem(sys.modules, full, types.ModuleType(full))   # remembered, and put back (or removed) at teardown
    del sys.modules[full]
    monkeypatch.setattr(retk, name, None, raising=False)             # the same for the package attribute
    return importlib.import_module(full)


def import_detached(name):
    """retk.<name>, imported anew (against the real frida, say) and left out of sys.modules and the package
    afterwards, so no other test finds this copy."""
    full = f"retk.{name}"
    old_module, old_attr = sys.modules.pop(full, None), retk.__dict__.pop(name, None)
    try:
        return importlib.import_module(full)
    finally:
        sys.modules.pop(full, None)
        retk.__dict__.pop(name, None)
        if old_module is not None:
            sys.modules[full] = old_module
        if old_attr is not None:
            setattr(retk, name, old_attr)
