import pytest

import node_support


@pytest.fixture(autouse=True)
def _own_data_dir(tmp_path_factory, monkeypatch):
    """No test may read or write the real user data directory (profiles, the build cache): each one
    gets an empty one of its own, and no $RE_PROFILES_DIR left over from the machine running them."""
    monkeypatch.setenv("RE_DATA_DIR", str(tmp_path_factory.mktemp("data")))
    monkeypatch.delenv("RE_PROFILES_DIR", raising=False)


@pytest.fixture(scope="session")
def node_scripts(tmp_path_factory):
    """A copy of scripts/, exactly as shipped, that Node can import as ES modules."""
    node_support.require_node()
    return node_support.copy_scripts(tmp_path_factory.mktemp("scripts"))
