"""Bootstrap ``src`` layout for monorepo checkouts (xwlogin + sibling stack)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("XWSTACK_SKIP_XWLAZY_INIT", "1")

_TESTS_ROOT = Path(__file__).resolve().parent
_XWLOGIN_ROOT = _TESTS_ROOT.parent
_XWLOGIN_SRC = _XWLOGIN_ROOT / "src"
if _XWLOGIN_SRC.is_dir():
    sys.path.insert(0, str(_XWLOGIN_SRC))

_MONO_ROOT = _XWLOGIN_ROOT.parent
# Sibling order aligned with ``xwauth/tests/conftest.py`` / ``xwauth-api/tests/conftest.py`` (GUIDE_51).
for _name in (
    "xwnode",
    "xwdata",
    "xwschema",
    "xwentity",
    "xwbase",
    "xwaction",
    "xwauth",
    "xwapi",
    "xwjson",
    "xwstorage",
    "xwauth-api",
    "xwsystem",
):
    _sibling = _MONO_ROOT / _name / "src"
    if _sibling.is_dir():
        sys.path.insert(0, str(_sibling))

from exonware.xwlogin.test_support import MockStorageProvider, XWAuth, XWAuthConfig


@pytest.fixture
def mock_storage():
    return MockStorageProvider()


@pytest.fixture
def auth_config(mock_storage):
    return XWAuthConfig(
        jwt_secret="test-secret-key-for-testing-only",
        storage_provider=mock_storage,
    )


@pytest.fixture
def auth(auth_config):
    return XWAuth(config=auth_config)
