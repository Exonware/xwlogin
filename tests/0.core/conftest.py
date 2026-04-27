# exonware/xwauth.identity/tests/0.core/conftest.py
"""Core layer: mark all tests in this directory (GUIDE_51)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xwlogin_core
