# exonware/xwauth-identity/tests/1.unit/package_tests/test_connect_discovery.py
"""Package-level connect discovery API (GUIDE_51)."""

from __future__ import annotations

import pytest

import exonware.xwauth.identity as identity_pkg

pytestmark = pytest.mark.xwauth_identity_unit


def test_discover_connect_respects_disable_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XWAUTH_IDENTITY_DISABLE_CONNECT_DISCOVERY", "1")
    identity_pkg._reset_discovery_cache_for_tests()
    try:
        assert identity_pkg.discover_connect_package() is None
        assert identity_pkg.connect_is_available() is False
    finally:
        monkeypatch.delenv("XWAUTH_IDENTITY_DISABLE_CONNECT_DISCOVERY", raising=False)
        identity_pkg._reset_discovery_cache_for_tests()


def test_connect_is_available_true_when_connect_importable() -> None:
    identity_pkg._reset_discovery_cache_for_tests()
    try:
        mod = identity_pkg.discover_connect_package()
        if mod is None:
            pytest.skip("exonware.xwauth.connect not available in this environment")
        assert identity_pkg.connect_is_available() is True
        assert identity_pkg.discover_connect_package() is mod
    finally:
        identity_pkg._reset_discovery_cache_for_tests()
