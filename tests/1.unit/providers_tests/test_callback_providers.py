#!/usr/bin/env python3
"""
Unit tests for callback_providers discovery and provider-name verification.
Ensures endpoint names match each provider's provider_name (registry lookup).
"""

import pytest
from exonware.xwlogin.providers.callback_providers import (
    discover_oauth2_callback_provider_names,
    get_oauth2_callback_provider_names,
    verify_provider_names_match_modules,
)
@pytest.mark.xwlogin_unit


class TestCallbackProviders:
    """Test callback provider discovery and name verification."""

    def test_discover_returns_non_empty(self):
        """Discovery returns a non-empty list of provider names."""
        names = discover_oauth2_callback_provider_names()
        assert isinstance(names, list)
        assert len(names) > 0

    def test_discover_includes_expected_providers(self):
        """Discovery includes well-known providers used by explicit handlers."""
        names = discover_oauth2_callback_provider_names()
        for expected in ("google", "microsoft", "apple", "github", "discord", "slack"):
            assert expected in names, f"expected {expected} in discovered names"

    def test_get_oauth2_callback_provider_names_merges_extra(self):
        """get_oauth2_callback_provider_names merges extra names from config."""
        base = set(discover_oauth2_callback_provider_names())
        with_extra = get_oauth2_callback_provider_names(extra=["custom_foo", "custom_bar"])
        for n in ("custom_foo", "custom_bar"):
            assert n in with_extra
        assert set(with_extra) >= base

    def test_provider_names_match_modules(self):
        """No mismatch between module name and provider_name.
        Endpoint names must match provider_name so registry lookup works.
        When we cannot instantiate, we use module name as fallback (same
        convention), so no mismatch is expected.
        """
        mismatches, fallbacks = verify_provider_names_match_modules()
        assert mismatches == [], (
            f"module vs provider_name mismatches: {mismatches}. "
            "Endpoint names must match provider_name for registry lookup."
        )
