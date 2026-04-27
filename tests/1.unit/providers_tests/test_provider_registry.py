#!/usr/bin/env python3

"""

#exonware/xwauth.connector/tests/1.unit/providers_tests/test_provider_registry.py

Unit tests for provider registry.

Company: eXonware.com

Author: eXonware Backend Team

Email: connect@exonware.com

Version: 0.0.1.0

Generation Date: 20-Dec-2025

"""



import pytest

from exonware.xwauth.identity.provider_connector import ProviderRegistry, XWProviderNotFoundError

from exonware.xwauth.connect.providers.google import GoogleProvider

@pytest.mark.xwlogin_unit



class TestProviderRegistry:

    """Test ProviderRegistry implementation."""

    @pytest.fixture



    def registry(self):

        """Create ProviderRegistry instance."""

        return ProviderRegistry()

    @pytest.fixture



    def google_provider(self):

        """Create GoogleProvider instance."""

        return GoogleProvider(

            client_id="test_client_id",

            client_secret="test_client_secret"

        )



    def test_register_provider(self, registry, google_provider):

        """Test provider registration."""

        registry.register(google_provider)

        assert registry.has("google") is True



    def test_get_provider(self, registry, google_provider):

        """Test getting provider."""

        registry.register(google_provider)

        provider = registry.get("google")

        assert provider is not None

        assert provider.provider_name == "google"



    def test_get_provider_not_found(self, registry):

        """Test getting non-existent provider."""

        # Should raise XWProviderNotFoundError or KeyError

        with pytest.raises((XWProviderNotFoundError, KeyError)):

            registry.get("nonexistent")



    def test_list_providers(self, registry, google_provider):

        """Test listing providers."""

        registry.register(google_provider)

        providers = registry.list_providers()

        assert "google" in providers



    def test_has_provider(self, registry, google_provider):

        """Test checking if provider exists."""

        assert registry.has("google") is False

        registry.register(google_provider)

        assert registry.has("google") is True

