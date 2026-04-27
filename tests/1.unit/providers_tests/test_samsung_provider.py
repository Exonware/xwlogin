#!/usr/bin/env python3

"""

#exonware/xwauth.connector/tests/1.unit/providers_tests/test_samsung_provider.py

Unit tests for Samsung OAuth provider.

Company: eXonware.com

Author: eXonware Backend Team

Email: connect@exonware.com

Version: 0.0.1.0

Generation Date: 20-Dec-2025

"""



import pytest

from exonware.xwauth.identity.provider_connector import ProviderType, XWProviderConnectionError

from exonware.xwauth.connect.providers.samsung import SamsungProvider

@pytest.mark.xwlogin_unit



class TestSamsungProvider:

    """Test SamsungProvider implementation."""

    @pytest.fixture



    def provider(self):

        """Create SamsungProvider instance."""

        return SamsungProvider(

            client_id="test_samsung_client",

            client_secret="test_samsung_secret"

        )



    def test_provider_name(self, provider):

        """Test provider name."""

        assert provider.provider_name == "samsung"



    def test_provider_type(self, provider):

        """Test provider type."""

        assert provider.provider_type == ProviderType.SAMSUNG

    @pytest.mark.asyncio



    async def test_get_authorization_url(self, provider):

        """Test authorization URL generation."""

        url = await provider.get_authorization_url(

            client_id="test_samsung_client",

            redirect_uri="https://example.com/callback",

            state="test_state",

            scopes=["profile"]

        )

        assert url is not None

        assert "samsung" in url.lower()

        assert "test_samsung_client" in url

