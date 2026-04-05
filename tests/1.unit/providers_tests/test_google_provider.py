#!/usr/bin/env python3
"""
#exonware/xwauth/tests/1.unit/providers_tests/test_google_provider.py
Unit tests for Google OAuth provider.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.0
Generation Date: 20-Dec-2025
"""

import pytest
from urllib.parse import parse_qs, urlparse
from unittest.mock import AsyncMock, Mock

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from exonware.xwlogin.providers.google import GoogleProvider
@pytest.mark.xwlogin_unit

class TestGoogleProvider:
    """Test GoogleProvider implementation."""
    @pytest.fixture

    def provider(self):
        """Create GoogleProvider instance."""
        return GoogleProvider(
            client_id="test_google_client",
            client_secret="test_google_secret"
        )

    def test_provider_name(self, provider):
        """Test provider name."""
        assert provider.provider_name == "google"

    def test_provider_type(self, provider):
        """Test provider type."""
        assert provider.provider_type == ProviderType.GOOGLE
    @pytest.mark.asyncio

    async def test_get_authorization_url(self, provider):
        """Test authorization URL generation."""
        url = await provider.get_authorization_url(
            client_id="test_google_client",
            redirect_uri="https://example.com/callback",
            state="test_state",
            scopes=["openid", "email", "profile"]
        )
        assert url is not None
        parsed = urlparse(url)
        assert parsed.netloc == "accounts.google.com"
        assert parsed.path == "/o/oauth2/v2/auth"
        query = parse_qs(parsed.query)
        assert query["client_id"] == ["test_google_client"]
        assert query["redirect_uri"] == ["https://example.com/callback"]
        assert query["state"] == ["test_state"]
        assert query["response_type"] == ["code"]
        assert query["scope"] == ["openid email profile"]
        assert query["access_type"] == ["offline"]
        assert query["prompt"] == ["consent"]
    @pytest.mark.asyncio

    async def test_exchange_code_for_token(self, provider):
        """Test code exchange for token with deterministic async mock."""
        provider._async_http_client = AsyncMock()
        provider._async_http_client.post.return_value = Mock(
            status_code=200,
            json=lambda: {"access_token": "at", "token_type": "Bearer"},
        )

        response = await provider.exchange_code_for_token(
            code="test_code",
            redirect_uri="https://example.com/callback"
        )
        assert response == {"access_token": "at", "token_type": "Bearer"}
        provider._async_http_client.post.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_exchange_code_for_token_non_200_raises_provider_error(self, provider):
        """Test token exchange maps non-200 to provider connection error."""
        provider._async_http_client = AsyncMock()
        provider._async_http_client.post.return_value = AsyncMock(
            status_code=401,
            text="unauthorized",
        )
        with pytest.raises(XWProviderConnectionError):
            await provider.exchange_code_for_token(
                code="bad_code",
                redirect_uri="https://example.com/callback"
            )
    @pytest.mark.asyncio

    async def test_get_user_info(self, provider):
        """Test normalized user info mapping from provider response."""
        base_response = {
            "id": "google-1",
            "email": "user@example.com",
            "name": "User Example",
            "picture": "https://example.com/avatar.png",
            "verified_email": True,
        }
        original = ABaseProvider.get_user_info
        ABaseProvider.get_user_info = AsyncMock(return_value=base_response)
        try:
            user_info = await provider.get_user_info("test_access_token")
        finally:
            ABaseProvider.get_user_info = original

        assert user_info == {
            "id": "google-1",
            "email": "user@example.com",
            "name": "User Example",
            "picture": "https://example.com/avatar.png",
            "verified_email": True,
        }

    @pytest.mark.asyncio
    async def test_get_user_info_defaults_verified_email_to_false(self, provider):
        """Test normalized mapping defaults verified_email to False."""
        original = ABaseProvider.get_user_info
        ABaseProvider.get_user_info = AsyncMock(
            return_value={"id": "google-2", "email": "user2@example.com", "name": "User 2"}
        )
        try:
            user_info = await provider.get_user_info("test_access_token")
        finally:
            ABaseProvider.get_user_info = original

        assert user_info["verified_email"] is False
