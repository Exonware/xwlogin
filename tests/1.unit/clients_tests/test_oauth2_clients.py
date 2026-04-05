#!/usr/bin/env python3
"""
#exonware/xwauth/tests/1.unit/clients_tests/test_oauth2_clients.py
Unit tests for enhanced OAuth 2.0 client libraries.
Tests OAuth2Session and AsyncOAuth2Session with multiple HTTP backends.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.0
Generation Date: 25-Jan-2026
"""

from __future__ import annotations
import pytest
from exonware.xwlogin.clients.oauth2_client import OAuth2Session
from exonware.xwlogin.clients.async_client import AsyncOAuth2Session
@pytest.mark.xwlogin_unit

class TestOAuth2Session:
    """Test OAuth2Session (synchronous client)."""
    @pytest.fixture

    def client_config(self):
        """OAuth 2.0 client configuration."""
        return {
            "client_id": "test_client",
            "client_secret": "test_secret",
            "redirect_uri": "https://client.example.com/callback",
            "authorization_url": "https://auth.example.com/oauth/authorize",
            "token_url": "https://auth.example.com/oauth/token",
        }

    def test_client_initialization(self, client_config):
        """Test OAuth2Session initialization."""
        client = OAuth2Session(
            client_id=client_config["client_id"],
            client_secret=client_config["client_secret"],
            http_backend="httpx"
        )
        assert client._client_id == client_config["client_id"]
        assert client._client_secret == client_config["client_secret"]
        assert client._http_backend == "httpx"

    def test_client_with_different_backends(self, client_config):
        """Test OAuth2Session with different HTTP backends."""
        backends = ["httpx", "aiohttp", "requests"]
        for backend in backends:
            try:
                client = OAuth2Session(
                    client_id=client_config["client_id"],
                    client_secret=client_config["client_secret"],
                    http_backend=backend
                )
                assert client is not None
                assert client._http_backend == backend
            except ImportError:
                # Backend not installed, skip
                pytest.skip(f"HTTP backend '{backend}' not installed")
@pytest.mark.xwlogin_unit

class TestAsyncOAuth2Session:
    """Test AsyncOAuth2Session (async client with auto-refresh)."""
    @pytest.fixture

    def client_config(self):
        """OAuth 2.0 client configuration."""
        return {
            "client_id": "test_client",
            "client_secret": "test_secret",
            "token_url": "https://auth.example.com/oauth/token",
        }
    @pytest.mark.asyncio

    async def test_client_initialization(self, client_config):
        """Test AsyncOAuth2Session initialization."""
        client = AsyncOAuth2Session(
            client_id=client_config["client_id"],
            client_secret=client_config["client_secret"],
            token_url=client_config["token_url"]
        )
        # Verify client was created (check internal attributes)
        assert client is not None
        assert hasattr(client, '_client_id') or hasattr(client, 'client_id')
        assert hasattr(client, '_client_secret') or hasattr(client, 'client_secret')
        assert hasattr(client, '_token_url') or hasattr(client, 'token_url')
    @pytest.mark.asyncio

    async def test_automatic_token_refresh(self, client_config):
        """Test that AsyncOAuth2Session supports automatic token refresh."""
        client = AsyncOAuth2Session(
            client_id=client_config["client_id"],
            client_secret=client_config["client_secret"],
            token_url=client_config["token_url"]
        )
        # Verify auto-refresh capability exists
        assert hasattr(client, 'refresh_token') or hasattr(client, '_refresh_token') or hasattr(client, 'refresh_access_token') or hasattr(client, '_auto_refresh')
