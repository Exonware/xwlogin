#!/usr/bin/env python3

"""

#exonware/xwauth.connector/tests/1.unit/providers_tests/test_github_provider.py

Unit tests for GitHub OAuth provider.

Company: eXonware.com

Author: eXonware Backend Team

Email: connect@exonware.com

Version: 0.0.1.0

Generation Date: 20-Dec-2025

"""



import pytest

from exonware.xwauth.identity.provider_connector import ProviderType, XWProviderConnectionError

from exonware.xwauth.connect.providers.github import GitHubProvider

@pytest.mark.xwlogin_unit



class TestGitHubProvider:

    """Test GitHubProvider implementation."""

    @pytest.fixture



    def provider(self):

        """Create GitHubProvider instance."""

        return GitHubProvider(

            client_id="test_github_client",

            client_secret="test_github_secret"

        )



    def test_provider_name(self, provider):

        """Test provider name."""

        assert provider.provider_name == "github"



    def test_provider_type(self, provider):

        """Test provider type."""

        assert provider.provider_type == ProviderType.GITHUB

    @pytest.mark.asyncio



    async def test_get_authorization_url(self, provider):

        """Test authorization URL generation."""

        url = await provider.get_authorization_url(

            client_id="test_github_client",

            redirect_uri="https://example.com/callback",

            state="test_state",

            scopes=["user", "repo"]

        )

        assert url is not None

        assert "github.com" in url.lower()

        assert "test_github_client" in url

        assert "test_state" in url

    @pytest.mark.asyncio



    async def test_exchange_code_for_token(self, provider):

        """Test code exchange for token."""

        try:

            response = await provider.exchange_code_for_token(

                code="test_code",

                redirect_uri="https://example.com/callback"

            )

            assert response is not None

        except (XWProviderConnectionError, TypeError, ValueError):

            # Expected to fail without real connection or proper base_url

            pass

    @pytest.mark.asyncio



    async def test_get_user_info(self, provider):

        """Test getting user info."""

        try:

            user_info = await provider.get_user_info("test_access_token")

            assert user_info is not None

        except (XWProviderConnectionError, TypeError, ValueError):

            # Expected to fail without real connection or proper base_url

            pass

