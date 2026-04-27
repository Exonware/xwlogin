#!/usr/bin/env python3

"""

#exonware/xwauth.connector/tests/1.unit/providers_tests/test_new_providers.py

Unit tests for new OAuth providers (Twitter, LinkedIn, Reddit, Spotify, etc.).

Company: eXonware.com

Author: eXonware Backend Team

Email: connect@exonware.com

Version: 0.0.1.0

Generation Date: 25-Jan-2026

"""



from __future__ import annotations

import pytest

from exonware.xwauth.connect.providers.twitter import TwitterProvider

from exonware.xwauth.connect.providers.linkedin import LinkedInProvider

from exonware.xwauth.connect.providers.reddit import RedditProvider

from exonware.xwauth.connect.providers.spotify import SpotifyProvider

from exonware.xwauth.connect.providers.dropbox import DropboxProvider

@pytest.mark.xwlogin_unit



class TestTwitterProvider:

    """Test Twitter OAuth provider."""

    @pytest.fixture



    def provider(self):

        """Create TwitterProvider instance."""

        return TwitterProvider(

            client_id="test_client_id",

            client_secret="test_client_secret"

        )



    def test_provider_name(self, provider):

        """Test provider name."""

        assert provider.provider_name == "twitter"

    @pytest.mark.asyncio



    async def test_get_authorization_url(self, provider):

        """Test authorization URL generation."""

        url = await provider.get_authorization_url(

            client_id="test_client_id",

            redirect_uri="https://example.com/callback",

            state="test_state",

            scopes=["tweet.read", "users.read"]

        )

        assert "twitter.com" in url

        assert "test_state" in url

        assert "test_client_id" in url

@pytest.mark.xwlogin_unit



class TestLinkedInProvider:

    """Test LinkedIn OAuth provider."""

    @pytest.fixture



    def provider(self):

        """Create LinkedInProvider instance."""

        return LinkedInProvider(

            client_id="test_client_id",

            client_secret="test_client_secret"

        )



    def test_provider_name(self, provider):

        """Test provider name."""

        assert provider.provider_name == "linkedin"

@pytest.mark.xwlogin_unit



class TestRedditProvider:

    """Test Reddit OAuth provider."""

    @pytest.fixture



    def provider(self):

        """Create RedditProvider instance."""

        return RedditProvider(

            client_id="test_client_id",

            client_secret="test_client_secret"

        )



    def test_provider_name(self, provider):

        """Test provider name."""

        assert provider.provider_name == "reddit"

@pytest.mark.xwlogin_unit



class TestSpotifyProvider:

    """Test Spotify OAuth provider."""

    @pytest.fixture



    def provider(self):

        """Create SpotifyProvider instance."""

        return SpotifyProvider(

            client_id="test_client_id",

            client_secret="test_client_secret"

        )



    def test_provider_name(self, provider):

        """Test provider name."""

        assert provider.provider_name == "spotify"

@pytest.mark.xwlogin_unit



class TestDropboxProvider:

    """Test Dropbox OAuth provider."""

    @pytest.fixture



    def provider(self):

        """Create DropboxProvider instance."""

        return DropboxProvider(

            client_id="test_client_id",

            client_secret="test_client_secret"

        )



    def test_provider_name(self, provider):

        """Test provider name."""

        assert provider.provider_name == "dropbox"

