#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/twitter.py
Twitter OAuth Provider
Twitter OAuth 2.0 provider implementation (Twitter API v2).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class TwitterProvider(ABaseProvider):
    """Twitter OAuth 2.0 provider (Twitter API v2)."""
    AUTHORIZATION_URL = "https://twitter.com/i/oauth2/authorize"
    TOKEN_URL = "https://api.twitter.com/2/oauth2/token"
    USERINFO_URL = "https://api.twitter.com/2/users/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Twitter provider.
        Args:
            client_id: Twitter OAuth client ID
            client_secret: Twitter OAuth client secret
            **kwargs: Additional configuration
        """
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=self.USERINFO_URL,
            **kwargs
        )
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "twitter"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.TWITTER

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Twitter-specific authorization parameters."""
        return {
            'response_type': 'code',
            'code_challenge_method': 'S256',  # Twitter requires PKCE
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Twitter.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Twitter API v2 returns data in 'data' field
        data = user_info.get('data', user_info)
        # Normalize Twitter user info format
        return {
            'id': str(data.get('id')),
            'username': data.get('username'),
            'name': data.get('name'),
            'email': data.get('email'),  # Requires email scope
            'profile_image_url': data.get('profile_image_url'),
        }
