#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/reddit.py
Reddit OAuth Provider
Reddit OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class RedditProvider(ABaseProvider):
    """Reddit OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://www.reddit.com/api/v1/authorize"
    TOKEN_URL = "https://www.reddit.com/api/v1/access_token"
    USERINFO_URL = "https://oauth.reddit.com/api/v1/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Reddit provider.
        Args:
            client_id: Reddit OAuth client ID
            client_secret: Reddit OAuth client secret
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
        return "reddit"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.CUSTOM  # Reddit not in enum yet

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Reddit.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Reddit user info format
        return {
            'id': user_info.get('id'),
            'username': user_info.get('name'),
            'email': user_info.get('email'),  # May not be available
            'avatar_url': user_info.get('icon_img'),
            'karma': user_info.get('total_karma', 0),
        }
