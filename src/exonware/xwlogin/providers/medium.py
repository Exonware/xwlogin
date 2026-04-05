#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/medium.py
Medium OAuth Provider
Medium OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class MediumProvider(ABaseProvider):
    """Medium OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://medium.com/m/oauth/authorize"
    TOKEN_URL = "https://medium.com/v1/tokens"
    USERINFO_URL = "https://api.medium.com/v1/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Medium provider.
        Args:
            client_id: Medium Client ID
            client_secret: Medium Client Secret
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
        return "medium"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.MEDIUM

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Medium.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Medium user info format
        data = user_info.get('data', user_info)
        return {
            'id': data.get('id'),
            'username': data.get('username'),
            'name': data.get('name'),
            'url': data.get('url'),
        }
