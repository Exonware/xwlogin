#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/circleci.py
CircleCI OAuth Provider
CircleCI OAuth 2.0 provider implementation.
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


class CircleCIProvider(ABaseProvider):
    """CircleCI OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://circleci.com/oauth/authorize"
    TOKEN_URL = "https://circleci.com/oauth/token"
    USERINFO_URL = "https://circleci.com/api/v2/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize CircleCI provider.
        Args:
            client_id: CircleCI Client ID
            client_secret: CircleCI Client Secret
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
        return "circleci"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.CIRCLECI

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from CircleCI.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize CircleCI user info format
        return {
            'id': str(user_info.get('id')),
            'name': user_info.get('name'),
            'login': user_info.get('login'),
        }
