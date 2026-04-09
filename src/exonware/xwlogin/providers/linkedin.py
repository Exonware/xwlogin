#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/linkedin.py
LinkedIn OAuth Provider
LinkedIn OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class LinkedInProvider(ABaseProvider):
    """LinkedIn OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://www.linkedin.com/oauth/v2/authorization"
    TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
    USERINFO_URL = "https://api.linkedin.com/v2/userinfo"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize LinkedIn provider.
        Args:
            client_id: LinkedIn OAuth client ID
            client_secret: LinkedIn OAuth client secret
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
        return "linkedin"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.LINKEDIN

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from LinkedIn.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize LinkedIn user info format
        return {
            'id': user_info.get('sub'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'given_name': user_info.get('given_name'),
            'family_name': user_info.get('family_name'),
            'picture': user_info.get('picture'),
        }
