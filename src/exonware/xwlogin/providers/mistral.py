#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/mistral.py
Mistral AI OAuth Provider
Mistral AI OAuth 2.0 provider implementation.
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


class MistralProvider(ABaseProvider):
    """Mistral AI OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://auth.mistral.ai/oauth/authorize"
    TOKEN_URL = "https://auth.mistral.ai/oauth/token"
    USERINFO_URL = "https://api.mistral.ai/v1/users/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Mistral provider.
        Args:
            client_id: Mistral Client ID
            client_secret: Mistral Client Secret
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
        return "mistral"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.MISTRAL

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Mistral AI.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Mistral user info format
        return {
            'id': user_info.get('id'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
        }
