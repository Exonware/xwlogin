#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/tamara.py
Tamara OAuth Provider
Tamara OAuth 2.0 provider implementation.
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


class TamaraProvider(ABaseProvider):
    """Tamara OAuth 2.0 provider."""
    # Tamara API endpoints
    AUTHORIZATION_URL = "https://api.tamara.co/oauth/authorize"
    TOKEN_URL = "https://api.tamara.co/oauth/token"
    USERINFO_URL = "https://api.tamara.co/v1/customers/me"

    def __init__(self, client_id: str, client_secret: str, sandbox: bool = False, **kwargs):
        """
        Initialize Tamara provider.
        Args:
            client_id: Tamara API client ID
            client_secret: Tamara API client secret
            sandbox: Use sandbox environment (default: False)
            **kwargs: Additional configuration
        """
        if sandbox:
            authorization_url = "https://api-sandbox.tamara.co/oauth/authorize"
            token_url = "https://api-sandbox.tamara.co/oauth/token"
            userinfo_url = "https://api-sandbox.tamara.co/v1/customers/me"
        else:
            authorization_url = self.AUTHORIZATION_URL
            token_url = self.TOKEN_URL
            userinfo_url = self.USERINFO_URL
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            **kwargs
        )
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "tamara"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.TAMARA

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Tamara.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Tamara user info format
        return {
            'id': str(user_info.get('id')),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'phone': user_info.get('phone'),
        }
