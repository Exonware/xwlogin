#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/paytabs.py
PayTabs OAuth Provider
PayTabs OAuth 2.0 provider implementation.
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


class PayTabsProvider(ABaseProvider):
    """PayTabs OAuth 2.0 provider."""
    # PayTabs API endpoints
    AUTHORIZATION_URL = "https://secure.paytabs.com/oauth/authorize"
    TOKEN_URL = "https://secure.paytabs.com/oauth/token"
    USERINFO_URL = "https://secure.paytabs.com/v1/merchant/info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize PayTabs provider.
        Args:
            client_id: PayTabs API client ID
            client_secret: PayTabs API client secret
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
        return "paytabs"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.PAYTABS

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from PayTabs.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize PayTabs user info format
        return {
            'id': str(user_info.get('id')),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'merchant_id': user_info.get('merchant_id'),
        }
