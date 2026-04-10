#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/ebay.py
eBay OAuth Provider
eBay OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class eBayProvider(ABaseProvider):
    """eBay OAuth 2.0 provider."""
    # Production endpoints
    AUTHORIZATION_URL = "https://auth.ebay.com/oauth2/authorize"
    TOKEN_URL = "https://api.ebay.com/identity/v1/oauth2/token"
    USERINFO_URL = "https://api.ebay.com/identity/v1/oauth2/userinfo"
    # Sandbox endpoints
    SANDBOX_AUTHORIZATION_URL = "https://auth.sandbox.ebay.com/oauth2/authorize"
    SANDBOX_TOKEN_URL = "https://api.sandbox.ebay.com/identity/v1/oauth2/token"
    SANDBOX_USERINFO_URL = "https://api.sandbox.ebay.com/identity/v1/oauth2/userinfo"

    def __init__(self, client_id: str, client_secret: str, sandbox: bool = False, **kwargs):
        """
        Initialize eBay provider.
        Args:
            client_id: eBay Client ID
            client_secret: eBay Client Secret
            sandbox: Use sandbox environment (default: False)
            **kwargs: Additional configuration
        """
        if sandbox:
            authorization_url = self.SANDBOX_AUTHORIZATION_URL
            token_url = self.SANDBOX_TOKEN_URL
            userinfo_url = self.SANDBOX_USERINFO_URL
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
        return "ebay"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.EBAY

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from eBay.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize eBay user info format
        return {
            'id': user_info.get('sub'),
            'username': user_info.get('username'),
            'email': user_info.get('email'),
            'full_name': user_info.get('fullName'),
        }
