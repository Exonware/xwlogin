#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/rakbank.py
RAKBANK OAuth Provider
RAKBANK OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class RAKBANKProvider(ABaseProvider):
    """RAKBANK OAuth 2.0 provider."""
    # RAKBANK API endpoints
    AUTHORIZATION_URL = "https://api.rakbank.ae/sb/api/v1/customer_signin/oauth2/authorize"
    TOKEN_URL = "https://api.rakbank.ae/sb/api/v1/customer_signin/oauth2/token"
    USERINFO_URL = "https://api.rakbank.ae/sb/api/v1/customer_signin/userinfo"
    # Sandbox endpoints
    SANDBOX_AUTHORIZATION_URL = "https://sandboxapi.rakbank.ae/sb/api/v1/customer_signin/oauth2/authorize"
    SANDBOX_TOKEN_URL = "https://sandboxapi.rakbank.ae/sb/api/v1/customer_signin/oauth2/token"
    SANDBOX_USERINFO_URL = "https://sandboxapi.rakbank.ae/sb/api/v1/customer_signin/userinfo"

    def __init__(self, client_id: str, client_secret: str, sandbox: bool = False, **kwargs):
        """
        Initialize RAKBANK provider.
        Args:
            client_id: RAKBANK API client ID
            client_secret: RAKBANK API client secret
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
        return "rakbank"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.RAKBANK

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from RAKBANK.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize RAKBANK user info format
        return {
            'id': str(user_info.get('id')),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'phone': user_info.get('phone'),
        }
