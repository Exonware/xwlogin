#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/stc_pay.py
STC Pay OAuth Provider
STC Pay OAuth 2.0 provider implementation.
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


class STCPayProvider(ABaseProvider):
    """STC Pay OAuth 2.0 provider."""
    # STC Pay API endpoints
    AUTHORIZATION_URL = "https://api.stcpay.com.sa/oauth/authorize"
    TOKEN_URL = "https://api.stcpay.com.sa/oauth/token"
    USERINFO_URL = "https://api.stcpay.com.sa/v1/user/info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize STC Pay provider.
        Args:
            client_id: STC Pay API client ID
            client_secret: STC Pay API client secret
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
        return "stc_pay"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.STC_PAY

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from STC Pay.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize STC Pay user info format
        return {
            'id': str(user_info.get('id')),
            'phone': user_info.get('phone'),
            'name': user_info.get('name'),
        }
