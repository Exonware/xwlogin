#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/shopee.py
Shopee OAuth Provider
Shopee OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class ShopeeProvider(ABaseProvider):
    """Shopee OAuth 2.0 provider."""
    # Shopee uses country-specific endpoints
    AUTHORIZATION_URL = "https://partner.shopeemobile.com/api/v2/shop/auth_partner"
    TOKEN_URL = "https://partner.shopeemobile.com/api/v2/auth/token/get"
    USERINFO_URL = "https://partner.shopeemobile.com/api/v2/shop/get_shop_info"

    def __init__(self, client_id: str, client_secret: str, country: str = "SG", **kwargs):
        """
        Initialize Shopee provider.
        Args:
            client_id: Shopee Partner ID
            client_secret: Shopee Partner Key
            country: Country code (SG, MY, TH, PH, ID, VN, TW) - default: SG
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
        self.country = country.upper()
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "shopee"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.SHOPEE

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Shopee.
        Note: Shopee API requires specific method calls and signature.
        This is a simplified implementation.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        logger.warning(
            "Shopee API requires method calls and signature. "
            "This is a simplified implementation. Full implementation needed for production."
        )
        return {
            'id': None,
            'name': None,
        }
