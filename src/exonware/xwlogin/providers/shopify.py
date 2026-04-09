#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/shopify.py
Shopify OAuth Provider
Shopify OAuth 2.0 provider implementation.
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


class ShopifyProvider(ABaseProvider):
    """Shopify OAuth 2.0 provider."""

    def __init__(self, client_id: str, client_secret: str, shop: str, **kwargs):
        """
        Initialize Shopify provider.
        Args:
            client_id: Shopify OAuth client ID (API key)
            client_secret: Shopify OAuth client secret (API secret)
            shop: Shopify shop domain (e.g., 'myshop.myshopify.com' or 'myshop')
            **kwargs: Additional configuration
        """
        # Normalize shop domain
        if not shop.endswith('.myshopify.com'):
            shop = f"{shop}.myshopify.com"
        shop = shop.rstrip('/')
        authorization_url = f"https://{shop}/admin/oauth/authorize"
        token_url = f"https://{shop}/admin/oauth/access_token"
        # Shopify doesn't have a standard userinfo endpoint, use admin API
        userinfo_url = f"https://{shop}/admin/api/2024-01/shop.json"
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
        return "shopify"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.SHOPIFY

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get shop information from Shopify.
        Note: Shopify OAuth is primarily for app installation, not user authentication.
        This returns shop information instead of user information.
        Args:
            access_token: Access token
        Returns:
            Shop information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Shopify returns shop data, not user data
        shop_data = user_info.get('shop', user_info)
        return {
            'id': str(shop_data.get('id')),
            'name': shop_data.get('name'),
            'domain': shop_data.get('domain'),
            'email': shop_data.get('email'),
        }
