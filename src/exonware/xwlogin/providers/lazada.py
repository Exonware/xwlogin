#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/lazada.py
Lazada OAuth Provider
Lazada OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class LazadaProvider(ABaseProvider):
    """Lazada OAuth 2.0 provider."""
    # Lazada uses country-specific endpoints
    AUTHORIZATION_URL = "https://auth.lazada.com/oauth/authorize"
    TOKEN_URL = "https://auth.lazada.com/rest/auth/token/create"
    USERINFO_URL = "https://api.lazada.com.my/rest/user/get"

    def __init__(self, client_id: str, client_secret: str, country: str = "MY", **kwargs):
        """
        Initialize Lazada provider.
        Args:
            client_id: Lazada App Key
            client_secret: Lazada App Secret
            country: Country code (MY, SG, TH, PH, ID, VN) - default: MY
            **kwargs: Additional configuration
        """
        # Country-specific domain
        country_map = {
            "MY": "lazada.com.my",
            "SG": "lazada.sg",
            "TH": "lazada.co.th",
            "PH": "lazada.com.ph",
            "ID": "lazada.co.id",
            "VN": "lazada.vn",
        }
        domain = country_map.get(country.upper(), "lazada.com.my")
        authorization_url = f"https://auth.{domain}/oauth/authorize"
        token_url = f"https://auth.{domain}/rest/auth/token/create"
        userinfo_url = f"https://api.{domain}/rest/user/get"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            **kwargs
        )
        self.country = country.upper()
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "lazada"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.LAZADA

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Lazada.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Lazada user info format
        return {
            'id': str(user_info.get('user_id')),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
        }
