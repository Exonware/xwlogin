#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/mercado_libre.py
Mercado Libre OAuth Provider
Mercado Libre OAuth 2.0 provider implementation.
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


class MercadoLibreProvider(ABaseProvider):
    """Mercado Libre OAuth 2.0 provider."""
    # Mercado Libre uses country-specific endpoints
    # Default to Argentina, but can be configured for other countries
    AUTHORIZATION_URL = "https://auth.mercadolibre.com.ar/authorization"
    TOKEN_URL = "https://api.mercadolibre.com/oauth/token"
    USERINFO_URL = "https://api.mercadolibre.com/users/me"

    def __init__(self, client_id: str, client_secret: str, country: str = "AR", **kwargs):
        """
        Initialize Mercado Libre provider.
        Args:
            client_id: Mercado Libre Application ID
            client_secret: Mercado Libre Secret Key
            country: Country code (AR, BR, MX, CO, CL, etc.) - default: AR
            **kwargs: Additional configuration
        """
        # Country-specific authorization URL
        country_map = {
            "AR": "mercadolibre.com.ar",
            "BR": "mercadolivre.com.br",
            "MX": "mercadolibre.com.mx",
            "CO": "mercadolibre.com.co",
            "CL": "mercadolibre.cl",
        }
        domain = country_map.get(country.upper(), "mercadolibre.com.ar")
        authorization_url = f"https://auth.{domain}/authorization"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=self.TOKEN_URL,
            userinfo_url=self.USERINFO_URL,
            **kwargs
        )
        self.country = country.upper()
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "mercado_libre"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.MERCADO_LIBRE

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Mercado Libre.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Mercado Libre user info format
        return {
            'id': str(user_info.get('id')),
            'nickname': user_info.get('nickname'),
            'email': user_info.get('email'),
            'first_name': user_info.get('first_name'),
            'last_name': user_info.get('last_name'),
            'country_id': user_info.get('country_id'),
        }
