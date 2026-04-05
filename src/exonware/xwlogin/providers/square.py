#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/square.py
Square OAuth Provider
Square Connect OAuth 2.0 for seller / merchant authorization.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
from exonware.xwsystem.http_client import AsyncHttpClient
logger = get_logger(__name__)


class SquareProvider(ABaseProvider):
    """Square Connect OAuth 2.0 provider."""

    AUTHORIZATION_URL = "https://connect.squareup.com/oauth2/authorize"
    TOKEN_URL = "https://connect.squareup.com/oauth2/token"
    MERCHANT_PROFILE_URL = "https://connect.squareup.com/v2/merchants/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=self.MERCHANT_PROFILE_URL,
            **kwargs
        )

    @property
    def provider_name(self) -> str:
        return "square"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.SQUARE

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """Normalize Square merchant profile (seller) payload."""
        if self._async_http_client is None:
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self.MERCHANT_PROFILE_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Square-Version": "2024-01-18",
            },
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"Square merchant profile failed: {response.status_code}",
                error_code="userinfo_failed",
                context={"status_code": response.status_code},
            )
        body = response.json()
        merchant = body.get("merchant") or body
        main_loc = merchant.get("main_location_id")
        return {
            "id": str(merchant.get("id", "")),
            "name": merchant.get("business_name"),
            "country": merchant.get("country"),
            "language_code": merchant.get("language_code"),
            "main_location_id": main_loc,
            "status": merchant.get("status"),
        }
