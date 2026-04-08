#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/deviantart.py
DeviantArt OAuth Provider
OAuth 2.1 apps require PKCE (S256) for authorization code flow.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
from exonware.xwsystem.http_client import AsyncHttpClient
logger = get_logger(__name__)


class DeviantArtProvider(ABaseProvider):
    """DeviantArt OAuth 2.0 / 2.1 provider."""

    AUTHORIZATION_URL = "https://www.deviantart.com/oauth2/authorize"
    TOKEN_URL = "https://www.deviantart.com/oauth2/token"
    WHOAMI_URL = "https://www.deviantart.com/api/v1/oauth2/user/whoami"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=self.WHOAMI_URL,
            **kwargs
        )

    @property
    def provider_name(self) -> str:
        return "deviantart"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.DEVIANTART

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        if self._async_http_client is None:
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self.WHOAMI_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "User-Agent": "xwauth/exonware",
            },
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"DeviantArt whoami failed: {response.status_code}",
                error_code="userinfo_failed",
                context={"status_code": response.status_code},
            )
        u = response.json()
        prof = u.get("user") or u
        return {
            "id": str(prof.get("userid", prof.get("userId", ""))),
            "username": prof.get("username"),
            "name": prof.get("name") or prof.get("display_name"),
        }
