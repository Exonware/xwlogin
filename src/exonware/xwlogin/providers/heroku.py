#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/heroku.py
Heroku OAuth Provider
Platform API via id.heroku.com OAuth 2.0.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
from exonware.xwsystem.http_client import AsyncHttpClient
logger = get_logger(__name__)


class HerokuProvider(ABaseProvider):
    """Heroku OAuth 2.0 (Platform API) provider."""

    AUTHORIZATION_URL = "https://id.heroku.com/oauth/authorize"
    TOKEN_URL = "https://id.heroku.com/oauth/token"
    ACCOUNT_URL = "https://api.heroku.com/account"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=self.ACCOUNT_URL,
            **kwargs
        )

    @property
    def provider_name(self) -> str:
        return "heroku"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.HEROKU

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        if self._async_http_client is None:
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self.ACCOUNT_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.heroku+json; version=3",
            },
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"Heroku account failed: {response.status_code}",
                error_code="userinfo_failed",
                context={"status_code": response.status_code},
            )
        u = response.json()
        return {
            "id": u.get("id"),
            "email": u.get("email"),
            "name": f"{u.get('name', '')}".strip() or None,
        }
