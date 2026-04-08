#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/notion.py
Notion OAuth Provider
Public integrations: JSON token exchange with HTTP Basic (client_id:client_secret).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
import base64
from typing import Any, Optional
from exonware.xwsystem import get_logger
from exonware.xwsystem.http_client import AsyncHttpClient
logger = get_logger(__name__)


class NotionProvider(ABaseProvider):
    """Notion OAuth 2.0 for public workspace integrations."""

    AUTHORIZATION_URL = "https://api.notion.com/v1/oauth/authorize"
    TOKEN_URL = "https://api.notion.com/v1/oauth/token"
    USERINFO_URL = "https://api.notion.com/v1/users/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
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
        return "notion"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.NOTION

    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str,
        *,
        code_verifier: Optional[str] = None,
    ) -> dict[str, Any]:
        if code_verifier:
            logger.debug("Notion token exchange ignores PKCE code_verifier")
        basic = base64.b64encode(
            f"{self._client_id}:{self._client_secret}".encode("utf-8")
        ).decode("ascii")
        payload: dict[str, Any] = {"grant_type": "authorization_code", "code": code}
        if redirect_uri:
            payload["redirect_uri"] = redirect_uri
        if self._async_http_client is None:
            self._async_http_client = AsyncHttpClient()
        try:
            response = await self._async_http_client.post(
                self.TOKEN_URL,
                json_data=payload,
                headers={
                    "Authorization": f"Basic {basic}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            if response.status_code != 200:
                raise XWProviderConnectionError(
                    f"Notion token exchange failed: {response.status_code}",
                    error_code="token_exchange_failed",
                    context={"status_code": response.status_code, "response": response.text},
                )
            return response.json()
        except XWProviderConnectionError:
            raise
        except Exception as e:
            raise XWProviderConnectionError(
                f"Token exchange error: {e}",
                error_code="token_exchange_error",
                cause=e,
            )

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        if self._async_http_client is None:
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self.USERINFO_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Notion-Version": "2022-06-28",
            },
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"Notion user info failed: {response.status_code}",
                error_code="userinfo_failed",
                context={"status_code": response.status_code},
            )
        u = response.json()
        return {
            "id": u.get("id"),
            "name": u.get("name"),
            "type": u.get("type"),
            "avatar_url": u.get("avatar_url"),
        }
