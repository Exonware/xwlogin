#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/figma.py
Figma OAuth Provider
OAuth 2.0 for Figma REST API; user info from GET /v1/me (scope current_user:read).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
import base64
from typing import Any, Optional
from exonware.xwsystem import get_logger
from exonware.xwsystem.http_client import AsyncHttpClient
logger = get_logger(__name__)


class FigmaProvider(ABaseProvider):
    """Figma OAuth 2.0 provider."""

    AUTHORIZATION_URL = "https://www.figma.com/oauth"
    TOKEN_URL = "https://api.figma.com/v1/oauth/token"
    ME_URL = "https://api.figma.com/v1/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=self.ME_URL,
            **kwargs
        )

    @property
    def provider_name(self) -> str:
        return "figma"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.FIGMA

    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str,
        *,
        code_verifier: Optional[str] = None,
    ) -> dict[str, Any]:
        if code_verifier:
            logger.debug("Figma token exchange may ignore PKCE code_verifier unless configured on app")
        basic = base64.b64encode(
            f"{self._client_id}:{self._client_secret}".encode("utf-8")
        ).decode("ascii")
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
        if self._async_http_client is None:
            self._async_http_client = AsyncHttpClient()
        try:
            response = await self._async_http_client.post(
                self.TOKEN_URL,
                data=data,
                headers={
                    "Authorization": f"Basic {basic}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            if response.status_code != 200:
                raise XWProviderConnectionError(
                    f"Figma token exchange failed: {response.status_code}",
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
            self.ME_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"Figma /v1/me failed: {response.status_code}",
                error_code="userinfo_failed",
                context={"status_code": response.status_code},
            )
        u = response.json()
        return {
            "id": u.get("id"),
            "email": u.get("email"),
            "handle": u.get("handle"),
            "img_url": u.get("img_url"),
        }
