#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/fitbit.py
Fitbit OAuth Provider
OAuth 2.0 (PKCE recommended). Token endpoint expects HTTP Basic auth with
client_id:client_secret for confidential server apps per Fitbit Web API docs.
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


class FitbitProvider(ABaseProvider):
    """Fitbit OAuth 2.0 provider."""

    AUTHORIZATION_URL = "https://www.fitbit.com/oauth2/authorize"
    TOKEN_URL = "https://api.fitbit.com/oauth2/token"
    PROFILE_URL = "https://api.fitbit.com/1/user/-/profile.json"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=self.PROFILE_URL,
            **kwargs
        )

    @property
    def provider_name(self) -> str:
        return "fitbit"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.FITBIT

    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str,
        *,
        code_verifier: Optional[str] = None,
    ) -> dict[str, Any]:
        basic = base64.b64encode(
            f"{self._client_id}:{self._client_secret}".encode("utf-8")
        ).decode("ascii")
        data: dict[str, Any] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
        if code_verifier:
            data["code_verifier"] = code_verifier
        if self._async_http_client is None:
            self._async_http_client = AsyncHttpClient()
        try:
            response = await self._async_http_client.post(
                self._token_url,
                data=data,
                headers={
                    "Authorization": f"Basic {basic}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            if response.status_code != 200:
                raise XWProviderConnectionError(
                    f"Fitbit token exchange failed: {response.status_code}",
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
            self.PROFILE_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"Fitbit profile failed: {response.status_code}",
                error_code="userinfo_failed",
                context={"status_code": response.status_code},
            )
        body = response.json()
        user = body.get("user") or {}
        return {
            "id": user.get("encodedId"),
            "display_name": user.get("displayName"),
            "full_name": user.get("fullName"),
            "gender": user.get("gender"),
            "email": user.get("email"),
        }
