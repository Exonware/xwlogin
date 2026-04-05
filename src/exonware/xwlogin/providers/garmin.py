#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/garmin.py
Garmin Connect Developer OAuth Provider
OAuth 2.0 with PKCE (required). Enrollment is program-specific; endpoints match
Garmin Connect Developer / Health API documentation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError, XWProviderError
from typing import Any, Optional
from exonware.xwsystem import get_logger
from exonware.xwsystem.http_client import AsyncHttpClient
logger = get_logger(__name__)


class GarminProvider(ABaseProvider):
    """Garmin OAuth 2.0 (PKCE) for approved Connect Developer integrations."""

    AUTHORIZATION_URL = "https://connect.garmin.com/oauth2Confirm"
    TOKEN_URL = "https://diauth.garmin.com/di-oauth2-service/oauth/token"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        self._last_token: dict[str, Any] = {}
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=None,
            **kwargs
        )

    @property
    def provider_name(self) -> str:
        return "garmin"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.GARMIN

    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str,
        *,
        code_verifier: Optional[str] = None,
    ) -> dict[str, Any]:
        if not code_verifier:
            raise XWProviderError(
                "Garmin OAuth requires PKCE; pass code_verifier when exchanging the code",
                error_code="garmin_pkce_required",
            )
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "code_verifier": code_verifier,
        }
        if redirect_uri:
            data["redirect_uri"] = redirect_uri
        if self._async_http_client is None:
            self._async_http_client = AsyncHttpClient()
        try:
            response = await self._async_http_client.post(
                self._token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if response.status_code != 200:
                raise XWProviderConnectionError(
                    f"Garmin token exchange failed: {response.status_code}",
                    error_code="token_exchange_failed",
                    context={"status_code": response.status_code, "response": response.text},
                )
            self._last_token = response.json()
            return self._last_token
        except XWProviderError:
            raise
        except XWProviderConnectionError:
            raise
        except Exception as e:
            raise XWProviderConnectionError(
                f"Token exchange error: {e}",
                error_code="token_exchange_error",
                cause=e,
            )

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        uid = (
            self._last_token.get("userId")
            or self._last_token.get("user_id")
            or self._last_token.get("sub")
        )
        if uid:
            return {"id": str(uid), "source": "token_response"}
        if self._async_http_client is None:
            self._async_http_client = AsyncHttpClient()
        for url in (
            "https://apis.garmin.com/wellness-api/rest/user/id",
            "https://healthapi.garmin.com/wellness-api/rest/user/id",
        ):
            try:
                r = await self._async_http_client.get(
                    url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if r.status_code == 200:
                    j = r.json()
                    return {
                        "id": str(j.get("userId", j.get("id", ""))),
                        "raw": j,
                    }
            except Exception:
                continue
        raise XWProviderError(
            "Could not resolve Garmin user id; confirm Health API access and token scope",
            error_code="garmin_user_unknown",
            suggestions=["Inspect token JSON for userId", "Use program-specific user endpoints from Garmin docs"],
        )
