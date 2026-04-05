#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/strava.py
Strava OAuth Provider
Strava OAuth 2.0 — scopes are comma-separated on the authorize URL.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any, Optional
from urllib.parse import urlencode
from exonware.xwsystem import get_logger
from exonware.xwsystem.http_client import AsyncHttpClient
logger = get_logger(__name__)


class StravaProvider(ABaseProvider):
    """Strava OAuth 2.0 for athlete / activity APIs."""

    AUTHORIZATION_URL = "https://www.strava.com/oauth/authorize"
    TOKEN_URL = "https://www.strava.com/oauth/token"
    ATHLETE_URL = "https://www.strava.com/api/v3/athlete"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=self.ATHLETE_URL,
            **kwargs
        )

    @property
    def provider_name(self) -> str:
        return "strava"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.STRAVA

    async def get_authorization_url(
        self,
        client_id: str,
        redirect_uri: str,
        state: str,
        scopes: Optional[list[str]] = None,
        nonce: Optional[str] = None,
        code_verifier: Optional[str] = None,
    ) -> str:
        params: dict[str, Any] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
        }
        if scopes:
            params["scope"] = ",".join(scopes)
        if code_verifier:
            params["code_challenge"] = self._pkce_s256_challenge(code_verifier)
            params["code_challenge_method"] = "S256"
        params.update(self._get_authorization_params())
        return f"{self._authorization_url}?{urlencode(params)}"

    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str,
        *,
        code_verifier: Optional[str] = None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if code_verifier:
            data["code_verifier"] = code_verifier
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
                    f"Strava token exchange failed: {response.status_code}",
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
            self.ATHLETE_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"Strava athlete profile failed: {response.status_code}",
                error_code="userinfo_failed",
                context={"status_code": response.status_code},
            )
        a = response.json()
        return {
            "id": str(a.get("id", "")),
            "firstname": a.get("firstname"),
            "lastname": a.get("lastname"),
            "city": a.get("city"),
            "country": a.get("country"),
            "email": a.get("email"),
        }
