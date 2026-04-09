#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/stripe.py
Stripe Connect OAuth Provider
Stripe Connect Standard account OAuth (authorization code to access token).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any, Optional
from exonware.xwsystem import get_logger
from exonware.xwsystem.http_client import AsyncHttpClient
logger = get_logger(__name__)


class StripeConnectProvider(ABaseProvider):
    """Stripe Connect OAuth 2.0 for connected Standard accounts."""

    AUTHORIZATION_URL = "https://connect.stripe.com/oauth/authorize"
    TOKEN_URL = "https://connect.stripe.com/oauth/token"
    ACCOUNT_URL = "https://api.stripe.com/v1/account"

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
        return "stripe"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.STRIPE_CONNECT

    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str,
        *,
        code_verifier: Optional[str] = None,
    ) -> dict[str, Any]:
        if code_verifier:
            logger.warning("Stripe Connect code exchange does not use PKCE code_verifier on this path")
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
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
                    f"Stripe token exchange failed: {response.status_code}",
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
            self.ACCOUNT_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"Stripe account info failed: {response.status_code}",
                error_code="userinfo_failed",
                context={"status_code": response.status_code},
            )
        acct = response.json()
        email = acct.get("email")
        biz = acct.get("business_profile") or {}
        if not email:
            email = biz.get("support_email")
        return {
            "id": acct.get("id"),
            "email": email,
            "country": acct.get("country"),
            "business_name": biz.get("name"),
            "charges_enabled": acct.get("charges_enabled"),
            "type": acct.get("type"),
        }
