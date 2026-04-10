#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/bigcommerce.py
BigCommerce OAuth Provider
OAuth 2.0 for BigCommerce apps (marketplace / single-click install).
Token exchange requires the `context` string returned on your /auth callback — call
`set_oauth_context` before `exchange_code_for_token`.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError, XWProviderError
from typing import Any, Optional
from exonware.xwsystem import get_logger
from exonware.xwsystem.http_client import AsyncHttpClient
logger = get_logger(__name__)


class BigCommerceProvider(ABaseProvider):
    """BigCommerce OAuth 2.0 (authorization code) for store-scoped apps."""

    AUTHORIZATION_URL = "https://login.bigcommerce.com/oauth2/authorize"
    TOKEN_URL = "https://login.bigcommerce.com/oauth2/token"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        self._oauth_context: str | None = kwargs.pop("oauth_context", None)
        self._last_token: dict[str, Any] = {}
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=None,
            **kwargs
        )

    def set_oauth_context(self, context: str) -> None:
        """Set the `context` query value from the BigCommerce install callback before token exchange."""
        self._oauth_context = context

    @property
    def provider_name(self) -> str:
        return "bigcommerce"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.BIGCOMMERCE

    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str,
        *,
        code_verifier: Optional[str] = None,
    ) -> dict[str, Any]:
        ctx = self._oauth_context
        if not ctx:
            raise XWProviderError(
                "BigCommerce token exchange requires oauth context from the install callback",
                error_code="bigcommerce_context_required",
                suggestions=["Call set_oauth_context(context) with the value from the callback URL"],
            )
        data: dict[str, Any] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "context": ctx,
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
                    f"BigCommerce token exchange failed: {response.status_code}",
                    error_code="token_exchange_failed",
                    context={"status_code": response.status_code, "response": response.text},
                )
            self._last_token = response.json()
            return self._last_token
        except XWProviderError:
            raise
        except Exception as e:
            raise XWProviderConnectionError(
                f"Token exchange error: {e}",
                error_code="token_exchange_error",
                cause=e,
            )

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """Loads store metadata via BigCommerce Management API using the store hash from token/context."""
        path = self._last_token.get("context") or self._oauth_context or ""
        store_hash: str | None = None
        if isinstance(path, str) and path.startswith("stores/"):
            store_hash = path.split("/", 1)[1].strip("/ ") or None
        if not store_hash and isinstance(self._last_token.get("user"), dict):
            uid = self._last_token["user"].get("id")
            if uid is not None:
                store_hash = str(uid)
        if not store_hash:
            raise XWProviderError(
                "Cannot resolve BigCommerce store hash; complete token exchange first",
                error_code="bigcommerce_store_unknown",
            )
        url = f"https://api.bigcommerce.com/stores/{store_hash}/v2/store"
        if self._async_http_client is None:
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            url,
            headers={
                "X-Auth-Token": access_token,
                "Accept": "application/json",
            },
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"BigCommerce store info failed: {response.status_code}",
                error_code="userinfo_failed",
                context={"status_code": response.status_code},
            )
        info = response.json()
        return {
            "id": str(info.get("id", store_hash)),
            "name": info.get("name"),
            "domain": info.get("domain"),
            "email": info.get("admin_email") or info.get("order_email"),
            "store_hash": store_hash,
        }
