#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/feishu.py
Feishu / Lark OAuth Provider
ByteDance Feishu (飞书) domestic and Lark international use the same app model;
hosts differ (accounts.feishu.cn vs accounts.larksuite.com).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 07-Apr-2026
"""

from __future__ import annotations

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError, XWProviderError
import json
from typing import Any, Literal, Optional

from exonware.xwsystem.http_client import AsyncHttpClient
class FeishuProvider(ABaseProvider):
    """
    Feishu Open Platform user OAuth (authorization code → user_access_token).

    * ``feishu_cn`` — mainland Feishu (accounts.feishu.cn / open.feishu.cn).
    * ``lark_intl`` — international Lark (accounts.larksuite.com / open.larksuite.com).
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        app_region: Literal["feishu_cn", "lark_intl"] = "feishu_cn",
        **kwargs: Any,
    ):
        if app_region == "lark_intl":
            accounts = "https://accounts.larksuite.com"
            open_api = "https://open.larksuite.com"
        else:
            accounts = "https://accounts.feishu.cn"
            open_api = "https://open.feishu.cn"
        auth_url = f"{accounts}/open-apis/authen/v1/authorize"
        token_url = f"{open_api}/open-apis/authen/v2/oauth/token"
        userinfo_url = f"{open_api}/open-apis/authen/v1/user_info"
        self._app_region = app_region
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=auth_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "feishu"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.FEISHU

    def _get_authorization_params(self) -> dict[str, Any]:
        return {}

    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str,
        *,
        code_verifier: Optional[str] = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "grant_type": "authorization_code",
            "client_id": self._client_id,
            "client_secret": self._token_exchange_client_secret(),
            "code": code,
        }
        if redirect_uri:
            payload["redirect_uri"] = redirect_uri
        if code_verifier:
            payload["code_verifier"] = code_verifier
        if self._async_http_client is None:
            self._async_http_client = AsyncHttpClient()
        try:
            response = await self._async_http_client.post(
                self._token_url,
                json_data=payload,
                headers={
                    "Content-Type": "application/json; charset=utf-8",
                    "Accept": "application/json",
                },
            )
            if response.status_code != 200:
                raise XWProviderConnectionError(
                    f"Feishu token exchange failed: {response.status_code} {response.text[:500]}",
                    error_code="token_exchange_failed",
                    context={"status_code": response.status_code},
                )
            body = response.json()
        except XWProviderConnectionError:
            raise
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            raise XWProviderConnectionError(
                f"Feishu token response parse error: {e}",
                error_code="token_exchange_error",
                cause=e,
            )
        except Exception as e:
            raise XWProviderConnectionError(
                f"Feishu token exchange error: {e}",
                error_code="token_exchange_error",
                cause=e,
            )

        c = body.get("code") if isinstance(body, dict) else None
        if c is not None and c != 0:
            msg = body.get("msg") or body.get("message") or str(body)
            raise XWProviderConnectionError(
                f"Feishu API error: {msg}",
                error_code="token_exchange_failed",
                context={"feishu_code": c},
            )
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, dict):
            raise XWProviderConnectionError(
                "Feishu token response missing data",
                error_code="token_exchange_failed",
            )
        # Normalize for callers expecting RFC-style keys
        return {
            "access_token": data.get("access_token"),
            "refresh_token": data.get("refresh_token"),
            "expires_in": data.get("expires_in"),
            "token_type": data.get("token_type") or "Bearer",
            "refresh_expires_in": data.get("refresh_expires_in"),
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        from exonware.xwsystem import HTTP_CLIENT_AVAILABLE

        if not HTTP_CLIENT_AVAILABLE:
            raise XWProviderConnectionError(
                "HTTP client not available",
                error_code="http_client_unavailable",
            )
        if not self._userinfo_url:
            raise XWProviderError("User info endpoint not configured", error_code="userinfo_not_configured")
        if self._async_http_client is None:
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self._userinfo_url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"Feishu userinfo failed: {response.status_code}",
                error_code="userinfo_failed",
                context={"status_code": response.status_code},
            )
        body = response.json()
        uc = body.get("code") if isinstance(body, dict) else None
        if uc is not None and uc != 0:
            msg = body.get("msg") or str(body)
            raise XWProviderConnectionError(
                f"Feishu userinfo API error: {msg}",
                error_code="userinfo_failed",
            )
        data = body.get("data") if isinstance(body, dict) else None
        return data if isinstance(data, dict) else (body if isinstance(body, dict) else {})


class LarkIntlProvider(FeishuProvider):
    """International Lark — Feishu enterprise product outside mainland China (fixed ``lark_intl`` hosts)."""

    def __init__(self, client_id: str, client_secret: str, **kwargs: Any):
        super().__init__(
            client_id,
            client_secret,
            app_region="lark_intl",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "lark"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.LARK
