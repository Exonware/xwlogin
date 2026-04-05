#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/linear.py
Linear OAuth Provider
Linear OAuth 2.0; user profile via GraphQL viewer query.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any, Optional
from exonware.xwsystem import get_logger
from exonware.xwsystem.http_client import AsyncHttpClient
logger = get_logger(__name__)


class LinearProvider(ABaseProvider):
    """Linear OAuth 2.0 provider."""

    AUTHORIZATION_URL = "https://linear.app/oauth/authorize"
    TOKEN_URL = "https://api.linear.app/oauth/token"
    GRAPHQL_URL = "https://api.linear.app/graphql"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
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
        return "linear"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.LINEAR

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        query = "query { viewer { id name email displayName avatarUrl } }"
        if self._async_http_client is None:
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.post(
            self.GRAPHQL_URL,
            json_data={"query": query},
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"Linear GraphQL failed: {response.status_code}",
                error_code="userinfo_failed",
                context={"status_code": response.status_code},
            )
        body = response.json()
        err = body.get("errors")
        if err:
            raise XWProviderConnectionError(
                f"Linear GraphQL errors: {err}",
                error_code="userinfo_failed",
            )
        viewer = (body.get("data") or {}).get("viewer") or {}
        return {
            "id": viewer.get("id"),
            "email": viewer.get("email"),
            "name": viewer.get("name") or viewer.get("displayName"),
            "display_name": viewer.get("displayName"),
            "avatar_url": viewer.get("avatarUrl"),
        }
