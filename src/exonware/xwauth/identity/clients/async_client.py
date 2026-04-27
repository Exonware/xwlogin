#!/usr/bin/env python3
"""
#exonware/xwauth-identity/src/exonware/xwauth/identity/clients/async_client.py
Async OAuth 2.0 client session helpers.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
"""

from __future__ import annotations

from typing import Any, Optional

from exonware.xwsystem import get_logger

from .oauth2_client import OAuth2Session

logger = get_logger(__name__)


class AsyncOAuth2Session(OAuth2Session):
    """Async OAuth 2.0 session with optional token refresh on 401."""

    def __init__(
        self,
        client_id: str,
        client_secret: Optional[str] = None,
        token: Optional[dict[str, Any]] = None,
        token_url: Optional[str] = None,
        auto_refresh: bool = True,
        http_backend: str = "httpx",
    ):
        super().__init__(client_id, client_secret, token, http_backend)
        self._token_url = token_url
        self._auto_refresh = auto_refresh

    async def request(
        self,
        method: str,
        url: str,
        auto_refresh: Optional[bool] = None,
        **kwargs: Any,
    ) -> Any:
        auto_refresh = (
            auto_refresh if auto_refresh is not None else self._auto_refresh
        )
        try:
            return await super().request(method, url, **kwargs)
        except Exception as e:
            if auto_refresh and self._token_url and "401" in str(e):
                logger.debug("Token expired, attempting refresh")
                await self.refresh_token(self._token_url)
                return await super().request(method, url, **kwargs)
            raise
