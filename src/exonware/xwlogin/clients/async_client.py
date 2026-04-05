#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/clients/async_client.py
Async OAuth Client Utilities
Async utilities for OAuth client operations with multiple HTTP backends.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from typing import Any, Optional
from exonware.xwsystem import get_logger
from .oauth2_client import OAuth2Session
logger = get_logger(__name__)


class AsyncOAuth2Session(OAuth2Session):
    """
    Async OAuth 2.0 session with automatic token refresh.
    Extends OAuth2Session with async-specific features.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: Optional[str] = None,
        token: Optional[dict[str, Any]] = None,
        token_url: Optional[str] = None,
        auto_refresh: bool = True,
        http_backend: str = "httpx"
    ):
        """
        Initialize async OAuth 2.0 session.
        Args:
            client_id: OAuth client ID
            client_secret: OAuth client secret
            token: Existing token dictionary
            token_url: Token endpoint URL (for auto-refresh)
            auto_refresh: Automatically refresh expired tokens
            http_backend: HTTP client backend
        """
        super().__init__(client_id, client_secret, token, http_backend)
        self._token_url = token_url
        self._auto_refresh = auto_refresh

    async def request(
        self,
        method: str,
        url: str,
        auto_refresh: Optional[bool] = None,
        **kwargs
    ) -> Any:
        """
        Make authenticated request with automatic token refresh.
        Args:
            method: HTTP method
            url: Request URL
            auto_refresh: Override auto-refresh setting
            **kwargs: Additional request parameters
        Returns:
            HTTP response
        """
        auto_refresh = auto_refresh if auto_refresh is not None else self._auto_refresh
        try:
            return await super().request(method, url, **kwargs)
        except Exception as e:
            # If 401 and auto_refresh enabled, try refreshing token
            if auto_refresh and self._token_url and "401" in str(e):
                logger.debug("Token expired, attempting refresh")
                await self.refresh_token(self._token_url)
                return await super().request(method, url, **kwargs)
            raise
