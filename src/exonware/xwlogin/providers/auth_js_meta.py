#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/auth_js_meta.py
Auth.js / NextAuth-style provider router
Delegates OAuth operations to registered concrete providers by string id (e.g. google, github),
similar to how Auth.js aggregates built-in providers in one configuration surface.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 02-Apr-2026
"""

from __future__ import annotations

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderError
from typing import Any, Mapping, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class AuthJsMetaProvider(ABaseProvider):
    """
    Meta-provider: call `bind(idp_key)` (or pass `active_idp=` in constructor) then use
    async methods — they forward to the mapped `ABaseProvider` using that provider's credentials.
    """

    def __init__(
        self,
        routes: Mapping[str, ABaseProvider],
        *,
        active_idp: str | None = None,
        **kwargs: Any,
    ):
        self._routes = dict(routes)
        self._active = active_idp
        super().__init__(
            client_id="__auth_js_meta__",
            client_secret="__auth_js_meta__",
            authorization_url="https://authjs.dev/",
            token_url="https://authjs.dev/",
            userinfo_url=None,
            **kwargs
        )

    def bind(self, idp_key: str) -> AuthJsMetaProvider:
        """Select which concrete provider id receives delegated calls (Auth.js `provider.id`)."""
        if idp_key not in self._routes:
            raise XWProviderError(
                f"Unknown Auth.js provider id: {idp_key}",
                error_code="auth_js_unknown_idp",
                suggestions=[f"Known ids: {sorted(self._routes.keys())}"],
            )
        self._active = idp_key
        return self

    def _active_provider(self) -> ABaseProvider:
        if not self._active or self._active not in self._routes:
            raise XWProviderError(
                "AuthJsMetaProvider has no active idp; call bind(idp_key) first",
                error_code="auth_js_no_active_idp",
                suggestions=["meta.bind('google')", "or pass active_idp= to the constructor"],
            )
        return self._routes[self._active]

    @property
    def provider_name(self) -> str:
        return "auth_js_meta"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.AUTH_JS_META

    async def get_authorization_url(
        self,
        client_id: str,
        redirect_uri: str,
        state: str,
        scopes: Optional[list[str]] = None,
        nonce: Optional[str] = None,
        code_verifier: Optional[str] = None,
    ) -> str:
        inner = self._active_provider()
        return await inner.get_authorization_url(
            inner._client_id,
            redirect_uri,
            state,
            scopes,
            nonce,
            code_verifier,
        )

    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str,
        *,
        code_verifier: Optional[str] = None,
    ) -> dict[str, Any]:
        inner = self._active_provider()
        return await inner.exchange_code_for_token(code, redirect_uri, code_verifier=code_verifier)

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        inner = self._active_provider()
        return await inner.get_user_info(access_token)

    def resolve(self, idp_key: str) -> ABaseProvider:
        """Return the concrete provider for wiring outside the meta-delegation path."""
        if idp_key not in self._routes:
            raise XWProviderError(
                f"Unknown Auth.js provider id: {idp_key}",
                error_code="auth_js_unknown_idp",
            )
        return self._routes[idp_key]
