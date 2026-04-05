#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/auth0.py
Auth0 OIDC Provider
Uses your tenant domain (e.g. ``dev-abc.us.auth0.com`` or regional EU host).
For EU-only residency see ``Auth0EuropeProvider`` in ``eidas_europe_providers``.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 08-Apr-2026
"""

from __future__ import annotations

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
def _auth0_domain(domain: str) -> str:
    d = domain.strip().removeprefix("https://").removeprefix("http://").split("/")[0].strip()
    return d.rstrip("/")


class Auth0Provider(ABaseProvider):
    """Auth0 OAuth 2.0 / OIDC (any regional Auth0 hostname)."""

    def __init__(self, client_id: str, client_secret: str, *, domain: str, **kwargs: Any):
        host = _auth0_domain(domain)
        base = f"https://{host}"
        self._issuer = base
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{base}/authorize",
            token_url=f"{base}/oauth/token",
            userinfo_url=f"{base}/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "auth0"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.AUTH0

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/.well-known/jwks.json"

    def _get_authorization_params(self) -> dict[str, Any]:
        return {}
