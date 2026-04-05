#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/okta.py
Okta OAuth / OIDC Provider
Authorization Server default is ``default``; custom AS ids use the same ``/oauth2/{id}/v1`` layout.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 08-Apr-2026
"""

from __future__ import annotations

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
def _okta_host(okta_domain: str) -> str:
    d = okta_domain.strip().removeprefix("https://").removeprefix("http://").split("/")[0].strip()
    return d.rstrip("/")


class OktaProvider(ABaseProvider):
    """Okta OIDC authorization-code flow (tenant-specific host and authorization server)."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        okta_domain: str,
        authorization_server_id: str = "default",
        **kwargs: Any,
    ):
        host = _okta_host(okta_domain)
        aid = authorization_server_id.strip().strip("/")
        issuer = f"https://{host}/oauth2/{aid}"
        base = f"{issuer}/v1"
        self._issuer = issuer
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{base}/authorize",
            token_url=f"{base}/token",
            userinfo_url=f"{base}/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "okta"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.OKTA

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/v1/keys"

    def _get_authorization_params(self) -> dict[str, Any]:
        return {}
