#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/keycloak.py
Keycloak OIDC Provider
Self-hosted realm endpoints (``ProviderType.KEYCLOAK``). For EU residency labelling only,
see ``KeycloakEuProvider`` in ``eidas_europe_providers``.
Red Hat SSO is Keycloak-based — use ``RedHatSsoProvider`` for registry distinction.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 08-Apr-2026
"""

from __future__ import annotations

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
class KeycloakProvider(ABaseProvider):
    """Keycloak realm OpenID Connect endpoints."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        keycloak_base_url: str,
        realm: str,
        **kwargs: Any,
    ):
        base = keycloak_base_url.removesuffix("/")
        realm = realm.strip().strip("/")
        auth = f"{base}/realms/{realm}/protocol/openid-connect/auth"
        token = f"{base}/realms/{realm}/protocol/openid-connect/token"
        userinfo = f"{base}/realms/{realm}/protocol/openid-connect/userinfo"
        self._issuer = f"{base}/realms/{realm}"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=auth,
            token_url=token,
            userinfo_url=userinfo,
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "keycloak"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.KEYCLOAK

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/protocol/openid-connect/certs"


class RedHatSsoProvider(KeycloakProvider):
    """Red Hat SSO (RH-SSO) — same OIDC paths as Keycloak; separate registry key for RH deployments."""

    @property
    def provider_name(self) -> str:
        return "red_hat_sso"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.RED_HAT_SSO
