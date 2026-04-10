#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/enterprise_tier2_oidc.py
Tier-2 enterprise workforce IdPs with common OIDC URL layouts (tenant or host parameters).

Deployments vary; use each vendor's OpenID Provider Metadata (/.well-known/openid-configuration)
when paths differ from the defaults encoded here.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 08-Apr-2026
"""

from __future__ import annotations

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
def _host_only(url: str) -> str:
    return (
        url.strip()
        .removeprefix("https://")
        .removeprefix("http://")
        .split("/")[0]
        .strip()
        .rstrip("/")
    )


def _https_base(url: str) -> str:
    h = _host_only(url)
    return f"https://{h}"


class OneLoginOidcProvider(ABaseProvider):
    """OneLogin OpenID Connect (OIDC 2.0 endpoints under ``/oidc/2``)."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        onelogin_subdomain: str,
        **kwargs: Any,
    ):
        sub = _host_only(onelogin_subdomain).split(".")[0]
        issuer = f"https://{sub}.onelogin.com/oidc/2"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{issuer}/auth",
            token_url=f"{issuer}/token",
            userinfo_url=f"{issuer}/me",
            **kwargs,
        )
        self._issuer = issuer

    @property
    def provider_name(self) -> str:
        return "onelogin"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.ONELOGIN

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/certs"


class JumpCloudOidcProvider(ABaseProvider):
    """JumpCloud OIDC (hosted authorization server at ``oauth.id.jumpcloud.com``)."""

    _HOST = "https://oauth.id.jumpcloud.com"

    def __init__(self, client_id: str, client_secret: str, **kwargs: Any):
        self._issuer = self._HOST
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{self._HOST}/oauth2/auth",
            token_url=f"{self._HOST}/oauth2/token",
            userinfo_url=f"{self._HOST}/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "jumpcloud"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.JUMPCLOUD

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/oauth2/certs"


class PingOneOidcProvider(ABaseProvider):
    """PingOne (Ping Identity cloud) — OAuth AS at ``auth.pingone.com``."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        environment_id: str,
        **kwargs: Any,
    ):
        env = environment_id.strip().strip("/")
        base = f"https://auth.pingone.com/{env}/as"
        self._issuer = base
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
        return "ping_one"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.PING_ONE

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/jwks"


class AzureAdB2CPolicyProvider(ABaseProvider):
    """Microsoft Entra External ID (Azure AD B2C) — user-flow / policy in path segment."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        tenant_name: str,
        policy_name: str,
        **kwargs: Any,
    ):
        t = tenant_name.strip().removesuffix(".onmicrosoft.com")
        pol = policy_name.strip().strip("/")
        host = f"{t}.b2clogin.com"
        self._issuer = f"https://{host}/{t}.onmicrosoft.com/{pol}/v2.0"
        b2c_base = f"https://{host}/{t}.onmicrosoft.com/{pol}/oauth2/v2.0"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{b2c_base}/authorize",
            token_url=f"{b2c_base}/token",
            userinfo_url=None,
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "azure_ad_b2c"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.AZURE_AD_B2C

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/keys"


class FusionAuthProvider(ABaseProvider):
    """FusionAuth — OIDC under ``/oauth2`` on your FusionAuth host."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        fusionauth_host: str,
        **kwargs: Any,
    ):
        base = _https_base(fusionauth_host).rstrip("/")
        self._issuer = base
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{base}/oauth2/authorize",
            token_url=f"{base}/oauth2/token",
            userinfo_url=f"{base}/oauth2/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "fusionauth"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.FUSIONAUTH

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/.well-known/jwks.json"


class ZitadelProvider(ABaseProvider):
    """ZITADEL — OIDC paths under ``/oauth/v2`` on your instance host."""

    def __init__(self, client_id: str, client_secret: str, *, host: str, **kwargs: Any):
        base = _https_base(host).rstrip("/")
        self._issuer = base
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{base}/oauth/v2/authorize",
            token_url=f"{base}/oauth/v2/token",
            userinfo_url=f"{base}/oidc/v1/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "zitadel"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.ZITADEL

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/oauth/v2/keys"


class AuthentikApplicationProvider(ABaseProvider):
    """authentik application OIDC (slug selects the provider)."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        authentik_host: str,
        application_slug: str,
        **kwargs: Any,
    ):
        base = _https_base(authentik_host).rstrip("/")
        slug = application_slug.strip().strip("/")
        self._issuer = f"{base}/application/o/{slug}/"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{self._issuer}authorize/",
            token_url=f"{self._issuer}token/",
            userinfo_url=f"{self._issuer}userinfo/",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "authentik"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.AUTHENTIK

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer.removesuffix("/")

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}jwks/"


class Wso2IdentityServerProvider(ABaseProvider):
    """WSO2 Identity Server default OAuth2 endpoints (adjust base if context path is used)."""

    def __init__(self, client_id: str, client_secret: str, *, wso2_base_url: str, **kwargs: Any):
        base = wso2_base_url.strip().rstrip("/")
        if not base.startswith("http"):
            base = f"https://{base}"
        self._base = base
        self._issuer = f"{base}/oauth2/token"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{base}/oauth2/authorize",
            token_url=f"{base}/oauth2/token",
            userinfo_url=f"{base}/oauth2/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "wso2_identity_server"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.WSO2_IDENTITY_SERVER

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._base}/oauth2/jwks"


class GluuServerProvider(ABaseProvider):
    """Gluu Server (oxAuth) default REST paths."""

    def __init__(self, client_id: str, client_secret: str, *, gluu_host: str, **kwargs: Any):
        base = _https_base(gluu_host).rstrip("/")
        self._issuer = base
        p = f"{base}/oxauth/restv1"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{p}/authorize",
            token_url=f"{p}/token",
            userinfo_url=f"{p}/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "gluu_server"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.GLUU_SERVER

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/oxauth/restv1/jwks"


class OracleIdentityCloudProvider(ABaseProvider):
    """Oracle Identity Cloud Service (IDCS) — tenant host under ``identity.oraclecloud.com``."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        idcs_domain_host: str,
        **kwargs: Any,
    ):
        base = _https_base(idcs_domain_host).rstrip("/")
        self._issuer = base
        p = f"{base}/oauth2/v1"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{p}/authorize",
            token_url=f"{p}/token",
            userinfo_url=f"{p}/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "oracle_identity_cloud"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.ORACLE_IDENTITY_CLOUD

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/oauth2/v1/keys"


class ForgeRockAmOidcProvider(ABaseProvider):
    """ForgeRock Access Management realm-based OAuth2 (path realms layout)."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        am_base_url: str,
        realm: str = "alpha",
        **kwargs: Any,
    ):
        base = am_base_url.strip().rstrip("/")
        if not base.startswith("http"):
            base = f"https://{base}"
        realm = realm.strip().strip("/")
        prefix = f"{base}/am/oauth2/realms/root/realms/{realm}"
        self._issuer = prefix
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{prefix}/authorize",
            token_url=f"{prefix}/access_token",
            userinfo_url=f"{prefix}/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "forgerock"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.FORGEROCK

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/connect/jwk_uri"


class CurityIdentityServerProvider(ABaseProvider):
    """Curity Identity Server default OAuth endpoints (path ``/oauth/v2``)."""

    def __init__(self, client_id: str, client_secret: str, *, node_base_url: str, **kwargs: Any):
        base = node_base_url.strip().rstrip("/")
        if not base.startswith("http"):
            base = f"https://{base}"
        self._issuer = base
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{base}/oauth/v2/oauth-authorize",
            token_url=f"{base}/oauth/v2/oauth-token",
            userinfo_url=f"{base}/oauth/v2/oauth-userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "curity_identity_server"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.CURITY_IDENTITY_SERVER

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/oauth/v2/oauth-anonymous/jwks"


class DuendeIdentityServerProvider(ABaseProvider):
    """Duende IdentityServer / ASP.NET OpenIddict style ``/connect`` endpoints."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        authority_base_url: str,
        **kwargs: Any,
    ):
        base = authority_base_url.strip().rstrip("/")
        if not base.startswith("http"):
            base = f"https://{base}"
        self._issuer = base
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{base}/connect/authorize",
            token_url=f"{base}/connect/token",
            userinfo_url=f"{base}/connect/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "duende_identity_server"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.DUENDE_IDENTITY_SERVER

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/.well-known/openid-configuration/jwks"


class SapCloudIdentityProvider(ABaseProvider):
    """SAP Cloud Identity Services (IAS) default OAuth2 host pattern."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        ias_tenant_host: str,
        **kwargs: Any,
    ):
        base = _https_base(ias_tenant_host).rstrip("/")
        self._issuer = base
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{base}/oauth2/authorize",
            token_url=f"{base}/oauth2/token",
            userinfo_url=f"{base}/oauth2/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "sap_cloud_identity"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.SAP_CLOUD_IDENTITY

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/oauth2/certs"
