# exonware/xwauth/oauth_http/discovery.py
"""
OAuth 2.0 AS Metadata (RFC 8414) and OIDC discovery.
Builds /.well-known/oauth-authorization-server and
/.well-known/openid-configuration JSON.
"""

from __future__ import annotations
from typing import Any
from exonware.xwauth.identity.api_paths import AUTH_PREFIX, OAUTH2_PREFIX, OIDC_PREFIX  # noqa: F401


def _authorization_endpoint_response_types(oauth21_compliant: bool) -> list[str]:
    """
    ``response_type`` values that match the authorize endpoint (hybrid always includes ``code``;
    pure implicit types are rejected by the OAuth2 front door).
    """
    if oauth21_compliant:
        return ["code", "code id_token"]
    return ["code", "code id_token", "code token", "code id_token token"]


def oauth_authorization_server_metadata(
    issuer: str,
    oauth2_prefix: str | None = None,
    auth_prefix: str | None = None,
    fapi20_compliant: bool = False,
    fapi20_require_par: bool = False,
    fapi20_require_jar: bool = False,
    fapi20_require_dpop_or_mtls: bool = False,
    allow_password_grant: bool = True,
    scopes_supported: list[str] | None = None,
    oauth21_compliant: bool = False,
) -> dict[str, Any]:
    """
    Build RFC 8414 Authorization Server Metadata.
    Args:
        issuer: AS base URL (e.g. https://example.com), no trailing slash.
        oauth2_prefix: OAuth 2.0 core prefix (default from api_paths.OAUTH2_PREFIX).
        auth_prefix: Auth prefix for DCR (default from api_paths.AUTH_PREFIX).
        fapi20_compliant: Enable FAPI 2.0 compliance mode (default: False).
        fapi20_require_par: Require PAR for all requests (default: False).
        fapi20_require_jar: Require JAR (JWT Secured Authorization Request) (default: False).
        fapi20_require_dpop_or_mtls: Require DPoP or mTLS for token binding (default: False).
        oauth21_compliant: When True, omit hybrid response types that return access_token on redirect.
    Returns:
        JSON-serializable metadata dict.
    """
    base = issuer.rstrip("/")
    o2 = (oauth2_prefix or OAUTH2_PREFIX).rstrip("/") or OAUTH2_PREFIX
    ap = (auth_prefix or AUTH_PREFIX).rstrip("/") or AUTH_PREFIX
    grant_types = [
        "authorization_code",
        "refresh_token",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code",
    ]
    if allow_password_grant:
        grant_types.append("password")
    metadata = {
        "issuer": base,
        "authorization_endpoint": f"{base}{o2}/authorize",
        "token_endpoint": f"{base}{o2}/token",
        "revocation_endpoint": f"{base}{o2}/revoke",
        "introspection_endpoint": f"{base}{o2}/introspect",
        "jwks_uri": f"{base}{o2}/jwks.json",
        "device_authorization_endpoint": f"{base}{o2}/device_authorization",
        "pushed_authorization_request_endpoint": f"{base}{o2}/par",
        "registration_endpoint": f"{base}{ap}/register",
        # OpenID CIBA Core 1.0 backchannel authentication endpoint.
        "backchannel_authentication_endpoint": f"{base}{o2}/bc-authorize",
        "backchannel_token_delivery_modes_supported": ["poll"],
        # RFC 8693 token exchange endpoint.
        "token_exchange_endpoint": f"{base}{o2}/token/exchange",
        # Google-style simplified token validation.
        "token_info_endpoint": f"{base}{o2}/tokeninfo",
        "response_types_supported": _authorization_endpoint_response_types(oauth21_compliant),
        "grant_types_supported": grant_types,
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "none",
        ],
        "scopes_supported": scopes_supported or ["openid", "profile", "email"],
        "code_challenge_methods_supported": ["S256"],
    }
    if fapi20_compliant:
        metadata["fapi_security_profile"] = "fapi-2.0"
        if fapi20_require_par:
            metadata["require_pushed_authorization_requests"] = True
        if fapi20_require_jar:
            metadata["require_jwt_secured_authorization_request"] = True
        if fapi20_require_dpop_or_mtls:
            metadata["require_dpop_or_mtls"] = True
            metadata["dpop_signing_alg_values_supported"] = ["ES256", "RS256"]
            metadata["tls_client_certificate_bound_access_tokens"] = True
    return metadata


def openid_configuration(
    issuer: str,
    oauth2_prefix: str | None = None,
    oidc_prefix: str | None = None,
    auth_prefix: str | None = None,
    allow_password_grant: bool = True,
    scopes_supported: list[str] | None = None,
    fapi20_compliant: bool = False,
    fapi20_require_par: bool = False,
    fapi20_require_jar: bool = False,
    fapi20_require_dpop_or_mtls: bool = False,
    oauth21_compliant: bool = False,
    id_token_signing_alg_values_supported: list[str] | None = None,
) -> dict[str, Any]:
    """
    Build OIDC discovery (/.well-known/openid-configuration).
    Includes RFC 9126 ``pushed_authorization_request_endpoint`` (same URL as RFC 8414 AS metadata).
    FAPI 2.0 OIDC registry fields mirror ``oauth_authorization_server_metadata`` when enabled.
    Args:
        issuer: AS base URL.
        oauth2_prefix: OAuth 2.0 core prefix (default from api_paths.OAUTH2_PREFIX).
        oidc_prefix: OIDC prefix for userinfo (default from api_paths.OIDC_PREFIX).
        oauth21_compliant: When True, omit hybrid response types that return access_token on redirect.
        id_token_signing_alg_values_supported: Override for ID Token JWS algs; default RS256+HS256.
    Returns:
        JSON-serializable discovery dict.
    """
    base = issuer.rstrip("/")
    o2 = (oauth2_prefix or OAUTH2_PREFIX).rstrip("/") or OAUTH2_PREFIX
    oidc = (oidc_prefix or OIDC_PREFIX).rstrip("/") or OIDC_PREFIX
    ap = (auth_prefix or AUTH_PREFIX).rstrip("/") or AUTH_PREFIX
    grant_types = [
        "authorization_code",
        "refresh_token",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code",
    ]
    if allow_password_grant:
        grant_types.append("password")
    signing_algs = id_token_signing_alg_values_supported or ["RS256", "HS256"]
    doc: dict[str, Any] = {
        "issuer": base,
        "authorization_endpoint": f"{base}{o2}/authorize",
        "token_endpoint": f"{base}{o2}/token",
        "userinfo_endpoint": f"{base}{oidc}/userinfo",
        "jwks_uri": f"{base}{o2}/jwks.json",
        "revocation_endpoint": f"{base}{o2}/revoke",
        "introspection_endpoint": f"{base}{o2}/introspect",
        "device_authorization_endpoint": f"{base}{o2}/device_authorization",
        "pushed_authorization_request_endpoint": f"{base}{o2}/par",
        # RFC 7591 — Dynamic Client Registration
        "registration_endpoint": f"{base}{ap}/register",
        "end_session_endpoint": f"{base}{oidc}/logout",
        # OIDC Session Management 1.0
        "check_session_iframe": f"{base}{oidc}/check_session_iframe",
        # OpenID CIBA Core 1.0
        "backchannel_authentication_endpoint": f"{base}{o2}/bc-authorize",
        "backchannel_token_delivery_modes_supported": ["poll"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "none",
        ],
        "frontchannel_logout_supported": True,
        "frontchannel_logout_session_supported": True,
        "backchannel_logout_supported": True,
        "backchannel_logout_session_supported": True,
        "response_types_supported": _authorization_endpoint_response_types(oauth21_compliant),
        "response_modes_supported": ["query", "fragment", "form_post"],
        "grant_types_supported": grant_types,
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": signing_algs,
        "scopes_supported": scopes_supported or ["openid", "profile", "email"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce"],
        "code_challenge_methods_supported": ["S256"],
    }
    if fapi20_compliant:
        doc["fapi_security_profile"] = "fapi-2.0"
        if fapi20_require_par:
            doc["require_pushed_authorization_requests"] = True
        if fapi20_require_jar:
            doc["require_jwt_secured_authorization_request"] = True
        if fapi20_require_dpop_or_mtls:
            doc["require_dpop_or_mtls"] = True
            doc["dpop_signing_alg_values_supported"] = ["ES256", "RS256"]
            doc["tls_client_certificate_bound_access_tokens"] = True
    return doc


def oauth_protected_resource_metadata(
    resource: str,
    authorization_servers: list[str],
    issuer: str | None = None,
    oauth2_prefix: str | None = None,
    scopes_supported: list[str] | None = None,
    bearer_methods_supported: list[str] | None = None,
) -> dict[str, Any]:
    """
    Build RFC 9728 Protected Resource Metadata (/.well-known/oauth-protected-resource).
    """
    metadata = {
        "resource": resource,
        "authorization_servers": authorization_servers,
    }
    if bearer_methods_supported is None:
        bearer_methods_supported = ["header"]
    metadata["bearer_methods_supported"] = bearer_methods_supported
    if scopes_supported:
        metadata["scopes_supported"] = scopes_supported
    else:
        metadata["scopes_supported"] = ["openid", "profile", "email"]
    if issuer:
        base = issuer.rstrip("/")
        o2 = (oauth2_prefix or OAUTH2_PREFIX).rstrip("/") or OAUTH2_PREFIX
        metadata["jwks_uri"] = f"{base}{o2}/jwks"
    return metadata
