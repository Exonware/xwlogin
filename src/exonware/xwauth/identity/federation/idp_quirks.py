#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/federation/idp_quirks.py
Documented normalization and helpers for common enterprise IdP OIDC quirks (REF_25 #9).

These are **pure** utilities; wire them in brokers or admin flows where you build
:class:`~.oidc_id_token.OidcIdTokenValidationParams`.
"""

from __future__ import annotations

# Well-known issuer bases (normalize with :func:`normalize_oidc_issuer_url` before compares).
GOOGLE_OIDC_ISSUER = "https://accounts.google.com"

_ENTRA_HOST = "login.microsoftonline.com"


def normalize_oidc_issuer_url(issuer: str) -> str:
    """
    Normalize issuer / discovery base: strip trailing slashes, trim ASCII whitespace.

    Discovery URLs are built as ``{base}/.well-known/openid-configuration``; a trailing
    slash on *issuer* would produce ``//.well-known`` if concatenated naively.
    """
    return issuer.strip().rstrip("/")


def suggested_entra_multitenant_additional_issuers(
    discovery_issuer: str,
    token_issuer: str,
) -> tuple[str, ...]:
    """
    When discovery used Entra **/common/** or **/organizations/** but the id_token *iss*
    is **tenant-specific**, return ``(token_issuer,)`` so callers can set
    ``OidcIdTokenValidationParams.additional_allowed_issuers``.

    If the configured issuer already matches the token or is not a multi-tenant entrypoint,
    returns an empty tuple.
    """
    d = normalize_oidc_issuer_url(discovery_issuer)
    t = normalize_oidc_issuer_url(token_issuer)
    if t == d:
        return ()
    if _ENTRA_HOST not in d or _ENTRA_HOST not in t:
        return ()
    if "/common/" not in d and "/organizations/" not in d.lower():
        return ()
    # Token must look like a concrete tenant GUID path, not another alias.
    if "/common/" in t or "/organizations/" in t.lower():
        return ()
    return (t,)


def okta_authorization_server_base(issuer: str) -> str:
    """
    Return normalized issuer; Okta **custom AS** paths (``/oauth2/default``) must match
    token *iss* exactly — trailing slash drift is what we fix here.
    """
    return normalize_oidc_issuer_url(issuer)
