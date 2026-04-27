#!/usr/bin/env python3
"""
Validate federated OIDC id_tokens (signature, iss, aud, exp, optional iat, nonce, azp) using JWKS.

Implements checks aligned with OpenID Connect Core 1.0 — comparable to what
production brokers (e.g. open-source IdP clients) perform before trusting claims.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWK

from exonware.xwsystem import get_logger

from exonware.xwauth.identity.federation.errors import FederationUpstreamCode, XWFederationError
from .idp_quirks import normalize_oidc_issuer_url

logger = get_logger(__name__)

# Algorithms commonly used by Entra ID, Okta, Auth0, Google.
_DEFAULT_ALGORITHMS: tuple[str, ...] = (
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "HS256",  # uncommon for id_token; allowed for tests / legacy stacks
)


@dataclass(slots=True)
class OidcIdTokenValidationParams:
    """Parameters for strict id_token validation."""

    issuer: str
    # PyJWT accepts a single string or an iterable (multi-aud tokens, e.g. Google).
    audience: str | Sequence[str]
    jwks_uri: str | None = None
    jwks: dict[str, Any] | None = None
    clock_skew_seconds: int = 120
    algorithms: tuple[str, ...] = _DEFAULT_ALGORITHMS
    # e.g. Azure AD: token *iss* is tenant-specific while discovery used */common/*
    additional_allowed_issuers: tuple[str, ...] = ()
    # After a verify failure, invalidate cached JWKS and fetch once more (key rotation).
    jwks_refetch_on_verify_failure: bool = True
    # Max JWKs to try per JWKS document (signature verify); caps CPU on huge JWKS.
    max_jwks_verify_attempts: int = 24
    # OIDC Core: reject tokens without *iat* when True (stricter, closer to Auth0/Okta defaults).
    require_iat: bool = False
    # When *aud* contains multiple parties, OIDC requires *azp*; set to your OAuth client_id.
    expected_azp: str | None = None


async def fetch_openid_configuration(issuer: str, http_get: Any) -> dict[str, Any]:
    """
    Fetch OIDC discovery document. *issuer* should match IdP issuer string (no stray slash).
    *http_get* is async (url) -> response with .status_code and .json().
    """
    base = normalize_oidc_issuer_url(issuer)
    url = f"{base}/.well-known/openid-configuration"
    resp = await http_get(url)
    if resp.status_code != 200:
        raise XWFederationError(
            f"OpenID discovery failed: HTTP {resp.status_code}",
            upstream_code=FederationUpstreamCode.MISCONFIGURED_IDP,
            oauth_error="invalid_request",
            safe_description="Could not load OpenID Connect configuration for this provider.",
        )
    return resp.json()


async def fetch_jwks(jwks_uri: str, http_get: Any) -> dict[str, Any]:
    resp = await http_get(jwks_uri)
    if resp.status_code != 200:
        raise XWFederationError(
            f"JWKS fetch failed: HTTP {resp.status_code}",
            upstream_code=FederationUpstreamCode.MISCONFIGURED_IDP,
        )
    data = resp.json()
    if not isinstance(data, dict) or "keys" not in data:
        raise XWFederationError(
            "Invalid JWKS document",
            upstream_code=FederationUpstreamCode.MISCONFIGURED_IDP,
        )
    return data


def _jwk_candidates(
    keys: list[Any],
    kid: str | None,
    *,
    max_attempts: int,
) -> list[dict[str, Any]]:
    """Order: matching *kid* first, then remaining keys (handles wrong *kid* / key overlap)."""
    key_dicts = [k for k in keys if isinstance(k, dict)]
    if not key_dicts:
        raise XWFederationError(
            "JWKS contains no keys",
            upstream_code=FederationUpstreamCode.MISCONFIGURED_IDP,
        )
    cap = max(1, int(max_attempts or 1))
    ordered: list[dict[str, Any]] = []
    seen: set[int] = set()

    def _push(d: dict[str, Any]) -> None:
        i = id(d)
        if i in seen or len(ordered) >= cap:
            return
        seen.add(i)
        ordered.append(d)

    ks = kid if isinstance(kid, str) and kid.strip() else None
    if ks:
        for d in key_dicts:
            if d.get("kid") == ks:
                _push(d)
        for d in key_dicts:
            if d.get("kid") != ks:
                _push(d)
    else:
        for d in key_dicts:
            _push(d)
    return ordered


def _issuer_for_decode(params: OidcIdTokenValidationParams) -> str | list[str]:
    extra = tuple(params.additional_allowed_issuers or ())
    if not extra:
        return params.issuer
    return [params.issuer, *list(extra)]


def _decode_id_token_with_jwks_doc(
    id_token: str,
    jwks_doc: dict[str, Any],
    params: OidcIdTokenValidationParams,
) -> dict[str, Any]:
    """Verify signature and time/iss/aud claims; raises :exc:`jwt.PyJWTError` on failure."""
    keys = jwks_doc.get("keys")
    if not isinstance(keys, list):
        raise XWFederationError(
            "Malformed JWKS",
            upstream_code=FederationUpstreamCode.MISCONFIGURED_IDP,
        )

    try:
        header = jwt.get_unverified_header(id_token)
    except Exception as exc:
        raise XWFederationError(
            "Malformed id_token",
            upstream_code=FederationUpstreamCode.TOKEN_VALIDATION_FAILED,
        ) from exc

    kid = header.get("kid")
    kid_s = kid if isinstance(kid, str) else None
    candidates = _jwk_candidates(
        keys,
        kid_s,
        max_attempts=params.max_jwks_verify_attempts,
    )

    leeway = max(0, int(params.clock_skew_seconds or 0))
    require_claims = ["exp", "sub"]
    if params.require_iat:
        require_claims.append("iat")

    decode_kw: dict[str, Any] = {
        "algorithms": list(params.algorithms),
        "audience": params.audience,
        "issuer": _issuer_for_decode(params),
        "leeway": leeway,
        "options": {
            "require": require_claims,
            "verify_aud": True,
            "verify_iss": True,
        },
    }

    last_jwt: jwt.PyJWTError | None = None
    last_jwk_build: Exception | None = None
    for jwk_dict in candidates:
        try:
            jwk = PyJWK.from_dict(jwk_dict)
        except Exception as exc:
            last_jwk_build = exc
            continue
        try:
            payload = jwt.decode(id_token, jwk.key, **decode_kw)
            return dict(payload)
        except jwt.PyJWTError as exc:
            last_jwt = exc
            continue

    if last_jwt is not None:
        raise last_jwt
    if last_jwk_build is not None:
        raise XWFederationError(
            "Unsupported JWK in JWKS",
            upstream_code=FederationUpstreamCode.TOKEN_VALIDATION_FAILED,
        ) from last_jwk_build
    raise XWFederationError(
        "No usable JWK in JWKS",
        upstream_code=FederationUpstreamCode.MISCONFIGURED_IDP,
    )


async def _load_jwks_document(
    params: OidcIdTokenValidationParams,
    *,
    http_get: Any | None,
    jwks_document_cache: Any | None,
    force_refresh: bool,
) -> dict[str, Any]:
    if params.jwks is not None:
        return params.jwks
    if not params.jwks_uri or http_get is None:
        raise XWFederationError(
            "JWKS URI or inline JWKS required for id_token validation",
            upstream_code=FederationUpstreamCode.MISCONFIGURED_IDP,
        )
    if force_refresh and jwks_document_cache is not None:
        await jwks_document_cache.invalidate(params.jwks_uri)
    if jwks_document_cache is not None:
        return await jwks_document_cache.get_or_fetch(
            params.jwks_uri, http_get, fetch_jwks
        )
    return await fetch_jwks(params.jwks_uri, http_get)


async def validate_federated_id_token(
    id_token: str,
    params: OidcIdTokenValidationParams,
    *,
    expected_nonce: str | None,
    http_get: Any | None = None,
    jwks_document_cache: Any | None = None,
) -> dict[str, Any]:
    """
    Validate id_token signature and standard claims. When *expected_nonce* is set,
    require a matching *nonce* claim.

    *http_get* is required if *jwks* is not provided and *jwks_uri* is set.
    Optional *jwks_document_cache* is a :class:`~.jwks_cache.JwksDocumentCache` instance
    used to avoid refetching the same JWKS URI on every callback.

    When JWKS is loaded from *jwks_uri* and verification fails (often right after IdP key rotation),
    the cache entry is invalidated and JWKS is fetched once more when
    *jwks_refetch_on_verify_failure* is true on *params*.
    """
    remote_jwks = params.jwks is None and bool(params.jwks_uri) and http_get is not None
    refetch_ok = (
        remote_jwks
        and params.jwks_refetch_on_verify_failure
        and (jwks_document_cache is not None or http_get is not None)
    )
    max_rounds = 2 if refetch_ok else 1

    payload: dict[str, Any] | None = None

    for round_idx in range(max_rounds):
        force_refresh = round_idx > 0
        try:
            jwks_doc = await _load_jwks_document(
                params,
                http_get=http_get,
                jwks_document_cache=jwks_document_cache,
                force_refresh=force_refresh,
            )
            payload = _decode_id_token_with_jwks_doc(id_token, jwks_doc, params)
        except XWFederationError:
            raise
        except jwt.PyJWTError as exc:
            logger.debug("id_token validation failed", exc_info=True)
            if round_idx + 1 >= max_rounds:
                raise XWFederationError(
                    "id_token signature or claims validation failed",
                    upstream_code=FederationUpstreamCode.TOKEN_VALIDATION_FAILED,
                    oauth_error="invalid_grant",
                ) from exc
            continue
        else:
            break

    assert payload is not None

    if expected_nonce is not None:
        if payload.get("nonce") != expected_nonce:
            raise XWFederationError(
                "OpenID Connect nonce mismatch",
                upstream_code=FederationUpstreamCode.INVALID_NONCE,
            )

    if params.expected_azp is not None:
        if payload.get("azp") != params.expected_azp:
            raise XWFederationError(
                "OpenID Connect azp mismatch",
                upstream_code=FederationUpstreamCode.TOKEN_VALIDATION_FAILED,
                oauth_error="invalid_grant",
            )

    return payload


def decode_id_token_unverified(id_token: str) -> dict[str, Any]:
    """Parse id_token without verification (nonce-only / debugging)."""
    try:
        return jwt.decode(
            id_token,
            options={
                "verify_signature": False,
                "verify_aud": False,
                "verify_exp": False,
            },
        )
    except Exception as exc:
        raise XWFederationError(
            "Invalid id_token",
            upstream_code=FederationUpstreamCode.TOKEN_VALIDATION_FAILED,
        ) from exc
