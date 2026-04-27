#!/usr/bin/env python3
"""
Resolve signing material for locally-issued OIDC ID Tokens (symmetric or PEM private key).

Production stacks (Hydra, Keycloak, etc.) typically sign id_tokens with asymmetric keys
and publish the public JWK set; this module wires PEM + optional kid to PyJWT.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from exonware.xwauth.identity.errors import XWConfigError


@dataclass(frozen=True, slots=True)
class IdTokenSigningMaterial:
    """Algorithm name for PyJWT, signing key, optional JWS kid."""

    algorithm: str
    key: Any
    kid: str | None


def _kid_from_jwks_active(config: Any) -> str | None:
    for jwk in getattr(config, "jwks_active_keys", None) or []:
        if isinstance(jwk, dict) and jwk.get("kid"):
            return str(jwk["kid"])
    return None


def _jwt_alg_for_private_key(key: Any) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        name = key.curve.name
        if name in ("secp256r1", "prime256v1"):
            return "ES256"
        if name == "secp384r1":
            return "ES384"
        if name == "secp521r1":
            return "ES512"
    raise XWConfigError(
        "Unsupported private key type for OIDC id_token signing; use RSA or EC P-256/P-384/P-521 PEM",
        error_code="invalid_config",
    )


def infer_id_token_signing_algorithms_for_discovery(config: Any) -> list[str]:
    """
    Algorithms the AS will use for ID Token JWS, for ``id_token_signing_alg_values_supported``.

    Mirrors ``resolve_id_token_signing`` without requiring a fully valid operator setup:
    asymmetric PEM wins; otherwise the configured symmetric ``jwt_algorithm``.
    """
    pem = getattr(config, "oidc_id_token_signing_pem", None)
    if pem is not None and str(pem).strip():
        try:
            raw = str(pem).strip().encode("ascii")
            key = serialization.load_pem_private_key(raw, password=None, backend=default_backend())
            return [_jwt_alg_for_private_key(key)]
        except Exception:
            pass
    alg = (getattr(config, "jwt_algorithm", None) or "HS256").strip().upper()
    if alg not in ("HS256", "HS384", "HS512"):
        alg = "HS256"
    return [alg]


def resolve_id_token_signing(config: Any) -> IdTokenSigningMaterial:
    """
    If ``oidc_id_token_signing_pem`` is set, load asymmetric key and derive RS256/ES* from the key.
    Otherwise use ``jwt_secret`` + ``jwt_algorithm`` (typically HS256).
    """
    pem = getattr(config, "oidc_id_token_signing_pem", None)
    if pem is not None and str(pem).strip():
        raw = str(pem).strip().encode("ascii")
        try:
            key = serialization.load_pem_private_key(raw, password=None, backend=default_backend())
        except Exception as exc:
            raise XWConfigError(
                f"Invalid oidc_id_token_signing_pem: {exc}",
                error_code="invalid_config",
            ) from exc
        alg = _jwt_alg_for_private_key(key)
        kid = getattr(config, "oidc_id_token_signing_kid", None)
        if kid is not None and str(kid).strip():
            kid_s = str(kid).strip()
        else:
            kid_s = _kid_from_jwks_active(config)
        if not kid_s:
            raise XWConfigError(
                "oidc_id_token_signing_kid is required when using oidc_id_token_signing_pem "
                "(unless jwks_active_keys includes a matching kid)",
                error_code="invalid_config",
            )
        return IdTokenSigningMaterial(algorithm=alg, key=key, kid=kid_s)

    secret = getattr(config, "jwt_secret", None)
    if not secret:
        raise XWConfigError("jwt_secret is required to sign id_tokens", error_code="invalid_config")
    alg = (getattr(config, "jwt_algorithm", None) or "HS256").strip().upper()
    kid = getattr(config, "oidc_id_token_signing_kid", None)
    if kid is not None and str(kid).strip():
        kid_s = str(kid).strip()
    else:
        kid_s = _kid_from_jwks_active(config)
    return IdTokenSigningMaterial(algorithm=alg, key=str(secret), kid=kid_s)


def sign_id_token_jwt(
    payload: dict[str, Any],
    material: IdTokenSigningMaterial,
) -> str:
    headers: dict[str, str] = {"typ": "JWT"}
    if material.kid:
        headers["kid"] = material.kid
    return jwt.encode(payload, material.key, algorithm=material.algorithm, headers=headers)
