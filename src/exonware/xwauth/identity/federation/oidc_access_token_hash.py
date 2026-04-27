#!/usr/bin/env python3
"""
OpenID Connect Core 1.0 access token hash checks (*at_hash*, *c_hash*).

Uses the JWS alg suffix (256 / 384 / 512) to pick SHA-256, SHA-384, or SHA-512 over the token
string (UTF-8), then the left half of that digest, Base64URL-encoded (OIDC Core).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any


def _b64url_decode_segment(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + pad).encode("ascii"))


def _digest_left_half(access_token: str, signing_alg: str | None) -> bytes:
    alg = (signing_alg or "RS256").strip().upper()
    msg = access_token.encode("utf-8")
    if len(alg) >= 3 and alg[-3:] == "512":
        full = hashlib.sha512(msg).digest()
    elif len(alg) >= 3 and alg[-3:] == "384":
        full = hashlib.sha384(msg).digest()
    else:
        full = hashlib.sha256(msg).digest()
    return full[: len(full) // 2]


def compute_at_hash(access_token: str, signing_alg: str | None = None) -> str:
    """Compute *at_hash* for *access_token* using the digest family implied by *signing_alg*."""
    half = _digest_left_half(access_token, signing_alg)
    return base64.urlsafe_b64encode(half).decode("ascii").rstrip("=")


def verify_at_hash(access_token: str, at_hash_claim: Any, signing_alg: str | None) -> bool:
    """Return True if *at_hash_claim* matches the computed hash for *access_token*."""
    if not isinstance(at_hash_claim, str) or not at_hash_claim.strip():
        return False
    expected = compute_at_hash(access_token, signing_alg=signing_alg)
    try:
        a = _b64url_decode_segment(expected)
        b = _b64url_decode_segment(at_hash_claim.strip())
    except Exception:
        return False
    if len(a) != len(b):
        return False
    return secrets.compare_digest(a, b)


def compute_c_hash(authorization_code: str, signing_alg: str | None = None) -> str:
    """*c_hash* uses the same construction as *at_hash* over the authorization code string."""
    return compute_at_hash(authorization_code, signing_alg=signing_alg)


def verify_c_hash(authorization_code: str, c_hash_claim: Any, signing_alg: str | None) -> bool:
    """Return True if *c_hash_claim* matches the computed hash for *authorization_code*."""
    return verify_at_hash(authorization_code, c_hash_claim, signing_alg)
