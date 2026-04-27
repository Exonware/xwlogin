#!/usr/bin/env python3
"""
#exonware/xwauth-identity/tests/_vendor/jwt.py
Minimal PyJWT-compatible subset for offline test execution.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


class PyJWTError(Exception):
    """Base JWT error."""


class InvalidTokenError(PyJWTError):
    """Raised when token structure/signature/claims are invalid."""


class ExpiredSignatureError(InvalidTokenError):
    """Raised when token is expired."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))


def _json_dumps(data: dict[str, Any]) -> str:
    return json.dumps(data, separators=(",", ":"), sort_keys=True)


def _coerce_key(key: Any) -> bytes:
    if isinstance(key, bytes):
        return key
    if isinstance(key, str):
        return key.encode("utf-8")
    if key is None:
        return b""
    return str(key).encode("utf-8")


def encode(payload: dict[str, Any], key: Any, algorithm: str = "HS256", headers: dict[str, Any] | None = None) -> str:
    if algorithm != "HS256":
        raise InvalidTokenError(f"Unsupported algorithm: {algorithm}")
    token_headers = {"alg": algorithm, "typ": "JWT"}
    if headers:
        token_headers.update(headers)
    header_segment = _b64url_encode(_json_dumps(token_headers).encode("utf-8"))
    payload_segment = _b64url_encode(_json_dumps(payload).encode("utf-8"))
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    signature = hmac.new(_coerce_key(key), signing_input, hashlib.sha256).digest()
    signature_segment = _b64url_encode(signature)
    return f"{header_segment}.{payload_segment}.{signature_segment}"


def get_unverified_header(token: str) -> dict[str, Any]:
    try:
        header_segment = token.split(".", 2)[0]
        return json.loads(_b64url_decode(header_segment).decode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive parser guard
        raise InvalidTokenError("Invalid JWT header") from exc


def decode(
    token: str,
    key: Any | None = None,
    algorithms: list[str] | None = None,
    issuer: str | None = None,
    audience: str | None = None,
    options: dict[str, Any] | None = None,
    **_: Any,
) -> dict[str, Any]:
    opts = options or {}
    verify_signature = opts.get("verify_signature", True)
    verify_exp = opts.get("verify_exp", True)
    allowed_algorithms = algorithms or ["HS256"]
    try:
        header_segment, payload_segment, signature_segment = token.split(".", 2)
    except ValueError as exc:
        raise InvalidTokenError("JWT must have header.payload.signature") from exc
    try:
        header = json.loads(_b64url_decode(header_segment).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_segment).decode("utf-8"))
    except Exception as exc:
        raise InvalidTokenError("JWT contains invalid JSON") from exc
    alg = str(header.get("alg") or "")
    if alg not in allowed_algorithms:
        raise InvalidTokenError("JWT algorithm not allowed")
    if verify_signature:
        if alg != "HS256":
            raise InvalidTokenError(f"Unsupported algorithm: {alg}")
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        expected = hmac.new(_coerce_key(key), signing_input, hashlib.sha256).digest()
        provided = _b64url_decode(signature_segment)
        if not hmac.compare_digest(expected, provided):
            raise InvalidTokenError("Signature verification failed")
    now = int(time.time())
    exp = payload.get("exp")
    if verify_exp and exp is not None and int(exp) < now:
        raise ExpiredSignatureError("Signature has expired")
    if issuer is not None and payload.get("iss") != issuer:
        raise InvalidTokenError("Invalid issuer")
    if audience is not None:
        aud_claim = payload.get("aud")
        if isinstance(aud_claim, list):
            if audience not in aud_claim:
                raise InvalidTokenError("Invalid audience")
        elif aud_claim != audience:
            raise InvalidTokenError("Invalid audience")
    return payload
