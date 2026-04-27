# exonware/xwauth.identity/src/exonware/xwauth.identity/security/mfa_secrets.py
"""Envelope encryption for TOTP seeds and related MFA material at rest."""

from __future__ import annotations

import base64
import hashlib

from exonware.xwauth.identity.config.config import XWAuthConfig
from exonware.xwsystem.security.at_rest import get_at_rest_encryption, is_envelope
from exonware.xwsystem.security.errors import CryptographicError


def derive_mfa_encryption_key(jwt_secret: str, *, context: bytes = b"xwauth.mfa.v1") -> bytes:
    """Derive a 32-byte key from jwt_secret (PBKDF2). Not a substitute for a dedicated KMS key."""
    salt = hashlib.sha256(context + jwt_secret.encode("utf-8")).digest()[:16]
    return hashlib.pbkdf2_hmac("sha256", jwt_secret.encode("utf-8"), salt, 100_000, dklen=32)


def _resolve_key(config: XWAuthConfig) -> tuple[bytes, str]:
    algo = getattr(config, "mfa_at_rest_algorithm", "aes256-gcm") or "aes256-gcm"
    raw_b64 = getattr(config, "mfa_at_rest_key_b64", None)
    if raw_b64 and str(raw_b64).strip():
        key = base64.b64decode(raw_b64.strip(), validate=True)
        if len(key) != 32:
            raise CryptographicError("mfa_at_rest_key_b64 must decode to 32 bytes")
        return key, algo
    return derive_mfa_encryption_key(config.jwt_secret), algo


def encrypt_totp_secret(plaintext_secret: str, config: XWAuthConfig) -> str:
    """Return base64-encoded envelope bytes for storage in user attributes."""
    key, algo_id = _resolve_key(config)
    impl = get_at_rest_encryption(algo_id, key=key)
    envelope = impl.encrypt(plaintext_secret.encode("utf-8"))
    return base64.b64encode(envelope).decode("ascii")


def decrypt_totp_secret(stored: str | bytes, config: XWAuthConfig) -> str:
    """Decrypt envelope or pass through legacy plaintext base32."""
    raw = base64.b64decode(stored, validate=True) if isinstance(stored, str) else stored
    if not is_envelope(raw):
        return raw.decode("utf-8") if isinstance(raw, bytes) else str(stored)
    key, algo_id = _resolve_key(config)
    impl = get_at_rest_encryption(algo_id, key=key)
    out = impl.decrypt(raw)
    return out.decode("utf-8")
