#!/usr/bin/env python3
"""
PKCE (RFC 7636) helpers for public and confidential OIDC clients.
"""

from __future__ import annotations

import base64
import hashlib
import secrets


def generate_pkce_pair(byte_length: int = 32) -> tuple[str, str]:
    """
    Return (code_verifier, code_challenge) using S256.

    Verifier length is within RFC 7636 (43–128 chars after encoding).
    """
    raw = secrets.token_bytes(max(32, min(byte_length, 96)))
    verifier = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge
