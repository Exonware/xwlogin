# exonware/xwauth-identity/tests/1.unit/federation_tests/test_pkce_helpers.py
"""PKCE helper behavior (GUIDE_51)."""

from __future__ import annotations

import base64
import hashlib

import pytest

from exonware.xwauth.identity.federation.pkce import generate_pkce_pair

pytestmark = pytest.mark.xwauth_identity_unit


def test_generate_pkce_pair_s256_round_trip() -> None:
    verifier, challenge = generate_pkce_pair()
    assert 43 <= len(verifier) <= 128
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    assert challenge == expected


def test_generate_pkce_pair_produces_unique_verifiers() -> None:
    v1, _ = generate_pkce_pair()
    v2, _ = generate_pkce_pair()
    assert v1 != v2
