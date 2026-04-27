# exonware/xwauth-identity/tests/1.unit/federation_tests/test_oidc_access_token_hash.py
"""OIDC *at_hash* / *c_hash* helpers (GUIDE_51)."""

from __future__ import annotations

import pytest

from exonware.xwauth.identity.federation.oidc_access_token_hash import (
    compute_at_hash,
    compute_c_hash,
    verify_at_hash,
    verify_c_hash,
)

pytestmark = pytest.mark.xwauth_identity_unit


def test_compute_at_hash_hs256_stable_for_same_input() -> None:
    token = "access-token-example"
    h1 = compute_at_hash(token, signing_alg="HS256")
    h2 = compute_at_hash(token, signing_alg="HS256")
    assert h1 == h2
    assert len(h1) > 0


def test_compute_at_hash_differs_by_alg_family() -> None:
    token = "same"
    h256 = compute_at_hash(token, signing_alg="RS256")
    h384 = compute_at_hash(token, signing_alg="RS384")
    h512 = compute_at_hash(token, signing_alg="RS512")
    assert len({h256, h384, h512}) == 3


def test_verify_at_hash_accepts_matching_claim() -> None:
    token = "opaque-access"
    alg = "HS256"
    claim = compute_at_hash(token, signing_alg=alg)
    assert verify_at_hash(token, claim, signing_alg=alg) is True


def test_verify_at_hash_rejects_wrong_token() -> None:
    alg = "HS256"
    claim = compute_at_hash("a", signing_alg=alg)
    assert verify_at_hash("b", claim, signing_alg=alg) is False


def test_verify_at_hash_rejects_empty_claim() -> None:
    assert verify_at_hash("token", "", signing_alg="HS256") is False
    assert verify_at_hash("token", None, signing_alg="HS256") is False


def test_c_hash_matches_at_hash_on_code_string() -> None:
    code = "auth-code-value"
    alg = "HS256"
    assert compute_c_hash(code, signing_alg=alg) == compute_at_hash(code, signing_alg=alg)
    claim = compute_c_hash(code, signing_alg=alg)
    assert verify_c_hash(code, claim, signing_alg=alg) is True
