# exonware/xwauth/tests/1.unit/security_tests/test_mfa_passkeys_security.py
"""MFA/WebAuthn security primitives: challenge store, TOTP envelope, policy helpers."""

from __future__ import annotations

import pytest

from exonware.xwlogin.authentication.challenge_store import WebAuthnChallengeStore
from exonware.xwlogin.authentication.attestation_trust import build_pem_root_certs_bytes_by_fmt
from exonware.xwlogin.auth_connector import XWInvalidRequestError
from exonware.xwlogin.handlers.connector_http import (
    attestation_for_profile,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_backup_codes,
    hash_backup_code,
    merge_amr_claims,
    require_backup_codes,
    verify_backup_code,
)
from exonware.xwlogin.test_support import MockUser, XWAuth, XWAuthConfig, XWConfigError, create_webauthn_credential_index_redis

pytestmark = pytest.mark.xwlogin_unit


def test_challenge_store_consume_single_use() -> None:
    store = WebAuthnChallengeStore(default_ttl_seconds=60.0)
    h = store.issue(challenge_b64url="abc", purpose="registration", user_id="u1", ttl_seconds=60.0)
    got = store.consume(h, purpose="registration", user_id="u1")
    assert got == "abc"
    with pytest.raises(ValueError):
        store.consume(h, purpose="registration", user_id="u1")


def test_challenge_lookup_reuse_until_invalidate() -> None:
    store = WebAuthnChallengeStore(default_ttl_seconds=60.0)
    h = store.issue(challenge_b64url="xyz", purpose="authentication", user_id="u1", ttl_seconds=60.0)
    assert store.lookup(h, purpose="authentication", user_id="u1") == "xyz"
    assert store.lookup(h, purpose="authentication", user_id="u1") == "xyz"
    store.invalidate(h)
    with pytest.raises(ValueError):
        store.lookup(h, purpose="authentication", user_id="u1")


def test_challenge_store_user_mismatch() -> None:
    store = WebAuthnChallengeStore(default_ttl_seconds=60.0)
    h = store.issue(challenge_b64url="x", purpose="authentication", user_id="u1", ttl_seconds=60.0)
    with pytest.raises(ValueError, match="challenge_user_mismatch"):
        store.consume(h, purpose="authentication", user_id="u2")


def test_totp_encrypt_round_trip() -> None:
    cfg = XWAuthConfig(jwt_secret="unit-test-secret-for-mfa-encryption-key-derivation")
    secret = "JBSWY3DPEHPK3PXP"
    enc = encrypt_totp_secret(secret, cfg)
    assert enc != secret
    plain = decrypt_totp_secret(enc, cfg)
    assert plain == secret


def test_backup_codes_verify_once() -> None:
    codes = generate_backup_codes(3)
    hashes = [hash_backup_code(c) for c in codes]
    matched = verify_backup_code(codes[0], hashes)
    assert matched is not None
    remaining = [h for h in hashes if h != matched]
    assert verify_backup_code(codes[0], remaining) is None


def test_profile_attestation_and_backup_requirement() -> None:
    assert attestation_for_profile("A") == "none"
    assert attestation_for_profile("B") == "indirect"
    assert attestation_for_profile("C") == "direct"
    assert require_backup_codes("A") is False
    assert require_backup_codes("B") is True


def test_merge_amr_claims_order() -> None:
    assert merge_amr_claims(["pwd"], "totp") == ["pwd", "totp"]
    assert merge_amr_claims(["pwd", "totp"], "totp") == ["pwd", "totp"]


def test_attestation_pem_map_empty_and_nonempty() -> None:
    assert build_pem_root_certs_bytes_by_fmt([]) is None
    assert build_pem_root_certs_bytes_by_fmt(["", "  "]) is None
    pytest.importorskip("webauthn")
    pem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
    m = build_pem_root_certs_bytes_by_fmt([pem])
    assert m is not None
    from webauthn.helpers.structs import AttestationFormat

    assert AttestationFormat.NONE not in m
    assert AttestationFormat.PACKED in m
    assert m[AttestationFormat.PACKED][0].startswith(b"-----")


def test_config_webauthn_resident_key_validates() -> None:
    XWAuthConfig(jwt_secret="s", webauthn_resident_key="required").validate()
    with pytest.raises(XWConfigError, match="webauthn_resident_key"):
        XWAuthConfig(jwt_secret="s", webauthn_resident_key="invalid").validate()


@pytest.mark.asyncio
async def test_resolve_user_for_webauthn_credential_scan_and_cache(auth) -> None:
    from exonware.xwlogin.authentication.webauthn_credential_index import (
        register_webauthn_credential_mapping,
        resolve_user_for_webauthn_credential,
    )

    cid = "dGVzdC1jcmVkLWlkLXRvLW1hdGNoLWxlbmd0aA"
    u = MockUser(
        id="u_disc",
        email="d@e.f",
        attributes={"webauthn_credentials": [{"credential_id": cid}]},
    )
    await auth.storage.save_user(u)
    assert await resolve_user_for_webauthn_credential(auth, cid) == "u_disc"
    assert await resolve_user_for_webauthn_credential(auth, cid) == "u_disc"
    register_webauthn_credential_mapping(auth, "othercred", "u_disc")
    assert await resolve_user_for_webauthn_credential(auth, "othercred") == "u_disc"


@pytest.mark.asyncio
async def test_rebuild_webauthn_credential_index(auth) -> None:
    from exonware.xwlogin.authentication.webauthn_credential_index import (
        rebuild_webauthn_credential_index,
        resolve_user_for_webauthn_credential,
        unregister_webauthn_credential_mapping,
    )

    c1 = "Y3JlZDEteHl6LWxlbmd0aC1maXhlZC0xMjM0YWJjZGVm"
    c2 = "Y3JlZDIteHl6LWxlbmd0aC1maXhlZC0xMjM0YWJjZGVm"
    await auth.storage.save_user(
        MockUser(id="ua", email="a@x.t", attributes={"webauthn_credentials": [{"credential_id": c1}]})
    )
    await auth.storage.save_user(
        MockUser(id="ub", email="b@x.t", attributes={"webauthn_credentials": [{"credential_id": c2}]})
    )
    assert await rebuild_webauthn_credential_index(auth) == 2
    assert await resolve_user_for_webauthn_credential(auth, c1) == "ua"
    assert await resolve_user_for_webauthn_credential(auth, c2) == "ub"


def test_config_roundtrip_webauthn_attestation_pem_and_anti_enum() -> None:
    cfg = XWAuthConfig(
        jwt_secret="s",
        webauthn_trusted_attestation_ca_pem=["-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"],
        webauthn_anti_enumeration_login=False,
    )
    d = cfg.to_dict()
    assert d["webauthn_anti_enumeration_login"] is False
    assert len(d["webauthn_trusted_attestation_ca_pem"]) == 1
    cfg2 = XWAuthConfig.from_dict(d)
    assert cfg2.webauthn_anti_enumeration_login is False
    assert cfg2.webauthn_trusted_attestation_ca_pem[0].startswith("-----")


def test_webauthn_manager_requires_challenge_handle() -> None:
    pytest.importorskip("webauthn")
    from exonware.xwlogin.authentication.webauthn import WebAuthnManager

    auth = XWAuth(config=XWAuthConfig(jwt_secret="test", webauthn_rp_id="localhost", webauthn_allow_insecure_defaults=True))
    mgr = WebAuthnManager(auth, rp_id="localhost", expected_origins=["http://localhost:8000"])
    import asyncio

    async def _run() -> None:
        with pytest.raises(XWInvalidRequestError, match="webauthn_challenge_handle"):
            await mgr.verify_registration("u1", {}, challenge_handle=None)

    asyncio.run(_run())


def test_config_from_dict_preserves_webauthn_discoverable_resident_and_cred_index() -> None:
    cfg = XWAuthConfig(
        jwt_secret="s",
        webauthn_discoverable_login=False,
        webauthn_resident_key="required",
        webauthn_credential_index_backend="redis",
    )
    cfg.validate()
    cfg2 = XWAuthConfig.from_dict(cfg.to_dict())
    assert cfg2.webauthn_discoverable_login is False
    assert cfg2.webauthn_resident_key == "required"
    assert cfg2.webauthn_credential_index_backend == "redis"


def test_config_credential_index_backend_invalid() -> None:
    with pytest.raises(XWConfigError, match="webauthn_credential_index_backend"):
        XWAuthConfig(jwt_secret="s", webauthn_credential_index_backend="invalid").validate()


def test_create_credential_index_redis_factory() -> None:
    assert create_webauthn_credential_index_redis(XWAuthConfig(jwt_secret="s")) is None
    assert (
        create_webauthn_credential_index_redis(
            XWAuthConfig(
                jwt_secret="s",
                webauthn_credential_index_backend="redis",
                webauthn_redis_url=None,
            )
        )
        is None
    )


class _FakeCredRedis:
    def __init__(self) -> None:
        self.m: dict[str, str] = {}

    def set_mapping(self, cid: str, uid: str) -> None:
        self.m[cid] = uid

    def get_user(self, cid: str) -> str | None:
        return self.m.get(cid)

    def delete_mapping(self, cid: str) -> None:
        self.m.pop(cid, None)

    def replace_all(self, pairs: list[tuple[str, str]]) -> None:
        self.m.clear()
        for c, u in pairs:
            self.m[c] = u


@pytest.mark.asyncio
async def test_redis_backed_index_resolve_after_process_cache_clear(auth) -> None:
    from exonware.xwlogin.authentication import webauthn_credential_index as mod
    from exonware.xwlogin.authentication.webauthn_credential_index import (
        register_webauthn_credential_mapping,
        resolve_user_for_webauthn_credential,
    )

    fake = _FakeCredRedis()
    auth._webauthn_credential_index_redis = fake
    cid = "YmFzZTY0dXJsLWNyZWQtaWQtb25l"
    register_webauthn_credential_mapping(auth, cid, "u_redis")
    assert fake.m[cid] == "u_redis"
    mod._index(auth).clear()
    assert await resolve_user_for_webauthn_credential(auth, cid) == "u_redis"


@pytest.mark.asyncio
async def test_unregister_webauthn_credential_mapping_clears_backends(auth) -> None:
    from exonware.xwlogin.authentication.webauthn_credential_index import (
        register_webauthn_credential_mapping,
        resolve_user_for_webauthn_credential,
        unregister_webauthn_credential_mapping,
    )

    fake = _FakeCredRedis()
    auth._webauthn_credential_index_redis = fake
    register_webauthn_credential_mapping(auth, "delme", "u1")
    assert fake.m.get("delme") == "u1"
    unregister_webauthn_credential_mapping(auth, "delme")
    assert fake.m.get("delme") is None
    assert await resolve_user_for_webauthn_credential(auth, "delme") is None
