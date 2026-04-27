# exonware/xwauth.identity/tests/1.unit/security_tests/test_critical_regressions.py
"""Security regression coverage for critical auth hardening fixes."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import jwt
import pytest

from exonware.xwauth.identity.config.config import DEFAULT_TEST_CLIENTS, XWAuthConfig
from exonware.xwauth.identity.core.grants.base import ABaseGrant
from exonware.xwauth.identity.defs import GrantType
from exonware.xwauth.identity.errors import XWConfigError, XWUnauthorizedClientError
from exonware.xwauth.identity.facade import XWAuth
from exonware.xwauth.identity.handlers import _common as handlers_common
from exonware.xwauth.identity.storage.mock import MockStorageProvider
from exonware.xwauth.identity.tokens.jwt import JWTTokenManager
from exonware.xwauth.identity.tokens.revocation import TokenRevocation

pytestmark = pytest.mark.xwlogin_unit


class _GrantForSecretValidation(ABaseGrant):
    @property
    def grant_type(self) -> GrantType:
        return GrantType.CLIENT_CREDENTIALS

    async def validate_request(self, request: dict[str, Any]) -> dict[str, Any]:
        return request

    async def process(self, request: dict[str, Any]) -> dict[str, Any]:
        return request


class _AuthStub:
    def __init__(self, client_secret: str) -> None:
        self.config = SimpleNamespace(
            get_registered_client=lambda client_id: {
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uris": ["https://example.test/cb"],
            }
        )
        self.storage = MockStorageProvider()


def test_grant_client_secret_uses_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    from exonware.xwauth.identity.core.grants import base as grant_base_module

    called: dict[str, tuple[str, str]] = {}

    def _fake_compare_digest(a: str, b: str) -> bool:
        called["args"] = (a, b)
        return True

    monkeypatch.setattr(grant_base_module.secrets, "compare_digest", _fake_compare_digest)
    grant = _GrantForSecretValidation(_AuthStub(client_secret="expected-secret"))
    grant._validate_client("client-1", "provided-secret")
    assert called["args"] == ("provided-secret", "expected-secret")


def test_handler_client_auth_uses_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, tuple[str, str]] = {}

    def _fake_compare_digest(a: str, b: str) -> bool:
        called["args"] = (a, b)
        return True

    monkeypatch.setattr(handlers_common.secrets, "compare_digest", _fake_compare_digest)
    request = SimpleNamespace(headers={})
    form = {"client_id": "client-1", "client_secret": "provided-secret"}
    auth = _AuthStub(client_secret="expected-secret")
    err = handlers_common.require_client_auth(request, form, auth)
    assert err is None
    assert called["args"] == ("provided-secret", "expected-secret")


@pytest.mark.asyncio
async def test_jwt_revocation_requires_verified_signature() -> None:
    manager = JWTTokenManager(secret="trusted-signing-secret")
    revocation = TokenRevocation(jwt_manager=manager)

    valid = manager.generate_token(user_id="u1", client_id="c1", scopes=["openid"])
    valid_claims = manager.validate_token(valid)
    valid_jti = str(valid_claims["jti"])

    await revocation.revoke(valid)
    assert manager.is_jti_revoked(valid_jti) is True

    forged = jwt.encode(
        {
            "sub": "u1",
            "client_id": "c1",
            "scope": "openid",
            "iat": 0,
            "exp": 4102444800,
            "jti": "forged-jti",
        },
        "attacker-secret",
        algorithm="HS256",
    )
    await revocation.revoke(forged)
    assert manager.is_jti_revoked("forged-jti") is False


def test_insecure_default_test_clients_blocked_without_explicit_opt_in() -> None:
    insecure_client = dict(DEFAULT_TEST_CLIENTS[0])
    with pytest.raises(XWConfigError, match="DEFAULT_TEST_CLIENTS"):
        XWAuthConfig(jwt_secret="unit-test-secret", registered_clients=[insecure_client]).validate()

    cfg = XWAuthConfig(
        jwt_secret="unit-test-secret",
        registered_clients=[insecure_client],
        allow_insecure_test_clients=True,
    )
    cfg.validate()


def test_xwauth_requires_explicit_mock_storage_opt_in() -> None:
    with pytest.raises(XWConfigError, match="No storage provider configured"):
        XWAuth(config=XWAuthConfig(jwt_secret="unit-test-secret"))

    auth = XWAuth(
        config=XWAuthConfig(
            jwt_secret="unit-test-secret",
            allow_mock_storage_fallback=True,
        )
    )
    assert isinstance(auth.storage, MockStorageProvider)


def test_identity_does_not_require_connect_package() -> None:
    """exonware-xwauth-identity must not depend on exonware-xwauth-connect (optional discovery only)."""
    import os

    import exonware.xwauth.identity as identity_pkg

    identity_pkg._reset_discovery_cache_for_tests()
    try:
        monkey_env = "XWAUTH_IDENTITY_DISABLE_CONNECT_DISCOVERY"
        old = os.environ.get(monkey_env)
        os.environ[monkey_env] = "1"
        assert identity_pkg.discover_connect_package() is None
        assert identity_pkg.connect_is_available() is False
    finally:
        if old is None:
            os.environ.pop(monkey_env, None)
        else:
            os.environ[monkey_env] = old
        identity_pkg._reset_discovery_cache_for_tests()


def test_grant_secret_mismatch_still_rejected() -> None:
    grant = _GrantForSecretValidation(_AuthStub(client_secret="expected-secret"))
    with pytest.raises(XWUnauthorizedClientError, match="Invalid client credentials"):
        grant._validate_client("client-1", "wrong-secret")
