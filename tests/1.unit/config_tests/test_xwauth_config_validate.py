# exonware/xwauth-identity/tests/1.unit/config_tests/test_xwauth_config_validate.py
"""Unit tests for :class:`XWAuthConfig` validation (GUIDE_51)."""

from __future__ import annotations

import pytest

from exonware.xwauth.identity.config.config import XWAuthConfig
from exonware.xwauth.identity.errors import XWConfigError

pytestmark = pytest.mark.xwauth_identity_unit


def test_validate_minimal_config_passes() -> None:
    cfg = XWAuthConfig(
        jwt_secret="unit-test-secret-nonempty",
        storage_provider=None,
        registered_clients=[],
        allow_mock_storage_fallback=True,
    )
    cfg.validate()


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"jwt_secret": ""}, "jwt_secret"),
        ({"jwt_secret": "   "}, "jwt_secret"),
        ({"access_token_lifetime": 0}, "access_token_lifetime"),
        ({"refresh_token_lifetime": -1}, "refresh_token_lifetime"),
        ({"par_request_lifetime": 5}, "par_request_lifetime"),
        ({"par_request_lifetime": 601}, "par_request_lifetime"),
        ({"session_timeout": 0}, "session_timeout"),
        ({"rate_limit_requests_per_minute": 0}, "rate_limit_requests_per_minute"),
        ({"rate_limit_requests_per_hour": 0}, "rate_limit_requests_per_hour"),
        ({"max_concurrent_sessions": 0}, "max_concurrent_sessions"),
        ({"protocol_profile": "Z"}, "protocol_profile"),
        ({"default_scopes": []}, "default_scopes"),
        ({"default_scopes": ["openid", ""]}, "default_scopes"),
    ],
)
def test_validate_rejects_invalid_fields(kwargs: dict, match: str) -> None:
    base = {
        "jwt_secret": "unit-test-secret-nonempty",
        "registered_clients": [],
    }
    base.update(kwargs)
    cfg = XWAuthConfig(**base, allow_mock_storage_fallback=True)
    with pytest.raises(XWConfigError, match=match):
        cfg.validate()


def test_get_protocol_profile_requirements_unknown_falls_back_to_a() -> None:
    cfg = XWAuthConfig(
        jwt_secret="s",
        registered_clients=[],
        protocol_profile="unknown",
    )
    req = cfg.get_protocol_profile_requirements()
    assert "required_flags" in req
    assert "oauth21_compliant" in req["required_flags"]


def test_get_effective_token_lifetime_fapi_cap() -> None:
    cfg = XWAuthConfig(
        jwt_secret="s",
        registered_clients=[],
        fapi20_compliant=True,
        access_token_lifetime=7200,
        fapi20_max_token_lifetime=3600,
        allow_mock_storage_fallback=True,
    )
    assert cfg.get_effective_token_lifetime() == 3600


def test_from_dict_round_trip_core_fields() -> None:
    data = {
        "jwt_secret": "from-dict-secret",
        "access_token_lifetime": 120,
        "registered_clients": [{"client_id": "c1", "redirect_uris": ["https://a/cb"]}],
        "unknown_future_key": 123,
    }
    cfg = XWAuthConfig.from_dict(data)
    assert cfg.jwt_secret == "from-dict-secret"
    assert cfg.access_token_lifetime == 120
    assert cfg.extra_config.get("unknown_future_key") == 123
    cfg.validate()
