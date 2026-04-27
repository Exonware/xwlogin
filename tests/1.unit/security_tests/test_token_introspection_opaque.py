#!/usr/bin/env python3
"""
#exonware/xwauth.identity/tests/1.unit/security_tests/test_token_introspection_opaque.py
Opaque token introspection security (RFC 7662) — GUIDE_51 unit layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from exonware.xwauth.identity.tokens.introspection import TokenIntrospection


class _FakeOpaqueManager:
    def __init__(self, record: dict) -> None:
        self._record = record

    async def get_token(self, token: str) -> dict | None:
        return self._record if token == "opaque-test-token" else None


@pytest.mark.xwauth_identity_unit
@pytest.mark.asyncio
async def test_opaque_introspection_attributes_do_not_override_active_or_sub() -> None:
    """
    Stored ``attributes`` must not spoof ``active`` or ``sub`` over authoritative
    token fields (expiry / user_id from storage).
    """
    # Match introspection.py which compares with naive ``datetime.now()`` for
    # opaque expiry checks (use naive ISO strings for deterministic tests).
    past = (datetime.now() - timedelta(hours=1)).isoformat()
    mgr = _FakeOpaqueManager(
        {
            "expires_at": past,
            "user_id": "real-user",
            "client_id": "client-1",
            "scopes": ["openid"],
            "token_id": "tid-1",
            "attributes": {
                "active": True,
                "sub": "attacker-sub",
                "roles": ["from-attrs"],
            },
        }
    )
    intro = TokenIntrospection(jwt_manager=None, opaque_manager=mgr)
    result = await intro.introspect("opaque-test-token")
    assert result["active"] is False
    assert result["sub"] == "real-user"
    assert result["roles"] == ["from-attrs"]


@pytest.mark.xwauth_identity_unit
@pytest.mark.asyncio
async def test_opaque_introspection_non_spoofing_attributes_still_merge() -> None:
    """Safe extension keys from attributes remain visible to callers."""
    future = (datetime.now() + timedelta(hours=1)).isoformat()
    mgr = _FakeOpaqueManager(
        {
            "expires_at": future,
            "user_id": "u1",
            "client_id": "c1",
            "scopes": ["api"],
            "attributes": {"custom_extension": "ok", "tenant_hint": "t-9"},
        }
    )
    intro = TokenIntrospection(jwt_manager=None, opaque_manager=mgr)
    result = await intro.introspect("opaque-test-token")
    assert result["active"] is True
    assert result["custom_extension"] == "ok"
    assert result["tenant_hint"] == "t-9"
