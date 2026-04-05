# exonware/xwlogin/authentication/mfa_webauthn_audit.py
"""Structured audit hooks for MFA and WebAuthn (parity with enterprise IdP factor event logs)."""

from __future__ import annotations

from typing import Any


async def audit_mfa_event(
    auth: Any,
    event_type: str,
    *,
    user_id: str | None = None,
    attributes: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> None:
    mgr = getattr(auth, "_audit_manager", None)
    if mgr is None or not hasattr(mgr, "log_event"):
        return
    await mgr.log_event(
        event_type,
        user_id=user_id,
        resource="mfa",
        attributes=dict(attributes or {}),
        context=dict(context or {}),
    )


async def audit_webauthn_event(
    auth: Any,
    event_type: str,
    *,
    user_id: str | None = None,
    attributes: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> None:
    mgr = getattr(auth, "_audit_manager", None)
    if mgr is None or not hasattr(mgr, "log_event"):
        return
    await mgr.log_event(
        event_type,
        user_id=user_id,
        resource="webauthn",
        attributes=dict(attributes or {}),
        context=dict(context or {}),
    )
