#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/abuse_resistance.py
Abuse-hardening checklist and small **pure** helpers for rate-limit companions (REF_25 #13).

Does not implement storage-backed limiters; use with ``IRateLimiter`` / edge WAF / xwauth-api throttles.
"""

from __future__ import annotations

from typing import Any

ABUSE_RESISTANCE_OPS_SCHEMA_VERSION = 1


def exponential_backoff_delay_ms(
    attempt: int,
    *,
    base_ms: int = 200,
    cap_ms: int = 30_000,
    multiplier: float = 2.0,
) -> int:
    """
    Compute a delay for failed-auth or send-code paths (0-based *attempt*).

    ``attempt=0`` returns ``min(cap_ms, base_ms)``. Raises ``ValueError`` if *attempt* < 0.
    """
    if attempt < 0:
        raise ValueError("attempt must be >= 0")
    if base_ms < 0 or cap_ms < 0:
        raise ValueError("base_ms and cap_ms must be >= 0")
    if multiplier < 1.0:
        raise ValueError("multiplier must be >= 1.0")
    raw = float(base_ms) * (multiplier**attempt)
    return int(min(cap_ms, raw))


def abuse_resistance_checklist() -> dict[str, Any]:
    """JSON-serializable checklist aligned with handler ``rate_limit`` strings in xwauth mixins."""
    return {
        "schema_version": ABUSE_RESISTANCE_OPS_SCHEMA_VERSION,
        "kind": "abuse_resistance",
        "sections": [
            {
                "id": "credential_stuffing",
                "title": "Password and token endpoints",
                "items": [
                    "Apply **per-IP and per-identifier** throttles on login, token, and refresh endpoints.",
                    "Use **exponential backoff** (see ``exponential_backoff_delay_ms``) after repeated failures; cap wall-clock to avoid lockout storms.",
                    "Return **generic** errors for auth failures where policy requires anti-enumeration.",
                ],
            },
            {
                "id": "magic_link_and_otp",
                "title": "Magic link, OTP, and email SMS",
                "items": [
                    "Strict rate limits on **send** endpoints; separate limits for verify.",
                    "Invalidate single-use tokens on success; short TTL (see email ops REF).",
                ],
            },
            {
                "id": "registration_and_clients",
                "title": "Client registration and admin",
                "items": [
                    "Dynamic client registration and admin mutations should use **low** quotas (see mixin ``rate_limit`` defaults).",
                    "Require elevated auth for destructive admin routes.",
                ],
            },
            {
                "id": "edge_and_signals",
                "title": "Edge, bots, and reputation",
                "items": [
                    "Terminate TLS at a reverse proxy or WAF with **bot management** when exposed to the open internet.",
                    "Optional: integrate risk scores (ASN, geo velocity) before issuing tokens — keep hooks outside core library if possible.",
                ],
            },
            {
                "id": "observability",
                "title": "Detection",
                "items": [
                    "Alert on spikes in 401/429 and failed grant types; correlate by route family (xwauth-api ops headers).",
                ],
            },
        ],
    }
