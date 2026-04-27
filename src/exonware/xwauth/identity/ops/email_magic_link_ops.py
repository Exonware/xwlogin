#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/email_magic_link_ops.py
Structured operational checklist for **transactional auth email** (magic links, email OTP).

Use for onboarding docs, internal gates, or JSON export — not a mailer.
REF_25 #16.
"""

from __future__ import annotations

from typing import Any

EMAIL_MAGIC_LINK_OPS_SCHEMA_VERSION = 1

# Suggested bounds for single-use link/token TTL (seconds); integrators choose policy.
_MAGIC_LINK_TTL_MIN = 60
_MAGIC_LINK_TTL_MAX = 86_400


def recommended_magic_link_ttl_seconds_bounds() -> tuple[int, int]:
    """Return ``(min_s, max_s)`` for **guidance** only (not enforced here)."""
    return (_MAGIC_LINK_TTL_MIN, _MAGIC_LINK_TTL_MAX)


def magic_link_email_ops_checklist() -> dict[str, Any]:
    """
    JSON-serializable checklist sections for SPF/DKIM/DMARC, sending, and link hygiene.

    Keys are stable for tests and tooling; wording may evolve without breaking *structure*
    if ``schema_version`` is bumped when shape changes.
    """
    lo, hi = recommended_magic_link_ttl_seconds_bounds()
    return {
        "schema_version": EMAIL_MAGIC_LINK_OPS_SCHEMA_VERSION,
        "kind": "magic_link_email_ops",
        "recommended_magic_link_ttl_bounds_seconds": {"min": lo, "max": hi},
        "sections": [
            {
                "id": "dns_authentication",
                "title": "DNS authentication (SPF, DKIM, DMARC)",
                "items": [
                    "Publish SPF that authorizes your ESP or outbound MTA IPs/hostnames; avoid ``all`` mechanisms that negate enforcement.",
                    "Sign mail with DKIM aligned to the From domain (selector + key rotation runbook).",
                    "Publish a DMARC policy (start at p=none for monitoring, move to quarantine/reject when confident).",
                    "Use a dedicated subdomain (e.g. auth.example.com) for transactional mail when possible.",
                ],
            },
            {
                "id": "sending_infrastructure",
                "title": "Sending infrastructure and reputation",
                "items": [
                    "Use a transactional provider or MTA with bounce/webhook APIs; do not send bulk marketing from the same domain without warm-up.",
                    "Configure reverse DNS (PTR) consistent with EHLO/hostname for dedicated IPs.",
                    "Process bounces and complaints; suppress hard bounces and repeated soft bounces.",
                    "Monitor blocklists and provider dashboards; alert on sudden deferral spikes.",
                ],
            },
            {
                "id": "magic_link_security",
                "title": "Magic link and token hygiene",
                "items": [
                    f"Keep magic-link TTL within a deliberate window (guidance: {lo}–{hi} seconds unless UX requires otherwise).",
                    "Tokens must be single-use or rotation-safe; invalidate after first successful consume.",
                    "Use HTTPS links only; avoid open redirects in the redirect chain.",
                    "Do not log full magic-link URLs or raw tokens; log opaque correlation IDs only.",
                    "Rate-limit send and verify endpoints to reduce enumeration and abuse.",
                ],
            },
            {
                "id": "content_and_ux",
                "title": "Content, deliverability, and UX",
                "items": [
                    "Plain-text + HTML multipart; readable copy even if remote assets block.",
                    "Clear From/Reply-To; avoid spam trigger patterns in subject (test with seed inboxes).",
                    "Include short explanation of why the user received the message (context reduces phishing reports).",
                    "Support localization and accessible templates (contrast, language attribute).",
                ],
            },
        ],
    }
