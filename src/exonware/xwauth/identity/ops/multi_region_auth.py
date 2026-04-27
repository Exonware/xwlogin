#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/multi_region_auth.py
Operational checklist for **multi-region** OAuth/OIDC AS operation (REF_25 #18).

Covers JWKS rotation, token validation without sticky sessions, and revocation semantics at a high level.
"""

from __future__ import annotations

from typing import Any

MULTI_REGION_AUTH_OPS_SCHEMA_VERSION = 1


def multi_region_auth_checklist() -> dict[str, Any]:
    """
    JSON-serializable checklist for running AS/API across regions.
    """
    return {
        "schema_version": MULTI_REGION_AUTH_OPS_SCHEMA_VERSION,
        "kind": "multi_region_auth",
        "sections": [
            {
                "id": "issuer_and_discovery",
                "title": "Issuer URL and discovery stability",
                "items": [
                    "Use a **single canonical issuer** (global DNS + health-based routing) or region-specific issuers with explicit client config—never ambiguous duplicates.",
                    "Serve **openid-configuration** and **jwks_uri** consistently; avoid per-region issuer drift unless clients are region-aware.",
                ],
            },
            {
                "id": "jwks_rotation",
                "title": "JWKS and signing keys",
                "items": [
                    "Maintain **active + next** keys in JWKS; rotate with overlap so all regions publish the same key set (shared config store or signed replication).",
                    "Avoid region-only private keys unless clients validate only in that region (advanced); default is **shared signing material** with strict access control.",
                ],
            },
            {
                "id": "token_validation",
                "title": "Resource servers validating access tokens",
                "items": [
                    "Prefer **local JWKS cache** with TTL + backoff; tolerate brief skew after rotation.",
                    "For introspection, use a **region-local** or global introspection endpoint with identical semantics.",
                ],
            },
            {
                "id": "revocation_and_sessions",
                "title": "Revocation, refresh, and server-side sessions",
                "items": [
                    "Store **refresh tokens** and **session** state in a replicated or primary-secondary store with **consistent** invalidation (Redis cluster, global DB, or sticky owner region + async replicate).",
                    "Document **eventual consistency** window: a logout in region A must become visible in region B within your SLA (sync path or short TTL on cached grants).",
                ],
            },
            {
                "id": "redis_and_webauthn",
                "title": "Optional Redis / WebAuthn challenge backends",
                "items": [
                    "If using Redis for WebAuthn challenges or rate limits, use a **cross-region** replication mode or route challenges to the same region as login start.",
                    "Fail closed or retry when challenge store is partitioned.",
                ],
            },
            {
                "id": "testing",
                "title": "Validation",
                "items": [
                    "Chaos-test: rotate signing keys while traffic hits multiple regions.",
                    "Test refresh + revoke from different regions against shared storage.",
                ],
            },
        ],
    }
