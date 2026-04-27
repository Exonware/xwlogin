#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/admin_api_openapi_parity.py
Checklist for **admin console ↔ HTTP API** parity and **OpenAPI** fidelity (REF_25 #7).

Targets ``xwauth-api`` (and any future admin surface); does not enumerate routes here.
"""

from __future__ import annotations

from typing import Any

ADMIN_API_OPENAPI_PARITY_SCHEMA_VERSION = 1


def admin_api_openapi_parity_checklist() -> dict[str, Any]:
    """Expectations so every UI action is automatable and documented."""
    return {
        "schema_version": ADMIN_API_OPENAPI_PARITY_SCHEMA_VERSION,
        "kind": "admin_api_openapi_parity",
        "sections": [
            {
                "id": "inventory",
                "title": "Inventory console actions",
                "items": [
                    "List every **admin / tenant UI** action (create client, rotate key, invite user, SCIM toggle, etc.).",
                    "Map each action to exactly one **HTTP method + path** (no UI-only side channels).",
                ],
            },
            {
                "id": "api_coverage",
                "title": "REST coverage",
                "items": [
                    "CRUD and lifecycle verbs return **consistent** status codes and error envelopes (align with XWAPI patterns).",
                    "Long-running jobs expose **status** or async task ids where applicable.",
                ],
            },
            {
                "id": "openapi_fidelity",
                "title": "OpenAPI fidelity",
                "items": [
                    "Ship a single **OpenAPI 3** document that includes all admin routes; forbid undocumented private JSON.",
                    "Schemas use **discriminated** request/response bodies where polymorphism exists.",
                    "Publish OpenAPI in CI artifacts and diff on PR for **breaking** changes.",
                ],
            },
            {
                "id": "authorization",
                "title": "Authorization model",
                "items": [
                    "Document required **scopes/roles** per route; mirror in OpenAPI ``security`` requirements.",
                    "Regression tests prove **deny-by-default** for cross-tenant admin calls.",
                ],
            },
            {
                "id": "parity_gates",
                "title": "Parity gates",
                "items": [
                    "Optional contract test: **UI route manifest** (build-time) ⊆ OpenAPI paths.",
                    "Track **gaps** in issue tracker until parity reaches 100% for GA admin tier.",
                ],
            },
        ],
    }
