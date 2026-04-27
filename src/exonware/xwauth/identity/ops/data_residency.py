#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/data_residency.py
Operational checklist for **data residency** and **regional** deployment boundaries (REF_25 #12).

Policy is organizational/legal; this module captures technical controls operators should align.
"""

from __future__ import annotations

from typing import Any

DATA_RESIDENCY_OPS_SCHEMA_VERSION = 1


def data_residency_checklist() -> dict[str, Any]:
    """
    JSON-serializable checklist: where auth data lives, replication, subprocessors, logging.
    """
    return {
        "schema_version": DATA_RESIDENCY_OPS_SCHEMA_VERSION,
        "kind": "data_residency",
        "sections": [
            {
                "id": "data_inventory",
                "title": "Inventory and classification",
                "items": [
                    "List all **auth state**: users, credentials, MFA seeds, sessions, refresh tokens, audit logs, SCIM objects.",
                    "Tag each store with **region** (e.g. EU-West) and **legal jurisdiction**; note cross-border replication.",
                    "Document which fields are **PII** vs opaque identifiers for DPIA / ROPA tables.",
                ],
            },
            {
                "id": "storage_and_backups",
                "title": "Storage, backups, and DR",
                "items": [
                    "Ensure **xwstorage.connect** (or DB) primary and replicas stay in allowed regions; restrict backup copy targets.",
                    "Encrypt at rest per policy; separate keys per region if required.",
                    "Disaster recovery runbooks must not restore EU data into non-EU clusters without legal review.",
                ],
            },
            {
                "id": "federation_and_egress",
                "title": "Federation egress",
                "items": [
                    "Outbound calls to external IdPs (discovery, JWKS, token endpoint) may **exit** the region; document subprocessors and SCCs.",
                    "Prefer **regional IdP endpoints** (e.g. EU tenant URLs) when the vendor offers them.",
                    "Inline JWKS/metadata mirrors can reduce repeated cross-border fetches.",
                ],
            },
            {
                "id": "observability",
                "title": "Logs, traces, and SIEM",
                "items": [
                    "Route **audit** and access logs to SIEM buckets in the same residency zone as the tenant when required.",
                    "Scrub tokens and secrets from log pipelines; avoid shipping raw PII to global analytics.",
                ],
            },
            {
                "id": "tenant_isolation",
                "title": "Multi-tenant SaaS",
                "items": [
                    "Enforce **tenant_id** / org isolation in storage and admin APIs; residency may differ per tenant.",
                    "Expose region metadata in admin or support tooling so operators honor data-location contracts.",
                ],
            },
        ],
    }
