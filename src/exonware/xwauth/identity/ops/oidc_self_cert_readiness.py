#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/oidc_self_cert_readiness.py
Readiness checklist for **OpenID Foundation**–style certification and listing (REF_25 #2).

Concrete suite names and submission URLs change over time; this tracks engineering prerequisites only.
"""

from __future__ import annotations

from typing import Any

OIDC_SELF_CERT_READINESS_SCHEMA_VERSION = 1


def oidc_self_cert_readiness_checklist() -> dict[str, Any]:
    """Prerequisites before pursuing formal OIDC/OAuth certification and public listing."""
    return {
        "schema_version": OIDC_SELF_CERT_READINESS_SCHEMA_VERSION,
        "kind": "oidc_self_cert_readiness",
        "sections": [
            {
                "id": "conformance_baseline",
                "title": "Conformance baseline",
                "items": [
                    "Meet internal targets in [REF_23](REF_23_COMPETITIVE_PARITY_WIN_PLAN.md) / protocol scorecard before filing fees.",
                    "Green **protocol CI** (`protocol-conformance.yml`) on the profile you will certify.",
                    "Close or document **critical** items in [REF_54_PROTOCOL_DEVIATION_REGISTER.md](REF_54_PROTOCOL_DEVIATION_REGISTER.md).",
                ],
            },
            {
                "id": "certification_suites",
                "title": "Certification suites",
                "items": [
                    "Select official test plans (OAuth 2.0 / OpenID Connect) matching shipped endpoints and grant types.",
                    "Run suites against a stable **certification deployment** (not a developer laptop).",
                    "Archive logs and configuration snapshots required by the certification program.",
                ],
            },
            {
                "id": "foundation_submission",
                "title": "Foundation submission",
                "items": [
                    "Create or update vendor account per current OpenID Foundation process.",
                    "Submit passing results and pay program fees per current schedule.",
                    "Respond to clarifications; keep engineering owner for the full review window.",
                ],
            },
            {
                "id": "listing_and_marketing",
                "title": "Listing and marketing",
                "items": [
                    "After approval, link the **official listing** from docs and website.",
                    "Update [REF_53_PROTOCOL_TRACEABILITY_MATRIX.md](REF_53_PROTOCOL_TRACEABILITY_MATRIX.md) with certified profile identifiers.",
                ],
            },
            {
                "id": "ongoing_maintenance",
                "title": "Ongoing maintenance",
                "items": [
                    "Define **re-certification** triggers (major protocol-affecting releases, dependency upgrades).",
                    "Track certification expiry or program rule changes from the Foundation.",
                ],
            },
        ],
    }
