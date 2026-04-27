#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/pen_test_engagement.py
Checklist for **third-party penetration tests** and a publishable executive summary (REF_25 #1).

Does not replace a SoW or vendor contract; use as an internal readiness gate before kickoff.
"""

from __future__ import annotations

from typing import Any

PENTEST_ENGAGEMENT_SCHEMA_VERSION = 1


def pen_test_engagement_checklist() -> dict[str, Any]:
    """Structured steps from scoping through public executive-summary publication."""
    return {
        "schema_version": PENTEST_ENGAGEMENT_SCHEMA_VERSION,
        "kind": "pen_test_engagement",
        "sections": [
            {
                "id": "scope",
                "title": "Scope and assets",
                "items": [
                    "Enumerate in-scope components: `xwauth` library hot paths, `xwauth-api` HTTP surface, login/UI and IdP integration surfaces, storage adapters in use.",
                    "List **out of scope** (third-party IdPs, customer apps, infrastructure you do not operate).",
                    "Agree OAuth/OIDC profiles under test (grant types, federation, SCIM if exposed).",
                ],
            },
            {
                "id": "environment",
                "title": "Target environment",
                "items": [
                    "Dedicated **staging** stack mirroring production config (TLS, headers, rate limits).",
                    "Non-production **credentials** and synthetic tenants; no real PII.",
                    "Version pins: git SHAs or release tags for each in-scope component (auth library, API host, login UI, storage).",
                ],
            },
            {
                "id": "rules_of_engagement",
                "title": "Rules of engagement",
                "items": [
                    "Testing windows, emergency contacts, and escalation path for critical findings.",
                    "Safe-harbor for good-faith testing; no destructive actions on shared infra without written approval.",
                    "Data handling: how reports and evidence are stored and destroyed after engagement.",
                ],
            },
            {
                "id": "deliverables",
                "title": "Deliverables from vendor",
                "items": [
                    "Technical report with repro steps, severity (e.g. CVSS), and affected components.",
                    "**Executive summary** suitable for redaction and publication (procurement / trust page).",
                    "Retest window or statement after fixes land.",
                ],
            },
            {
                "id": "executive_summary_publication",
                "title": "Publishing the executive summary",
                "items": [
                    "Legal/comms review; redact customer-specific or exploitable-only detail.",
                    "Publish under `docs/logs/reviews/` (or site) with date, scope, and vendor attribution if allowed.",
                    "Link from `SECURITY.md` or the project README if policy allows.",
                ],
            },
            {
                "id": "remediation_follow_up",
                "title": "Remediation",
                "items": [
                    "Track findings in issue tracker; map to `docs/SECURITY_ADVISORIES.md` when shipping fixes.",
                    "Schedule follow-up or annual retest per risk appetite.",
                ],
            },
        ],
    }
