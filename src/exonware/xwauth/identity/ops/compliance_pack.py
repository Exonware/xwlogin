#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/compliance_pack.py
Compliance **checklist** and **evidence field stubs** for regulated buyers (REF_25 #11).

Not legal advice; legal/compliance teams must complete and sign artifacts.
"""

from __future__ import annotations

from typing import Any

COMPLIANCE_PACK_SCHEMA_VERSION = 1


def compliance_pack_checklist() -> dict[str, Any]:
    """Topics typically required for GDPR-style programs and enterprise DPAs."""
    return {
        "schema_version": COMPLIANCE_PACK_SCHEMA_VERSION,
        "kind": "compliance_pack_checklist",
        "sections": [
            {
                "id": "records_and_ropa",
                "title": "Records of processing / ROPA",
                "items": [
                    "Document **purposes** and **lawful bases** for auth data (contract, legitimate interest, consent where used).",
                    "List **categories** of data subjects (employees, customers’ users) and data categories (identifiers, MFA, audit).",
                    "Identify **recipients** and **cross-border** transfers (IdPs, ESP, cloud regions).",
                ],
            },
            {
                "id": "subprocessors",
                "title": "Subprocessor register",
                "items": [
                    "Maintain a table: vendor, function (email, IdP, hosting), region, DPA/SCC status.",
                    "Publish customer-facing **subprocessor list** update process (notice period).",
                ],
            },
            {
                "id": "retention",
                "title": "Retention and deletion",
                "items": [
                    "Define TTL for sessions, refresh tokens, magic links, audit logs, and backup retention.",
                    "Implement **delete user** / **tenant offboard** flows including replicas and backups policy.",
                ],
            },
            {
                "id": "dpa_annex",
                "title": "DPA / security annex",
                "items": [
                    "Map technical measures: encryption at rest/in transit, access control, logging, pen test cadence.",
                    "Assign **DPO** or EU representative contact if required.",
                ],
            },
            {
                "id": "data_subject_rights",
                "title": "DSR and portability",
                "items": [
                    "Procedures for access, rectification, erasure, restriction, and export of auth-related data.",
                    "SLAs for response times aligned with regulation and contract.",
                ],
            },
            {
                "id": "incidents",
                "title": "Breach and incident response",
                "items": [
                    "Playbook for suspected token compromise or database breach; customer notification thresholds.",
                    "Include repository SECURITY.md and docs/SECURITY_ADVISORIES.md in the customer security packet.",
                ],
            },
        ],
    }


def compliance_evidence_template() -> dict[str, Any]:
    """
    Placeholder map for **customer-facing** compliance packets (fill per deployment).

    Values are empty strings for programmatic merge into PDFs or portals.
    """
    return {
        "schema_version": COMPLIANCE_PACK_SCHEMA_VERSION,
        "kind": "compliance_evidence_template",
        "fields": {
            "data_controller_legal_name": "",
            "data_processor_legal_name": "",
            "product_name": "exonware-xwauth / xwauth-api stack",
            "primary_region": "",
            "subprocessor_list_url": "",
            "dpa_contact_email": "",
            "dpa_version": "",
            "last_ropa_review_date": "",
            "pen_test_summary_url": "",
            "soc2_or_iso_status": "",
        },
        "note": "Populate fields and attach architecture diagrams, subprocessors CSV, and ROPA excerpt.",
    }
