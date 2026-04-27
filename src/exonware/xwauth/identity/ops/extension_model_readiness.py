#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/extension_model_readiness.py
Readiness checklist for a **stable extension** surface: MFA, risk, step-up, custom claims (REF_25 #8).

Compare in-process hooks vs out-of-process HTTP plugins; pick one primary story per release train.
"""

from __future__ import annotations

from typing import Any

EXTENSION_MODEL_READINESS_SCHEMA_VERSION = 1


def extension_model_readiness_checklist() -> dict[str, Any]:
    """Engineering criteria before promising a supported extension API."""
    return {
        "schema_version": EXTENSION_MODEL_READINESS_SCHEMA_VERSION,
        "kind": "extension_model_readiness",
        "sections": [
            {
                "id": "surface_choice",
                "title": "Extension surface",
                "items": [
                    "Choose **primary** model: versioned Python entry points (in-process) **or** signed HTTP callbacks (out-of-process).",
                    "Document **latency and failure** semantics: what happens if an extension times out or errors.",
                ],
            },
            {
                "id": "versioning",
                "title": "Versioning and compatibility",
                "items": [
                    "Assign **semantic version** to the extension contract; bump MINOR for additive, MAJOR for breaking.",
                    "Provide **deprecation window** and runtime warnings before removal.",
                ],
            },
            {
                "id": "mfa_risk_stepup",
                "title": "MFA, risk, and step-up",
                "items": [
                    "Define extension hooks for **MFA enrollment**, **verification**, and **step-up** challenges with explicit inputs/outputs.",
                    "Risk signals (IP, device, velocity) should be **pluggable** without forking core auth code.",
                ],
            },
            {
                "id": "custom_claims",
                "title": "Custom claims and tokens",
                "items": [
                    "Specify how extensions contribute **claims** to access/id tokens without violating audience/scope rules.",
                    "Reject or sanitize claims that **break** JWT size or privacy commitments.",
                ],
            },
            {
                "id": "security_boundary",
                "title": "Security boundary",
                "items": [
                    "Extensions must not receive **raw** refresh tokens or long-lived secrets unless explicitly designed and audited.",
                    "For HTTP plugins, mandate **mTLS or HMAC** and replay protection.",
                ],
            },
        ],
    }
