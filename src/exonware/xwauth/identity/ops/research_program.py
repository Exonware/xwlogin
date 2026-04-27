#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/research_program.py
Machine-readable **draft** policy for coordinated disclosure, interop findings, and fuzzing focus.

No payments are promised here; ``status`` reflects program maturity (REF_25 #20).
"""

from __future__ import annotations

from typing import Any

RESEARCH_PROGRAM_SCHEMA_VERSION = 1

# Draft until legal/commercial approval; bump schema_version if shape changes.
_DEFAULT_STATUS = "draft"


def interop_bounty_policy() -> dict[str, Any]:
    """
    Structured scope for **protocol / interop** issues affecting ``xwauth``, login/IdP integrations, and ``xwauth-api``.

    Eligibility for paid rewards (if any) will be published separately; until then this is the
    technical scope for **good-faith coordinated disclosure**.
    """
    return {
        "schema_version": RESEARCH_PROGRAM_SCHEMA_VERSION,
        "kind": "interop_bounty_policy",
        "status": _DEFAULT_STATUS,
        "reporting": {
            "channel": "email",
            "address": "connect@exonware.com",
            "subject_prefix": "[SECURITY]",
            "note": "Do not file undisclosed vulnerabilities as public issues.",
        },
        "in_scope": [
            "RFC/OIDC spec violations that cause security impact (token mis-issuance, bypass, cross-tenant leakage).",
            "JWKS / JWT signature verification flaws in federation or AS code paths.",
            "SAML signature / assertion handling flaws when optional SAML extras are installed.",
            "SCIM endpoint authorization or data isolation bugs.",
            "Concrete interoperability breakages with major IdPs (Azure AD, Okta, Google) when reproducible with minimal config.",
        ],
        "out_of_scope": [
            "Issues in dependencies only (report upstream; we may still ship version bumps).",
            "Denial-of-service via oversized payloads without memory safety angle (unless catastrophic at default limits).",
            "Social engineering, phishing templates, or weak customer-chosen secrets.",
            "Findings in unmaintained forks or versions outside the supported range in SECURITY.md.",
            "Scanner noise without a working PoC.",
        ],
        "reward_note": "Paid interop bounty tiers are not active while status is draft; acknowledgement in advisories is still possible.",
    }


def fuzzing_recommendations() -> dict[str, Any]:
    """
    Suggested fuzz / property-test targets for contributors and security researchers.

    The repository does not vendor a fuzzer; use Hypothesis, Atheris, or libFuzzer harnesses externally.
    """
    return {
        "schema_version": RESEARCH_PROGRAM_SCHEMA_VERSION,
        "kind": "fuzzing_recommendations",
        "status": _DEFAULT_STATUS,
        "targets": [
            "OAuth2/OIDC query and form parsers (authorize, token, PAR bodies).",
            "JWT parsing and claim validation with adversarial alg/header combinations (reject ``none``).",
            "Redirect URI parsing and exact-match enforcement.",
            "SAML XML ingestion when ``[saml]`` extras are enabled.",
            "SCIM filter and PATCH parsers.",
        ],
        "tooling_note": "Prefer coverage-guided fuzzing on pure-python entry points or HTTP black-box against a local xwauth-api instance.",
    }
