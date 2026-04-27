#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/infra_as_code_tenants.py
Checklist for **Terraform / Pulumi** coverage of auth tenancy and clients (REF_25 #3).

Does not ship modules; use when authoring `deploy/terraform`, `deploy/pulumi`, or a sibling repo.
"""

from __future__ import annotations

from typing import Any

INFRA_AS_CODE_TENANTS_SCHEMA_VERSION = 1


def infra_as_code_tenants_checklist() -> dict[str, Any]:
    """Structured expectations for IaC that provisions tenants, OAuth clients, URIs, keys, and scopes."""
    return {
        "schema_version": INFRA_AS_CODE_TENANTS_SCHEMA_VERSION,
        "kind": "infra_as_code_tenants",
        "sections": [
            {
                "id": "resource_model",
                "title": "Resource model",
                "items": [
                    "Represent **tenants / realms / orgs** as first-class resources with stable identifiers.",
                    "OAuth **clients** (public/confidential), redirect URIs, post-logout URIs, and CORS origins as data, not hand-edited JSON in prod.",
                    "Optional **SCIM** or admin-only routes gated by the same tenant boundary as runtime config.",
                ],
            },
            {
                "id": "scopes_and_grants",
                "title": "Scopes, grants, and policies",
                "items": [
                    "Model **default scopes**, optional consent behavior, and grant-type allow lists per client or tenant.",
                    "Keep policy changes **versioned** in VCS; avoid silent drift between environments.",
                ],
            },
            {
                "id": "secrets_and_keys",
                "title": "Secrets and signing keys",
                "items": [
                    "Never commit raw **client secrets** or PEM/JWK private material; integrate with Vault, cloud KMS, or sealed secrets.",
                    "Define **rotation** procedure: new key → JWKS publish → validate → retire old key (align with `ops/multi_region_auth` themes).",
                ],
            },
            {
                "id": "state_and_drift",
                "title": "State and drift",
                "items": [
                    "Use **remote state** with locking; restrict access to state buckets equal to production.",
                    "Run `plan` in CI on pull requests; require review for applies that touch auth surfaces.",
                ],
            },
            {
                "id": "environments",
                "title": "Environments",
                "items": [
                    "Separate **dev/stage/prod** workspaces or stacks; forbid copying prod secrets into lower envs.",
                    "Document how **issuer URLs** and discovery metadata map per environment.",
                ],
            },
        ],
    }
