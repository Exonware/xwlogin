#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/airgap_deployment.py
Operational checklist for **air-gapped** or **offline** installs (no outbound internet).

Does not change runtime behavior; use as deployment gate / documentation (REF_25 #17).
"""

from __future__ import annotations

from typing import Any

AIRGAP_OPS_SCHEMA_VERSION = 1


def airgap_deployment_checklist() -> dict[str, Any]:
    """
    JSON-serializable checklist for regulated / disconnected environments.

    Covers packaging, federation, time, TLS, and optional extras (SAML/crypto).
    """
    return {
        "schema_version": AIRGAP_OPS_SCHEMA_VERSION,
        "kind": "airgap_deployment",
        "sections": [
            {
                "id": "python_artifacts",
                "title": "Python packages without PyPI",
                "items": [
                    "Build a **wheelhouse** (or vendor sdists) for exonware-xwauth, your login/IdP components, API hosts, and every transitive dependency on a connected build host.",
                    "Install with ``pip install --no-index --find-links=/path/to/wheels ...``; pin versions in a lockfile or constraints file.",
                    "Disable optional lazy/network installers (e.g. do not rely on runtime package fetch); set ``XWSTACK_SKIP_XWLAZY_INIT=1`` in hardened stacks if xwlazy is present.",
                ],
            },
            {
                "id": "federation_and_jwks",
                "title": "OIDC / federation without outbound HTTPS",
                "items": [
                    "Preload **JWKS** documents and IdP metadata on the build/staging side; configure inline ``jwks`` or internal mirror URLs reachable only inside the enclave.",
                    "Avoid discovery calls to public IdPs at runtime unless those endpoints are reachable on an internal network (reverse proxy, regional mirror).",
                    "Document issuer strings and key rotation: operators must refresh JWKS when IdP keys rotate (no automatic public refetch if blocked).",
                ],
            },
            {
                "id": "time_and_tokens",
                "title": "Clock skew and JWT/OAuth validity",
                "items": [
                    "Provide **synchronized time** (internal NTP stratum or disciplined clocks); JWT ``exp``/``nbf`` and SAML skew windows fail mysteriously when clocks drift.",
                    "Align ``clock_skew_seconds`` in federation validation with your time-sync SLA.",
                ],
            },
            {
                "id": "tls_and_trust",
                "title": "TLS trust stores",
                "items": [
                    "Ship an **internal CA bundle** for mTLS or HTTPS to enterprise IdPs; inject via OS trust store or application TLS context per your platform.",
                    "Do not disable TLS verification to “make airgap work”; fix trust instead.",
                ],
            },
            {
                "id": "optional_extras",
                "title": "Optional components (SAML, email, Redis)",
                "items": [
                    "``[saml]`` / signxml / lxml wheels must be in the wheelhouse; native wheels are platform-specific—build per target OS/arch.",
                    "Magic-link and email OTP require **internal SMTP** or queue; there is no cloud ESP.",
                    "Redis (WebAuthn challenges, rate limits) must be **inside** the enclave if used.",
                ],
            },
            {
                "id": "validation",
                "title": "Go-live validation",
                "items": [
                    "Run protocol and integration tests from an internal CI runner with the same network policy as production.",
                    "Exercise token issuance, JWKS verify, and (if enabled) SAML/SCIM with **no** egress except documented internal dependencies.",
                ],
            },
        ],
    }
