#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/session_device_reference_ui.py
Checklist for **end-user session and device management** in the reference app (REF_25 #14).

Applies to login UI templates and ``xwauth-api`` session APIs they call.
"""

from __future__ import annotations

from typing import Any

SESSION_DEVICE_REFERENCE_UI_SCHEMA_VERSION = 1


def session_device_reference_ui_checklist() -> dict[str, Any]:
    """UX and API expectations for “my sessions / my devices” surfaces."""
    return {
        "schema_version": SESSION_DEVICE_REFERENCE_UI_SCHEMA_VERSION,
        "kind": "session_device_reference_ui",
        "sections": [
            {
                "id": "surfaces",
                "title": "User-facing surfaces",
                "items": [
                    "Authenticated **account** area lists active **sessions** (approx. location/device/browser label, created/last seen).",
                    "Optional **device** list when WebAuthn or device-bound factors are used.",
                ],
            },
            {
                "id": "revocation",
                "title": "Revoke session / sign out elsewhere",
                "items": [
                    "Per-session **revoke** calls the same backend primitive as admin revoke (subject to authz).",
                    "**Sign out all** uses a defined token/session invalidation strategy (refresh rotation, server-side deny list).",
                ],
            },
            {
                "id": "security_copy",
                "title": "Security copy and a11y",
                "items": [
                    "Explain what revoking does (e.g. other browsers lose access within N minutes).",
                    "Meet **WCAG** basics per REF_36 themes for tables, buttons, and confirmations.",
                ],
            },
            {
                "id": "api_alignment",
                "title": "API alignment",
                "items": [
                    "Reference UI must use **documented** OAuth/OIDC or first-party session APIs—no *undocumented* cookies-only flows.",
                    "HTML reference ``GET /auth/sessions/view`` may use documented cookie ``xwauth_reference_access_token`` (same-origin; integrator-set access token; prefer HttpOnly/Secure/SameSite); JSON list/revoke remain Bearer-only.",
                    "CSRF and **same-site** policies consistent with login forms.",
                    "Library reference: ``exonware.xwauth.handlers.mixins.sessions`` — ``GET /auth/sessions``, ``GET /auth/sessions/view`` (HTML), ``DELETE /auth/sessions/{session_id}``, ``DELETE /auth/sessions/exclude-current`` (Bearer); OpenAPI operationIds ``auth_sessions_list``, ``auth_sessions_list_html``, ``auth_sessions_revoke``, ``auth_sessions_revoke_others``.",
                ],
            },
            {
                "id": "privacy",
                "title": "Privacy and telemetry",
                "items": [
                    "Minimize **PII** in device labels; allow user-editable friendly names where helpful.",
                    "If analytics fire on revoke, disclose in privacy notice.",
                ],
            },
        ],
    }
