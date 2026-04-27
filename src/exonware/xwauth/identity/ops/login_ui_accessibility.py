#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/login_ui_accessibility.py
WCAG-oriented checklist for **reference login / consent HTML** (REF_25 #10).

Applies to login UI templates (reference or customer-owned) and BFF surfaces; not a browser audit tool.
"""

from __future__ import annotations

from typing import Any

LOGIN_UI_A11Y_SCHEMA_VERSION = 1


def login_ui_accessibility_checklist() -> dict[str, Any]:
    """Checklist aligned with **WCAG 2.2** AA themes for auth flows."""
    return {
        "schema_version": LOGIN_UI_A11Y_SCHEMA_VERSION,
        "kind": "login_ui_accessibility",
        "wcag_target": "2.2 AA",
        "sections": [
            {
                "id": "perceivable",
                "title": "Perceivable",
                "items": [
                    "Text contrast **≥ 4.5:1** for normal text; large text/scalable UI per 1.4.3–1.4.6.",
                    "Do not rely on **color alone** for errors (icons/text + `aria-invalid`).",
                    "Provide **text alternatives** for meaningful images; decorative images `alt=\"\"`.",
                ],
            },
            {
                "id": "operable",
                "title": "Operable",
                "items": [
                    "All interactive controls **keyboard reachable**; visible focus order matches reading order (2.4.3, 2.4.7).",
                    "No **keyboard traps** in modals; Escape closes where expected.",
                    "Target size comfortable for touch (2.5.8); avoid tiny-only hit areas.",
                ],
            },
            {
                "id": "understandable",
                "title": "Understandable",
                "items": [
                    "Set **`lang`** on `<html>`; mark password rules and errors in clear language (3.3.x).",
                    "Associate **labels** with inputs (`for`/`id` or `aria-labelledby`); announce errors with `aria-live` where appropriate.",
                    "Consistent navigation and identification across login, MFA, and error states.",
                ],
            },
            {
                "id": "robust",
                "title": "Robust",
                "items": [
                    "Valid, semantic HTML; ARIA used only where native elements are insufficient.",
                    "Test with **screen reader** (NVDA/VoiceOver) and automated axe/Playwright a11y suite in CI when available.",
                ],
            },
            {
                "id": "vpat_style",
                "title": "VPAT-style evidence (procurement)",
                "items": [
                    "Map each WCAG criterion to **pass/partial/fail** for the reference login template version.",
                    "Attach remediation tickets for partial/fail; re-test after fixes.",
                ],
            },
        ],
    }
