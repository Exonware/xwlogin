# exonware/xwlogin/audit_connector.py
"""Request audit correlation from the connector (``xwauth.audit.context``).

AS transport layers (e.g. xwauth-api) should attach correlation here rather than importing
``xwauth.audit`` directly (GUIDE_32).
"""

from __future__ import annotations

from exonware.xwauth.audit.context import attach_audit_correlation, reset_audit_correlation

__all__ = [
    "attach_audit_correlation",
    "reset_audit_correlation",
]
