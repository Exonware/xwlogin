# exonware/xwauth.identity/src/exonware/xwauth.identity/foundation/defs.py
"""Foundation enums for the login product (REF_41 §7 — canonical here, not in xwauth)."""

from __future__ import annotations

from enum import Enum


class UserStatus(str, Enum):
    """User account status (identity / first-party login surface)."""

    ACTIVE = "active"
    PENDING = "pending"
    SUSPENDED = "suspended"
    DISABLED = "disabled"
    DELETED = "deleted"


class MFAMethod(str, Enum):
    """First-party multi-factor methods (login product surface)."""

    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    WEBAUTHN = "webauthn"
    BACKUP_CODE = "backup_code"
