#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/storage/__init__.py
Storage Integration Module
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from .interface import (
    IStorageProvider,
    User,
    Session,
    Token,
    AuditLog,
    AuthorizationCode,
    DeviceCode,
)
from .mock import MockStorageProvider
try:
    from .xwstorage_provider import XWStorageProvider
except Exception:  # pragma: no cover - optional dependency path
    XWStorageProvider = None  # type: ignore[assignment]
__all__ = [
    "IStorageProvider",
    "MockStorageProvider",
    "User",
    "Session",
    "Token",
    "AuditLog",
    "AuthorizationCode",
    "DeviceCode",
]
if XWStorageProvider is not None:
    __all__.append("XWStorageProvider")
