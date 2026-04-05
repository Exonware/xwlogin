# exonware/xwlogin/storage_connector.py
"""XWStorage-backed ``IStorageProvider`` implementation from the connector.

Hosts that build persistence with ``xwstorage`` + **xwauth**'s adapter should import the provider
class here instead of ``exonware.xwauth.storage.xwstorage_provider`` (GUIDE_32).
"""

from __future__ import annotations

from exonware.xwauth.storage.xwstorage_provider import XWStorageProvider

__all__ = ["XWStorageProvider"]
