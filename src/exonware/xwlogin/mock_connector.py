"""In-memory storage and user doubles from the connector (unit tests, examples).

Implementation is **xwauth** ``storage.mock``. Not for production deployments — only for tests and
local wiring. Prefer importing through ``exonware.xwlogin.test_support`` in xwlogin test suites.
"""

from __future__ import annotations

from exonware.xwauth.storage.mock import MockStorageProvider, MockUser

__all__ = ["MockStorageProvider", "MockUser"]
