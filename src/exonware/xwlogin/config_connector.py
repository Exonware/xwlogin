"""Authorization-server configuration types and config validation errors from the connector.

Login and MFA code should import from here instead of ``exonware.xwauth.config`` /
``exonware.xwauth.errors`` for these symbols.

``DEFAULT_TEST_CLIENTS`` is the same OAuth test client list as in **xwauth** — for integration
tests and sample apps only, not production configuration.
"""

from __future__ import annotations

from exonware.xwauth.config.config import DEFAULT_TEST_CLIENTS, XWAuthConfig
from exonware.xwauth.errors import XWConfigError

__all__ = ["DEFAULT_TEST_CLIENTS", "XWAuthConfig", "XWConfigError"]
