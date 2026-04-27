# exonware/xwauth.identity/src/exonware/xwauth.identity/foundation/contracts.py
"""Foundation protocols for the login product (REF_41 §7 — no xwauth imports)."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class IAuthenticator(Protocol):
    """First-party authenticator contract (credentials → user id or failure)."""

    async def authenticate(self, credentials: dict[str, Any]) -> str | None:
        """Return user id if authenticated, else ``None``."""
        ...
