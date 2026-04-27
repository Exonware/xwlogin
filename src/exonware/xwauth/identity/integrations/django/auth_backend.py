"""Minimal Django auth backend shim."""

from __future__ import annotations

from typing import Any


class XWAuthBackend:
    """Simple backend-like object with Django-compatible method names."""

    def authenticate(self, request: Any = None, **credentials: Any) -> Any | None:
        return credentials.get("user")

    def get_user(self, user_id: Any) -> Any | None:
        return user_id


__all__ = ["XWAuthBackend"]
