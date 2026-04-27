"""Minimal Django REST Framework auth shim."""

from __future__ import annotations

from typing import Any


class XWAuthAuthentication:
    """DRF-like authentication class shim."""

    def authenticate(self, request: Any) -> tuple[Any, Any] | None:
        user = getattr(request, "user", None)
        token = getattr(request, "auth", None)
        if user is None:
            return None
        return user, token


__all__ = ["XWAuthAuthentication"]
