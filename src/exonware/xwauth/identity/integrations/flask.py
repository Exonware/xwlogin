"""Flask integration shims for xwauth."""

from __future__ import annotations

from typing import Any


def get_current_user(request: Any) -> Any | None:
    """Return current user from request context when present."""
    return getattr(request, "user", None)


def require_auth(request: Any) -> Any:
    """Require authenticated user from request context."""
    user = get_current_user(request)
    if user is None:
        raise PermissionError("Authentication required")
    return user


def require_scope(scope: str):
    """Return a checker that requires a scope on a user-like payload."""

    def _checker(request: Any) -> Any:
        user = require_auth(request)
        scopes = user.get("scopes", []) if isinstance(user, dict) else []
        if scope not in scopes:
            raise PermissionError(f"Required scope: {scope}")
        return user

    return _checker


__all__ = ["get_current_user", "require_auth", "require_scope"]
