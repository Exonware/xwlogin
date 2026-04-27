"""FastAPI integration shims for xwauth."""

from __future__ import annotations

from typing import Any


async def get_current_user(request: Any) -> Any | None:
    """Return current user from request state when available."""
    state = getattr(request, "state", None)
    if state is None:
        return None
    return getattr(state, "user", None)


async def require_auth(request: Any) -> Any:
    """Require authenticated user from request context."""
    user = await get_current_user(request)
    if user is None:
        raise PermissionError("Authentication required")
    return user


def require_scope(scope: str):
    """Return a checker that requires a scope on a user-like payload."""

    async def _checker(request: Any) -> Any:
        user = await require_auth(request)
        scopes = user.get("scopes", []) if isinstance(user, dict) else []
        if scope not in scopes:
            raise PermissionError(f"Required scope: {scope}")
        return user

    return _checker


__all__ = ["get_current_user", "require_auth", "require_scope"]
