"""SQLAlchemy mixin placeholders for compatibility tests."""

from __future__ import annotations


class OAuth2ClientMixin:
    """Compatibility mixin placeholder."""

    client_id: str | None = None
    client_secret: str | None = None


class OAuth2TokenMixin:
    """Compatibility placeholder mixin for OAuth2 token records."""

    id: str | None = None
    user_id: str | None = None
    client_id: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None


class UserMixin:
    """Compatibility placeholder mixin for user records."""

    id: str | None = None
    email: str | None = None
    password_hash: str | None = None


__all__ = ["OAuth2ClientMixin", "OAuth2TokenMixin", "UserMixin"]
