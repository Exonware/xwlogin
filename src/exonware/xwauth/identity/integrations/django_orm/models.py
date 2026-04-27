"""Minimal Django ORM model placeholders for integration tests."""

from __future__ import annotations


class OAuth2ClientModel:
    """Compatibility placeholder model."""

    client_id: str | None = None


class OAuth2TokenModel:
    """Compatibility placeholder model."""

    id: str | None = None
    user_id: str | None = None
    client_id: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None


class UserModel:
    """Compatibility placeholder model."""

    id: str | None = None
    email: str | None = None
    password_hash: str | None = None


__all__ = ["OAuth2ClientModel", "OAuth2TokenModel", "UserModel"]
