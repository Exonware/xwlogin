#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/contracts.py
XWAuth Interfaces and Contracts
This module defines all interfaces (I-prefix) for xwauth following GUIDE_DEV.md.
All interfaces use @runtime_checkable Protocol pattern.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any, Callable, Protocol, runtime_checkable
from datetime import datetime
from exonware.xwsystem.security.contracts import AuthContext, IAuthContextResolver


# ==============================================================================
# LOGIN HTTP BUNDLE (used by xwauth-identity-api and connector hosts)
# ==============================================================================
@runtime_checkable
class ILoginHttpBundle(Protocol):
    """Shape of the login HTTP bundle returned by ``get_login_http_bundle()``.

    A login-provider deployment exposes two things over this bundle:
    - ``login_route_mixins``: a module (or namespace) that registers FastAPI route mixins
    - ``get_provider_callback_routes``: a callable returning the list of IdP callback routes
    """

    login_route_mixins: Any
    get_provider_callback_routes: Callable[..., Any]
# ==============================================================================
# SHARED AUTH CONTEXT CONTRACT
# ==============================================================================
# ==============================================================================
# PROVIDER INTERFACES
# ==============================================================================
@runtime_checkable

class IProvider(Protocol):
    """Interface for OAuth providers."""
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        ...
    @property

    def provider_type(self) -> str:
        """Get provider type."""
        ...

    async def get_authorization_url(
        self,
        client_id: str,
        redirect_uri: str,
        state: str,
        scopes: list[str] | None = None
    ) -> str:
        """
        Get authorization URL for OAuth flow.
        Args:
            client_id: OAuth client ID
            redirect_uri: Redirect URI
            state: State parameter for CSRF protection
            scopes: Optional list of scopes
        Returns:
            Authorization URL
        """
        ...

    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str
    ) -> dict[str, Any]:
        """
        Exchange authorization code for access token.
        Args:
            code: Authorization code
            redirect_uri: Redirect URI
        Returns:
            Token response dictionary
        """
        ...

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from provider.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        ...
# ==============================================================================
# TOKEN MANAGER INTERFACES
# ==============================================================================
@runtime_checkable

class ITokenManager(Protocol):
    """Interface for token management."""

    async def generate_access_token(
        self,
        user_id: str | None,
        client_id: str,
        scopes: list[str]
    ) -> str:
        """
        Generate access token.
        Args:
            user_id: User identifier (None for client credentials)
            client_id: Client identifier
            scopes: List of scopes
        Returns:
            Access token string
        """
        ...

    async def generate_refresh_token(
        self,
        user_id: str | None,
        client_id: str,
        *,
        refresh_metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Generate refresh token.
        Args:
            user_id: User identifier
            client_id: Client identifier
            refresh_metadata: Optional fields persisted with the refresh token (tenancy, session)
        Returns:
            Refresh token string
        """
        ...

    async def validate_token(self, token: str) -> bool:
        """
        Validate token.
        Args:
            token: Token string
        Returns:
            True if valid, False otherwise
        """
        ...

    async def revoke_token(self, token: str) -> None:
        """
        Revoke token.
        Args:
            token: Token string to revoke
        """
        ...
# ==============================================================================
# SESSION MANAGER INTERFACES
# ==============================================================================
@runtime_checkable

class ISessionManager(Protocol):
    """Interface for session management."""

    async def create_session(
        self,
        user_id: str,
        expires_in: int
    ) -> str:
        """
        Create new session.
        Args:
            user_id: User identifier
            expires_in: Session expiration in seconds
        Returns:
            Session ID
        """
        ...

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """
        Get session data.
        Args:
            session_id: Session identifier
        Returns:
            Session data dictionary or None
        """
        ...

    async def revoke_session(self, session_id: str) -> None:
        """
        Revoke session.
        Args:
            session_id: Session identifier
        """
        ...
# ==============================================================================
# AUTHENTICATION INTERFACES
# ==============================================================================
@runtime_checkable
class IAuthenticator(Protocol):
    """Interface for authentication methods (in-process authenticator plugins)."""

    async def authenticate(self, credentials: dict[str, Any]) -> str | None:
        """
        Authenticate user with credentials.
        Args:
            credentials: Authentication credentials
        Returns:
            User ID if authenticated, None otherwise
        """
        ...
# ==============================================================================
# AUTHORIZATION INTERFACES
# ==============================================================================
@runtime_checkable

class IAuthorizer(Protocol):
    """Interface for authorization."""

    async def check_permission(
        self,
        user_id: str,
        resource: str,
        action: str
    ) -> bool:
        """
        Check if user has permission for resource action.
        Args:
            user_id: User identifier
            resource: Resource identifier
            action: Action to check
        Returns:
            True if user has permission, False otherwise
        """
        ...

    async def get_user_roles(self, user_id: str) -> list[str]:
        """
        Get user roles.
        Args:
            user_id: User identifier
        Returns:
            List of role names
        """
        ...
# ==============================================================================
# CONFIGURATION INTERFACES
# ==============================================================================
@runtime_checkable

class IConfig(Protocol):
    """Interface for configuration."""

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        ...

    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        ...

    def has(self, key: str) -> bool:
        """Check if configuration key exists."""
        ...
# ==============================================================================
# RATE LIMITING & AUDIT (parity with xlib_OLD/xauth)
# ==============================================================================
@runtime_checkable

class IRateLimiter(Protocol):
    """Interface for rate limiting (auth operations)."""

    async def check_rate_limit(
        self,
        identifier: str,
        action: str,
        max_requests: int,
        window_seconds: int
    ) -> bool:
        """
        Check if rate limit is exceeded.
        Args:
            identifier: Rate limit key (e.g. IP, user_id).
            action: Action name (e.g. login_attempt_ip, registration).
            max_requests: Max requests allowed in window.
            window_seconds: Window size in seconds.
        Returns:
            True if limit exceeded, False otherwise.
        """
        ...

    async def increment_counter(self, identifier: str, action: str) -> int:
        """
        Increment counter for identifier/action. Returns current count.
        """
        ...
@runtime_checkable

class IAuditLogger(Protocol):
    """Interface for audit logging (auth events)."""

    async def log_event(
        self,
        event_type: str,
        detail: str,
        user_id: str | None = None,
        client_ip: str | None = None,
        success: bool = True,
        additional_data: dict[str, Any] | None = None
    ) -> None:
        """Log an audit event."""
        ...

    async def get_user_events(self, user_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Return audit events for a user (optional)."""
        ...
