#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/storage/interface.py
IStorageProvider Interface Definition
Defines the IStorageProvider interface for dependency inversion with xwstorage.connect.
This allows xwauth to work independently with a mock implementation,
then integrate with xwstorage.connect's real implementation later.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any, Optional, Protocol, runtime_checkable
from datetime import datetime
# ==============================================================================
# DATA MODELS (Protocol-based for interface definition)
# ==============================================================================
@runtime_checkable

class User(Protocol):
    """User data model protocol."""
    @property

    def id(self) -> str:
        """Unique user identifier."""
        ...
    @property

    def email(self) -> Optional[str]:
        """User email address."""
        ...
    @property

    def phone(self) -> Optional[str]:
        """User phone number."""
        ...
    @property

    def password_hash(self) -> Optional[str]:
        """Hashed password."""
        ...
    @property

    def attributes(self) -> dict[str, Any]:
        """Additional user attributes."""
        ...
@runtime_checkable

class Session(Protocol):
    """Session data model protocol."""
    @property

    def id(self) -> str:
        """Unique session identifier."""
        ...
    @property

    def user_id(self) -> str:
        """User identifier."""
        ...
    @property

    def expires_at(self) -> datetime:
        """Session expiration timestamp."""
        ...
    @property

    def attributes(self) -> dict[str, Any]:
        """Additional session attributes."""
        ...
@runtime_checkable

class Token(Protocol):
    """Token data model protocol."""
    @property

    def id(self) -> str:
        """Unique token identifier."""
        ...
    @property

    def user_id(self) -> Optional[str]:
        """User identifier (None for client credentials)."""
        ...
    @property

    def client_id(self) -> str:
        """Client identifier."""
        ...
    @property

    def token_type(self) -> str:
        """Token type (e.g., 'Bearer')."""
        ...
    @property

    def access_token(self) -> str:
        """Access token string."""
        ...
    @property

    def refresh_token(self) -> Optional[str]:
        """Refresh token string."""
        ...
    @property

    def expires_at(self) -> datetime:
        """Token expiration timestamp."""
        ...
    @property

    def scopes(self) -> list[str]:
        """List of granted scopes."""
        ...
    @property

    def attributes(self) -> dict[str, Any]:
        """Additional token attributes."""
        ...
@runtime_checkable

class AuditLog(Protocol):
    """Audit log entry protocol."""
    @property

    def id(self) -> str:
        """Unique audit log identifier."""
        ...
    @property

    def user_id(self) -> Optional[str]:
        """User identifier (None for system actions)."""
        ...
    @property

    def action(self) -> str:
        """Action performed."""
        ...
    @property

    def timestamp(self) -> datetime:
        """Action timestamp."""
        ...
    @property

    def resource(self) -> Optional[str]:
        """Resource affected."""
        ...
    @property

    def attributes(self) -> dict[str, Any]:
        """Additional audit log attributes."""
        ...
@runtime_checkable

class AuthorizationCode(Protocol):
    """Authorization code data model protocol."""
    @property

    def code(self) -> str:
        """Authorization code string."""
        ...
    @property

    def client_id(self) -> str:
        """Client identifier."""
        ...
    @property

    def redirect_uri(self) -> str:
        """Redirect URI."""
        ...
    @property

    def scopes(self) -> list[str]:
        """List of granted scopes."""
        ...
    @property

    def code_challenge(self) -> Optional[str]:
        """PKCE code challenge."""
        ...
    @property

    def code_challenge_method(self) -> Optional[str]:
        """PKCE code challenge method (S256 or plain)."""
        ...
    @property

    def expires_at(self) -> datetime:
        """Code expiration timestamp."""
        ...
    @property

    def created_at(self) -> datetime:
        """Code creation timestamp."""
        ...
    @property

    def user_id(self) -> Optional[str]:
        """User identifier (set after authentication)."""
        ...
    @property

    def attributes(self) -> dict[str, Any]:
        """Additional authorization code attributes."""
        ...
@runtime_checkable

class DeviceCode(Protocol):
    """Device code data model protocol."""
    @property

    def device_code(self) -> str:
        """Device code string."""
        ...
    @property

    def user_code(self) -> str:
        """User code string (for display to user)."""
        ...
    @property

    def client_id(self) -> str:
        """Client identifier."""
        ...
    @property

    def scopes(self) -> list[str]:
        """List of requested scopes."""
        ...
    @property

    def expires_at(self) -> datetime:
        """Device code expiration timestamp."""
        ...
    @property

    def created_at(self) -> datetime:
        """Device code creation timestamp."""
        ...
    @property

    def status(self) -> str:
        """Device code status (pending, approved, denied, expired)."""
        ...
    @property

    def user_id(self) -> Optional[str]:
        """User identifier (set when approved)."""
        ...
    @property

    def attributes(self) -> dict[str, Any]:
        """Additional device code attributes."""
        ...
# ==============================================================================
# STORAGE PROVIDER INTERFACE
# ==============================================================================
# Import basic interface from xwsystem (single source of truth)
from exonware.xwsystem.shared.contracts import IBasicProviderStorage
@runtime_checkable

class IStorageProvider(IBasicProviderStorage, Protocol):
    """
    Storage provider interface for dependency inversion (extends IBasicProviderStorage).
    This interface extends IBasicProviderStorage (from xwsystem) with domain-specific
    convenience methods for xwauth. The basic interface provides generic CRUD operations
    (save, get, update, delete, list) that work with any entity type, while this full
    interface adds convenience methods for users, sessions, tokens, audit logs, etc.
    Following dependency inversion principle for circular dependency resolution:
    - xwsystem defines IBasicProviderStorage (minimal, generic core)
    - xwauth extends IBasicProviderStorage to IStorageProvider (full interface)
    - xwstorage.connect implements IStorageProvider
    - xwauth uses IStorageProvider (not xwstorage.connect directly)
    """
    # ==========================================================================
    # USER OPERATIONS
    # ==========================================================================

    async def save_user(self, user: User) -> None:
        """
        Save user to storage.
        Args:
            user: User object to save
        """
        ...

    async def get_user(self, user_id: str) -> Optional[User]:
        """
        Get user by ID.
        Args:
            user_id: User identifier
        Returns:
            User object if found, None otherwise
        """
        ...

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email address.
        Args:
            email: Email address
        Returns:
            User object if found, None otherwise
        """
        ...

    async def get_user_by_phone(self, phone: str) -> Optional[User]:
        """
        Get user by phone number.
        Args:
            phone: Phone number
        Returns:
            User object if found, None otherwise
        """
        ...

    async def update_user(self, user_id: str, updates: dict[str, Any]) -> None:
        """
        Update user data.
        Args:
            user_id: User identifier
            updates: Dictionary of fields to update
        """
        ...

    async def delete_user(self, user_id: str) -> None:
        """
        Delete user from storage.
        Args:
            user_id: User identifier
        """
        ...

    async def list_users(self, filters: Optional[dict[str, Any]] = None) -> list[User]:
        """
        List users with optional filters.
        Args:
            filters: Optional filter dictionary (e.g., {"status": "active"})
        Returns:
            List of User objects
        """
        ...

    async def find_user_by_provider(
        self,
        provider: str,
        provider_user_id: str
    ) -> Optional[User]:
        """
        Find user by provider account.
        Args:
            provider: Provider name (e.g., 'google', 'github')
            provider_user_id: Provider user ID
        Returns:
            User object if found, None otherwise
        """
        ...
    # ==========================================================================
    # SESSION OPERATIONS
    # ==========================================================================

    async def save_session(self, session: Session) -> None:
        """
        Save session to storage.
        Args:
            session: Session object to save
        """
        ...

    async def get_session(self, session_id: str) -> Optional[Session]:
        """
        Get session by ID.
        Args:
            session_id: Session identifier
        Returns:
            Session object if found, None otherwise
        """
        ...

    async def delete_session(self, session_id: str) -> None:
        """
        Delete session from storage.
        Args:
            session_id: Session identifier
        """
        ...

    async def list_user_sessions(self, user_id: str) -> list[Session]:
        """
        List all sessions for a user.
        Args:
            user_id: User identifier
        Returns:
            List of Session objects
        """
        ...
    # ==========================================================================
    # TOKEN OPERATIONS
    # ==========================================================================

    async def save_token(self, token: Token) -> None:
        """
        Save token to storage.
        Args:
            token: Token object to save
        """
        ...

    async def get_token(self, token_id: str) -> Optional[Token]:
        """
        Get token by ID.
        Args:
            token_id: Token identifier
        Returns:
            Token object if found, None otherwise
        """
        ...

    async def get_token_by_access_token(self, access_token: str) -> Optional[Token]:
        """
        Get token by access token string.
        Args:
            access_token: Access token string
        Returns:
            Token object if found, None otherwise
        """
        ...

    async def get_token_by_refresh_token(self, refresh_token: str) -> Optional[Token]:
        """
        Get token by refresh token string.
        Args:
            refresh_token: Refresh token string
        Returns:
            Token object if found, None otherwise
        """
        ...

    async def delete_token(self, token_id: str) -> None:
        """
        Delete token from storage.
        Args:
            token_id: Token identifier
        """
        ...

    async def list_user_tokens(self, user_id: str) -> list[Token]:
        """
        List all tokens for a user.
        Args:
            user_id: User identifier
        Returns:
            List of Token objects
        """
        ...
    # ==========================================================================
    # AUDIT LOG OPERATIONS
    # ==========================================================================

    async def save_audit_log(self, log: AuditLog) -> None:
        """
        Save audit log entry to storage.
        Args:
            log: AuditLog object to save
        """
        ...

    async def get_audit_logs(self, filters: Optional[dict[str, Any]] = None) -> list[AuditLog]:
        """
        Get audit logs with optional filters.
        Args:
            filters: Optional filter dictionary
                     (e.g., {"user_id": "user123", "action": "login"})
        Returns:
            List of AuditLog objects
        """
        ...
    # ==========================================================================
    # AUTHORIZATION CODE OPERATIONS
    # ==========================================================================

    async def save_authorization_code(self, code: AuthorizationCode) -> None:
        """
        Save authorization code to storage.
        Args:
            code: AuthorizationCode object to save
        """
        ...

    async def get_authorization_code(self, code: str) -> Optional[AuthorizationCode]:
        """
        Get authorization code by code string.
        Args:
            code: Authorization code string
        Returns:
            AuthorizationCode object if found, None otherwise
        """
        ...

    async def delete_authorization_code(self, code: str) -> None:
        """
        Delete authorization code from storage.
        Args:
            code: Authorization code string
        """
        ...
    # ==========================================================================
    # DEVICE CODE OPERATIONS
    # ==========================================================================

    async def save_device_code(self, device_code: DeviceCode) -> None:
        """
        Save device code to storage.
        Args:
            device_code: DeviceCode object to save
        """
        ...

    async def get_device_code(self, device_code: str) -> Optional[DeviceCode]:
        """
        Get device code by device code string.
        Args:
            device_code: Device code string
        Returns:
            DeviceCode object if found, None otherwise
        """
        ...

    async def get_device_code_by_user_code(self, user_code: str) -> Optional[DeviceCode]:
        """
        Get device code by user code string.
        Args:
            user_code: User code string
        Returns:
            DeviceCode object if found, None otherwise
        """
        ...

    async def update_device_code_status(
        self,
        device_code: str,
        status: str,
        user_id: Optional[str] = None
    ) -> None:
        """
        Update device code status.
        Args:
            device_code: Device code string
            status: New status (pending, approved, denied, expired)
            user_id: Optional user identifier (set when approved)
        """
        ...

    async def delete_device_code(self, device_code: str) -> None:
        """
        Delete device code from storage.
        Args:
            device_code: Device code string
        """
        ...
