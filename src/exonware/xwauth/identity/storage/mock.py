#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/storage/mock.py
Mock IStorageProvider Implementation
Provides a mock implementation of IStorageProvider for independent development
of xwauth without requiring xwstorage.connect. Uses in-memory storage.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any
from datetime import datetime
from dataclasses import dataclass, field
from exonware.xwsystem import get_logger
from .interface import (
    IStorageProvider,
    User,
    Session,
    Token,
    AuditLog,
    AuthorizationCode,
    DeviceCode,
)
logger = get_logger(__name__)
# ==============================================================================
# MOCK DATA MODELS
# ==============================================================================
@dataclass

class MockUser:
    """Mock user implementation."""
    id: str
    email: str | None = None
    phone: str | None = None
    password_hash: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
@dataclass

class MockSession:
    """Mock session implementation."""
    id: str
    user_id: str
    expires_at: datetime
    attributes: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
@dataclass

class MockToken:
    """Mock token implementation."""
    id: str
    user_id: str | None
    client_id: str
    token_type: str
    access_token: str
    refresh_token: str | None = None
    expires_at: datetime = None
    scopes: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
@dataclass

class MockAuditLog:
    """Mock audit log implementation."""
    id: str
    user_id: str | None
    action: str
    timestamp: datetime
    resource: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)
@dataclass

class MockAuthorizationCode:
    """Mock authorization code implementation."""
    code: str
    client_id: str
    redirect_uri: str
    scopes: list[str] = field(default_factory=list)
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    expires_at: datetime = None
    created_at: datetime = None
    user_id: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
@dataclass

class MockDeviceCode:
    """Mock device code implementation."""
    device_code: str
    user_code: str
    client_id: str
    scopes: list[str] = field(default_factory=list)
    expires_at: datetime = None
    created_at: datetime = None
    status: str = "pending"  # pending, approved, denied, expired
    user_id: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
# ==============================================================================
# MOCK STORAGE PROVIDER
# ==============================================================================


class MockStorageProvider:
    """
    Mock storage provider for independent development.
    Provides in-memory storage functionality without requiring xwstorage.connect:
    - In-memory user storage
    - In-memory session storage
    - In-memory token storage
    - In-memory audit log storage
    This allows xwauth to be developed and tested independently
    before integrating with xwstorage.connect's real implementation.
    """

    def __init__(self):
        """Initialize mock storage provider."""
        self._users: dict[str, MockUser] = {}
        self._users_by_email: dict[str, str] = {}  # email -> user_id
        self._users_by_phone: dict[str, str] = {}  # phone -> user_id
        self._users_by_provider: dict[tuple[str, str], str] = {}  # (provider, provider_user_id) -> user_id
        self._sessions: dict[str, MockSession] = {}
        self._sessions_by_user: dict[str, list[str]] = {}  # user_id -> [session_id]
        self._tokens: dict[str, MockToken] = {}
        self._tokens_by_access: dict[str, str] = {}  # access_token -> token_id
        self._tokens_by_refresh: dict[str, str] = {}  # refresh_token -> token_id
        self._tokens_by_user: dict[str, list[str]] = {}  # user_id -> [token_id]
        self._audit_logs: list[MockAuditLog] = []
        self._authorization_codes: dict[str, MockAuthorizationCode] = {}  # code -> AuthorizationCode
        self._device_codes: dict[str, MockDeviceCode] = {}  # device_code -> DeviceCode
        self._device_codes_by_user_code: dict[str, str] = {}  # user_code -> device_code
        logger.info("MockStorageProvider initialized (independent development mode)")
    # ==========================================================================
    # USER OPERATIONS
    # ==========================================================================

    async def save_user(self, user: User) -> None:
        """Save user to storage."""
        if not isinstance(user, MockUser):
            # Convert protocol to mock implementation
            mock_user = MockUser(
                id=user.id,
                email=user.email,
                phone=getattr(user, 'phone', None),
                password_hash=user.password_hash,
                attributes=user.attributes.copy() if hasattr(user, 'attributes') else {}
            )
        else:
            mock_user = user
        self._users[mock_user.id] = mock_user
        # Index by email
        if mock_user.email:
            self._users_by_email[mock_user.email.lower()] = mock_user.id
        # Index by phone
        if mock_user.phone:
            self._users_by_phone[mock_user.phone] = mock_user.id
        # Index by provider accounts (from linked_accounts)
        linked_accounts = mock_user.attributes.get('linked_accounts', {})
        for provider, account_data in linked_accounts.items():
            if isinstance(account_data, dict):
                provider_user_id = account_data.get('provider_user_id')
                if provider_user_id:
                    self._users_by_provider[(provider, provider_user_id)] = mock_user.id
        logger.debug(f"Saved user: {mock_user.id}")

    async def get_user(self, user_id: str) -> User | None:
        """Get user by ID."""
        return self._users.get(user_id)

    async def get_user_by_email(self, email: str) -> User | None:
        """Get user by email address."""
        if not email:
            return None
        user_id = self._users_by_email.get(email.lower())
        if user_id:
            return self._users.get(user_id)
        return None

    async def get_user_by_phone(self, phone: str) -> User | None:
        """Get user by phone number."""
        if not phone:
            return None
        user_id = self._users_by_phone.get(phone)
        if user_id:
            return self._users.get(user_id)
        return None

    async def find_user_by_provider(
        self,
        provider: str,
        provider_user_id: str
    ) -> User | None:
        """Find user by provider account (efficient indexed lookup)."""
        if not provider or not provider_user_id:
            return None
        user_id = self._users_by_provider.get((provider, provider_user_id))
        if user_id:
            return self._users.get(user_id)
        return None

    async def update_user(self, user_id: str, updates: dict[str, Any]) -> None:
        """Update user data."""
        if user_id not in self._users:
            raise ValueError(f"User not found: {user_id}")
        user = self._users[user_id]
        # Update email index if email changed
        old_email = user.email
        if 'email' in updates and updates['email'] != old_email:
            if old_email:
                self._users_by_email.pop(old_email.lower(), None)
            if updates['email']:
                self._users_by_email[updates['email'].lower()] = user_id
        # Update phone index if phone changed
        old_phone = getattr(user, 'phone', None)
        if 'phone' in updates and updates['phone'] != old_phone:
            if old_phone:
                self._users_by_phone.pop(old_phone, None)
            if updates['phone']:
                self._users_by_phone[updates['phone']] = user_id
        # Update provider index if linked_accounts changed
        if 'linked_accounts' in updates or 'attributes' in updates:
            # Remove old provider indexes for this user
            keys_to_remove = [k for k, v in self._users_by_provider.items() if v == user_id]
            for key in keys_to_remove:
                self._users_by_provider.pop(key, None)
            # Add new provider indexes
            final_attributes = user.attributes.copy()
            final_attributes.update(updates.get('attributes', {}))
            if 'linked_accounts' in updates:
                final_attributes['linked_accounts'] = updates['linked_accounts']
            linked_accounts = final_attributes.get('linked_accounts', {})
            for provider, account_data in linked_accounts.items():
                if isinstance(account_data, dict):
                    provider_user_id = account_data.get('provider_user_id')
                    if provider_user_id:
                        self._users_by_provider[(provider, provider_user_id)] = user_id
        # Update user attributes
        for key, value in updates.items():
            if hasattr(user, key):
                setattr(user, key, value)
            else:
                user.attributes[key] = value
        logger.debug(f"Updated user: {user_id}")

    async def delete_user(self, user_id: str) -> None:
        """Delete user from storage."""
        if user_id not in self._users:
            return
        user = self._users[user_id]
        # Remove from email index
        if user.email:
            self._users_by_email.pop(user.email.lower(), None)
        # Remove user
        del self._users[user_id]
        logger.debug(f"Deleted user: {user_id}")

    async def list_users(self, filters: dict[str, Any] | None = None) -> list[User]:
        """List users with optional filters."""
        users = list(self._users.values())
        if filters:
            filtered = []
            for user in users:
                match = True
                for key, value in filters.items():
                    if key == 'email' and user.email != value:
                        match = False
                        break
                    elif hasattr(user, key) and getattr(user, key) != value:
                        match = False
                        break
                    elif key in user.attributes and user.attributes[key] != value:
                        match = False
                        break
                if match:
                    filtered.append(user)
            return filtered
        return users
    # ==========================================================================
    # SESSION OPERATIONS
    # ==========================================================================

    async def save_session(self, session: Session) -> None:
        """Save session to storage."""
        if not isinstance(session, MockSession):
            # Convert protocol to mock implementation
            mock_session = MockSession(
                id=session.id,
                user_id=session.user_id,
                expires_at=session.expires_at,
                attributes=session.attributes.copy() if hasattr(session, 'attributes') else {}
            )
        else:
            mock_session = session
        self._sessions[mock_session.id] = mock_session
        # Index by user
        if mock_session.user_id not in self._sessions_by_user:
            self._sessions_by_user[mock_session.user_id] = []
        if mock_session.id not in self._sessions_by_user[mock_session.user_id]:
            self._sessions_by_user[mock_session.user_id].append(mock_session.id)
        logger.debug(f"Saved session: {mock_session.id}")

    async def get_session(self, session_id: str) -> Session | None:
        """Get session by ID."""
        return self._sessions.get(session_id)

    async def delete_session(self, session_id: str) -> None:
        """Delete session from storage."""
        if session_id not in self._sessions:
            return
        session = self._sessions[session_id]
        # Remove from user index
        if session.user_id in self._sessions_by_user:
            self._sessions_by_user[session.user_id] = [
                sid for sid in self._sessions_by_user[session.user_id]
                if sid != session_id
            ]
            if not self._sessions_by_user[session.user_id]:
                del self._sessions_by_user[session.user_id]
        # Remove session
        del self._sessions[session_id]
        logger.debug(f"Deleted session: {session_id}")

    async def list_user_sessions(self, user_id: str) -> list[Session]:
        """List all sessions for a user."""
        session_ids = self._sessions_by_user.get(user_id, [])
        return [self._sessions[sid] for sid in session_ids if sid in self._sessions]
    # ==========================================================================
    # TOKEN OPERATIONS
    # ==========================================================================

    async def save_token(self, token: Token) -> None:
        """Save token to storage."""
        if not isinstance(token, MockToken):
            # Convert protocol to mock implementation
            mock_token = MockToken(
                id=token.id,
                user_id=token.user_id,
                client_id=token.client_id,
                token_type=token.token_type,
                access_token=token.access_token,
                refresh_token=token.refresh_token,
                expires_at=token.expires_at,
                scopes=token.scopes.copy() if hasattr(token, 'scopes') else [],
                attributes=token.attributes.copy() if hasattr(token, 'attributes') else {}
            )
        else:
            mock_token = token
        self._tokens[mock_token.id] = mock_token
        # Index by access token
        self._tokens_by_access[mock_token.access_token] = mock_token.id
        # Index by refresh token
        if mock_token.refresh_token:
            self._tokens_by_refresh[mock_token.refresh_token] = mock_token.id
        # Index by user
        if mock_token.user_id:
            if mock_token.user_id not in self._tokens_by_user:
                self._tokens_by_user[mock_token.user_id] = []
            if mock_token.id not in self._tokens_by_user[mock_token.user_id]:
                self._tokens_by_user[mock_token.user_id].append(mock_token.id)
        logger.debug(f"Saved token: {mock_token.id}")

    async def get_token(self, token_id: str) -> Token | None:
        """Get token by ID."""
        return self._tokens.get(token_id)

    async def get_token_by_access_token(self, access_token: str) -> Token | None:
        """Get token by access token string."""
        token_id = self._tokens_by_access.get(access_token)
        if token_id:
            return self._tokens.get(token_id)
        return None

    async def get_token_by_refresh_token(self, refresh_token: str) -> Token | None:
        """Get token by refresh token string."""
        token_id = self._tokens_by_refresh.get(refresh_token)
        if token_id:
            return self._tokens.get(token_id)
        return None

    async def delete_token(self, token_id: str) -> None:
        """Delete token from storage."""
        if token_id not in self._tokens:
            return
        token = self._tokens[token_id]
        # Remove from access token index
        self._tokens_by_access.pop(token.access_token, None)
        # Remove from refresh token index
        if token.refresh_token:
            self._tokens_by_refresh.pop(token.refresh_token, None)
        # Remove from user index
        if token.user_id and token.user_id in self._tokens_by_user:
            self._tokens_by_user[token.user_id] = [
                tid for tid in self._tokens_by_user[token.user_id]
                if tid != token_id
            ]
            if not self._tokens_by_user[token.user_id]:
                del self._tokens_by_user[token.user_id]
        # Remove token
        del self._tokens[token_id]
        logger.debug(f"Deleted token: {token_id}")

    async def list_user_tokens(self, user_id: str) -> list[Token]:
        """List all tokens for a user."""
        token_ids = self._tokens_by_user.get(user_id, [])
        return [self._tokens[tid] for tid in token_ids if tid in self._tokens]
    # ==========================================================================
    # AUDIT LOG OPERATIONS
    # ==========================================================================

    async def save_audit_log(self, log: AuditLog) -> None:
        """Save audit log entry to storage."""
        existing_ids = {entry.id for entry in self._audit_logs}
        if log.id in existing_ids:
            raise ValueError(f"Audit log with id '{log.id}' already exists")
        if not isinstance(log, MockAuditLog):
            # Convert protocol to mock implementation
            mock_log = MockAuditLog(
                id=log.id,
                user_id=log.user_id,
                action=log.action,
                timestamp=log.timestamp,
                resource=log.resource if hasattr(log, 'resource') else None,
                attributes=log.attributes.copy() if hasattr(log, 'attributes') else {},
                context=log.context.copy() if hasattr(log, 'context') else {},
            )
        else:
            mock_log = MockAuditLog(
                id=log.id,
                user_id=log.user_id,
                action=log.action,
                timestamp=log.timestamp,
                resource=log.resource,
                attributes=log.attributes.copy(),
                context=log.context.copy(),
            )
        self._audit_logs.append(mock_log)
        logger.debug(f"Saved audit log: {mock_log.id} - {mock_log.action}")

    async def get_audit_logs(self, filters: dict[str, Any] | None = None) -> list[AuditLog]:
        """Get audit logs with optional filters."""
        logs = list(self._audit_logs)
        if filters:
            filtered = []
            for log in logs:
                match = True
                for key, value in filters.items():
                    if hasattr(log, key):
                        if getattr(log, key) != value:
                            match = False
                            break
                        continue
                    if key in log.attributes:
                        if log.attributes[key] != value:
                            match = False
                            break
                        continue
                    match = False
                    break
                if match:
                    filtered.append(log)
            return filtered
        return logs
    # ==========================================================================
    # AUTHORIZATION CODE OPERATIONS
    # ==========================================================================

    async def save_authorization_code(self, code: AuthorizationCode) -> None:
        """Save authorization code to storage."""
        if not isinstance(code, MockAuthorizationCode):
            # Convert protocol to mock implementation
            mock_code = MockAuthorizationCode(
                code=code.code,
                client_id=code.client_id,
                redirect_uri=code.redirect_uri,
                scopes=code.scopes.copy() if hasattr(code, 'scopes') else [],
                code_challenge=code.code_challenge if hasattr(code, 'code_challenge') else None,
                code_challenge_method=code.code_challenge_method if hasattr(code, 'code_challenge_method') else None,
                expires_at=code.expires_at,
                created_at=code.created_at if hasattr(code, 'created_at') else datetime.now(),
                user_id=code.user_id if hasattr(code, 'user_id') else None,
                attributes=code.attributes.copy() if hasattr(code, 'attributes') else {}
            )
        else:
            mock_code = code
        self._authorization_codes[mock_code.code] = mock_code
        logger.debug(f"Saved authorization code: {mock_code.code}")

    async def get_authorization_code(self, code: str) -> AuthorizationCode | None:
        """Get authorization code by code string."""
        return self._authorization_codes.get(code)

    async def delete_authorization_code(self, code: str) -> None:
        """Delete authorization code from storage."""
        if code in self._authorization_codes:
            del self._authorization_codes[code]
            logger.debug(f"Deleted authorization code: {code}")
    # ==========================================================================
    # DEVICE CODE OPERATIONS
    # ==========================================================================

    async def save_device_code(self, device_code: DeviceCode) -> None:
        """Save device code to storage."""
        if not isinstance(device_code, MockDeviceCode):
            # Convert protocol to mock implementation
            mock_device_code = MockDeviceCode(
                device_code=device_code.device_code,
                user_code=device_code.user_code,
                client_id=device_code.client_id,
                scopes=device_code.scopes.copy() if hasattr(device_code, 'scopes') else [],
                expires_at=device_code.expires_at,
                created_at=device_code.created_at if hasattr(device_code, 'created_at') else datetime.now(),
                status=device_code.status if hasattr(device_code, 'status') else "pending",
                user_id=device_code.user_id if hasattr(device_code, 'user_id') else None,
                attributes=device_code.attributes.copy() if hasattr(device_code, 'attributes') else {}
            )
        else:
            mock_device_code = device_code
        self._device_codes[mock_device_code.device_code] = mock_device_code
        # Index by user code
        self._device_codes_by_user_code[mock_device_code.user_code] = mock_device_code.device_code
        logger.debug(f"Saved device code: {mock_device_code.device_code}")

    async def get_device_code(self, device_code: str) -> DeviceCode | None:
        """Get device code by device code string."""
        return self._device_codes.get(device_code)

    async def get_device_code_by_user_code(self, user_code: str) -> DeviceCode | None:
        """Get device code by user code string."""
        device_code = self._device_codes_by_user_code.get(user_code)
        if device_code:
            return self._device_codes.get(device_code)
        return None

    async def update_device_code_status(
        self,
        device_code: str,
        status: str,
        user_id: str | None = None
    ) -> None:
        """Update device code status."""
        if device_code not in self._device_codes:
            raise ValueError(f"Device code not found: {device_code}")
        mock_device_code = self._device_codes[device_code]
        mock_device_code.status = status
        if user_id is not None:
            mock_device_code.user_id = user_id
        logger.debug(f"Updated device code status: {device_code} -> {status}")

    async def delete_device_code(self, device_code: str) -> None:
        """Delete device code from storage."""
        if device_code not in self._device_codes:
            return
        mock_device_code = self._device_codes[device_code]
        # Remove from user code index
        self._device_codes_by_user_code.pop(mock_device_code.user_code, None)
        # Remove device code
        del self._device_codes[device_code]
        logger.debug(f"Deleted device code: {device_code}")
