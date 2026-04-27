#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/sessions/manager.py

Session Manager

Session lifecycle management with CSRF protection and concurrent session limits.

Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any
from datetime import datetime, timedelta
import uuid

from exonware.xwsystem import get_logger

from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.defs import SessionStatus
from exonware.xwauth.identity.errors import XWSessionError, XWSessionExpiredError
from exonware.xwauth.identity.contracts import ISessionManager
from exonware.xwauth.identity.base import ABaseSessionManager
from .session import Session
from .security import SessionSecurity
from .storage import SessionStorage

logger = get_logger(__name__)


class SessionManager(ABaseSessionManager, ISessionManager):
    """
    Session manager implementation.
    
    Handles session creation, validation, revocation, and concurrent session limits.
    """
    
    def __init__(self, auth: ABaseAuth):
        """
        Initialize session manager.
        
        Args:
            auth: XWAuth instance
        """
        super().__init__(auth.storage if hasattr(auth, 'storage') else None)
        self._auth = auth
        self._config = auth.config
        self._storage = SessionStorage(self._storage)
        self._security = SessionSecurity()
        
        logger.info("SessionManager initialized")
    
    async def create_session(
        self,
        user_id: str,
        expires_in: int | None = None
    ) -> str:
        """
        Create new session.
        
        Args:
            user_id: User identifier
            expires_in: Session expiration in seconds (uses config default if None)
            
        Returns:
            Session ID
        """
        # Check concurrent session limits
        if self._config.max_concurrent_sessions:
            await self._enforce_concurrent_limit(user_id)
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Generate CSRF token if enabled
        csrf_token = None
        if self._config.enable_csrf:
            csrf_token = self._security.generate_csrf_token()
        
        # Set expiration
        expires_in = expires_in or self._config.session_timeout
        expires_at = datetime.now() + timedelta(seconds=expires_in)
        
        # Create session
        session = Session(
            id=session_id,
            user_id=user_id,
            expires_at=expires_at,
            status=SessionStatus.ACTIVE,
            csrf_token=csrf_token
        )
        
        # Save to storage
        await self._storage.save_session(session)
        
        logger.debug(f"Created session: {session_id} for user: {user_id}")
        return session_id
    
    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """
        Get session data.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session data dictionary or None
        """
        session = await self._storage.get_session(session_id)
        if not session:
            return None
        
        # Check if expired
        if session.is_expired():
            await self._storage.delete_session(session_id)
            raise XWSessionExpiredError(
                "Session has expired",
                error_code="session_expired"
            )
        
        # Update access time
        session.update_access_time()
        await self._storage.save_session(session)
        
        return {
            'id': session.id,
            'user_id': session.user_id,
            'expires_at': session.expires_at.isoformat(),
            'status': session.status.value,
            'csrf_token': session.csrf_token,
            'attributes': session.attributes,
        }
    
    async def revoke_session(self, session_id: str) -> None:
        """
        Revoke session.
        
        Args:
            session_id: Session identifier
        """
        session = await self._storage.get_session(session_id)
        if session:
            session.status = SessionStatus.REVOKED
            await self._storage.save_session(session)
            logger.debug(f"Revoked session: {session_id}")
    
    async def list_user_sessions(self, user_id: str) -> list[dict[str, Any]]:
        """
        List all active sessions for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of session dictionaries with metadata
        """
        sessions = await self._storage.list_user_sessions(user_id)
        
        result = []
        for session in sessions:
            # Only include active sessions
            if session.is_active():
                session_dict = {
                    "session_id": session.id,
                    "user_id": session.user_id,
                    "created_at": session.created_at.isoformat(),
                    "last_accessed_at": session.last_accessed_at.isoformat(),
                    "expires_at": session.expires_at.isoformat(),
                    "status": session.status.value,
                }
                
                # Add metadata from attributes
                if session.attributes:
                    metadata = session.attributes.get("metadata", {})
                    if metadata:
                        session_dict["ip_address"] = metadata.get("ip_address")
                        session_dict["user_agent"] = metadata.get("user_agent")
                        session_dict["device_info"] = metadata.get("device_info")
                
                result.append(session_dict)
        
        return result
    
    async def revoke_all_sessions_except(self, user_id: str, exclude_session_id: str) -> int:
        """
        Revoke all user sessions except the specified one.
        
        Args:
            user_id: User identifier
            exclude_session_id: Session ID to keep active
            
        Returns:
            Number of sessions revoked
        """
        sessions = await self._storage.list_user_sessions(user_id)
        
        revoked_count = 0
        for session in sessions:
            if session.id != exclude_session_id and session.is_active():
                await self.revoke_session(session.id)
                revoked_count += 1
        
        logger.debug(f"Revoked {revoked_count} sessions for user {user_id} (kept {exclude_session_id})")
        return revoked_count
    
    async def create_session_with_metadata(
        self,
        user_id: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_info: dict[str, Any] | None = None,
        expires_in: int | None = None,
    ) -> str:
        """
        Create new session with metadata.
        
        Args:
            user_id: User identifier
            ip_address: Client IP address
            user_agent: User-Agent header
            device_info: Device information dict
            expires_in: Session expiration in seconds
            
        Returns:
            Session ID
        """
        # Check concurrent session limits
        if self._config.max_concurrent_sessions:
            await self._enforce_concurrent_limit(user_id)
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Generate CSRF token if enabled
        csrf_token = None
        if self._config.enable_csrf:
            csrf_token = self._security.generate_csrf_token()
        
        # Set expiration
        expires_in = expires_in or self._config.session_timeout
        expires_at = datetime.now() + timedelta(seconds=expires_in)
        
        # Build metadata
        metadata = {}
        if ip_address:
            metadata["ip_address"] = ip_address
        if user_agent:
            metadata["user_agent"] = user_agent
        if device_info:
            metadata["device_info"] = device_info
        
        # Create session with metadata in attributes
        attributes = {}
        if metadata:
            attributes["metadata"] = metadata
        
        session = Session(
            id=session_id,
            user_id=user_id,
            expires_at=expires_at,
            status=SessionStatus.ACTIVE,
            csrf_token=csrf_token,
            attributes=attributes,
        )
        
        # Save to storage
        await self._storage.save_session(session)
        
        logger.debug(f"Created session: {session_id} for user: {user_id} with metadata")
        return session_id
    
    async def validate_csrf_token(self, session_id: str, csrf_token: str) -> bool:
        """
        Validate CSRF token for session.
        
        Args:
            session_id: Session identifier
            csrf_token: CSRF token to validate
            
        Returns:
            True if valid
            
        Raises:
            XWSessionError: If validation fails
        """
        session = await self._storage.get_session(session_id)
        if not session:
            raise XWSessionError(
                "Session not found",
                error_code="session_not_found"
            )
        
        return self._security.validate_csrf_token(csrf_token, session.csrf_token or "")
    
    async def _enforce_concurrent_limit(self, user_id: str) -> None:
        """
        Enforce concurrent session limit.
        
        Revokes oldest sessions if limit is exceeded.
        
        Args:
            user_id: User identifier
        """
        sessions = await self._storage.list_user_sessions(user_id)
        
        # Filter active sessions
        active_sessions = [s for s in sessions if s.is_active()]
        
        if len(active_sessions) >= self._config.max_concurrent_sessions:
            # Sort by last accessed time (oldest first)
            active_sessions.sort(key=lambda s: s.last_accessed_at)
            
            # Revoke oldest sessions
            to_revoke = len(active_sessions) - self._config.max_concurrent_sessions + 1
            for session in active_sessions[:to_revoke]:
                await self.revoke_session(session.id)
                logger.debug(f"Revoked session {session.id} due to concurrent limit")
