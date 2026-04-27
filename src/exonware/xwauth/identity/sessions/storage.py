#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/sessions/storage.py

Session Storage

Session storage via IStorageProvider interface.

Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from datetime import datetime

from exonware.xwsystem import get_logger

from exonware.xwauth.identity.storage.interface import IStorageProvider
from .session import Session

logger = get_logger(__name__)


class SessionStorage:
    """
    Session storage implementation.
    
    Manages session persistence via IStorageProvider.
    """
    
    def __init__(self, storage: IStorageProvider):
        """
        Initialize session storage.
        
        Args:
            storage: Storage provider
        """
        self._storage = storage
        logger.debug("SessionStorage initialized")
    
    async def save_session(self, session: Session) -> None:
        """
        Save session to storage.
        
        Args:
            session: Session object
        """
        from ..storage.mock import MockSession
        
        # Convert to mock session for storage
        mock_session = MockSession(
            id=session.id,
            user_id=session.user_id,
            expires_at=session.expires_at,
            attributes={
                'status': session.status.value,
                'csrf_token': session.csrf_token,
                'created_at': session.created_at.isoformat(),
                'last_accessed_at': session.last_accessed_at.isoformat(),
                **session.attributes
            }
        )
        
        await self._storage.save_session(mock_session)
        logger.debug(f"Saved session: {session.id}")
    
    async def get_session(self, session_id: str) -> Session | None:
        """
        Get session from storage.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session object or None
        """
        session_obj = await self._storage.get_session(session_id)
        if not session_obj:
            return None
        
        # Convert from storage format to Session
        from exonware.xwauth.identity.defs import SessionStatus
        
        attributes = session_obj.attributes if hasattr(session_obj, 'attributes') else {}
        status_str = attributes.get('status', 'active')
        
        try:
            status = SessionStatus(status_str)
        except ValueError:
            status = SessionStatus.ACTIVE
        
        session = Session(
            id=session_obj.id,
            user_id=session_obj.user_id,
            expires_at=session_obj.expires_at,
            status=status,
            csrf_token=attributes.get('csrf_token'),
            attributes={k: v for k, v in attributes.items() if k not in ['status', 'csrf_token', 'created_at', 'last_accessed_at']},
            created_at=datetime.fromisoformat(attributes.get('created_at', datetime.now().isoformat())),
            last_accessed_at=datetime.fromisoformat(attributes.get('last_accessed_at', datetime.now().isoformat()))
        )
        
        return session
    
    async def delete_session(self, session_id: str) -> None:
        """
        Delete session from storage.
        
        Args:
            session_id: Session identifier
        """
        await self._storage.delete_session(session_id)
        logger.debug(f"Deleted session: {session_id}")
    
    async def list_user_sessions(self, user_id: str) -> list[Session]:
        """
        List all sessions for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of Session objects
        """
        session_objs = await self._storage.list_user_sessions(user_id)
        
        sessions = []
        for session_obj in session_objs:
            session = await self._convert_storage_to_session(session_obj)
            if session:
                sessions.append(session)
        
        return sessions
    
    async def _convert_storage_to_session(self, session_obj) -> Session | None:
        """Convert storage session object to Session model."""
        from exonware.xwauth.identity.defs import SessionStatus
        
        attributes = session_obj.attributes if hasattr(session_obj, 'attributes') else {}
        status_str = attributes.get('status', 'active')
        
        try:
            status = SessionStatus(status_str)
        except ValueError:
            status = SessionStatus.ACTIVE
        
        return Session(
            id=session_obj.id,
            user_id=session_obj.user_id,
            expires_at=session_obj.expires_at,
            status=status,
            csrf_token=attributes.get('csrf_token'),
            attributes={k: v for k, v in attributes.items() if k not in ['status', 'csrf_token', 'created_at', 'last_accessed_at']},
            created_at=datetime.fromisoformat(attributes.get('created_at', datetime.now().isoformat())),
            last_accessed_at=datetime.fromisoformat(attributes.get('last_accessed_at', datetime.now().isoformat()))
        )
