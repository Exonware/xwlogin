#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/authentication/anonymous.py
Anonymous Authentication
Anonymous user authentication for guest access.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 20-Dec-2025
"""

from typing import Optional
import uuid
from exonware.xwsystem import get_logger
from exonware.xwlogin.auth_connector import (
    ABaseAuth,
    ABaseAuthenticator,
    IAuthenticator,
    User,
    UserStatus,
    XWAuthenticationError,
)
logger = get_logger(__name__)


class AnonymousAuthenticator(ABaseAuthenticator, IAuthenticator):
    """
    Anonymous authentication implementation.
    Creates temporary anonymous users for guest access.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize anonymous authenticator.
        Args:
            auth: XWAuth instance
        """
        super().__init__(auth.storage if hasattr(auth, 'storage') else None)
        self._auth = auth
        self._config = auth.config
        logger.debug("AnonymousAuthenticator initialized")

    async def authenticate(self, credentials: dict) -> Optional[str]:
        """
        Authenticate as anonymous user.
        Creates a temporary anonymous user if needed.
        Args:
            credentials: Empty dictionary (no credentials needed)
        Returns:
            Anonymous user ID
        """
        # Generate anonymous user ID
        anonymous_id = f"anonymous_{uuid.uuid4().hex[:16]}"
        # Check if anonymous user already exists (unlikely but possible)
        existing_user = await self._storage.get_user(anonymous_id)
        if existing_user:
            logger.debug(f"Anonymous user already exists: {anonymous_id}")
            return anonymous_id
        # Create anonymous user in storage
        anonymous_user = User(
            id=anonymous_id,
            email=None,  # Anonymous users don't have email
            password_hash=None,  # Anonymous users don't have password
            status=UserStatus.ACTIVE,
            attributes={
                'is_anonymous': True,
                'created_via': 'anonymous_authentication'
            }
        )
        # Save to storage
        await self._storage.save_user(anonymous_user)
        logger.debug(f"Created and authenticated anonymous user: {anonymous_id}")
        return anonymous_id
