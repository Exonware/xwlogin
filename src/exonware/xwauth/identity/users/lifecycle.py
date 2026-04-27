#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/users/lifecycle.py
User Lifecycle Management
User CRUD operations and lifecycle management.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Optional, Any
import uuid
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.errors import XWUserError, XWUserNotFoundError, XWUserAlreadyExistsError
from .user import User
logger = get_logger(__name__)


class UserLifecycle:
    """
    User lifecycle management.
    Handles user CRUD operations via IStorageProvider.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize user lifecycle manager.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._storage = auth.storage
        logger.debug("UserLifecycle initialized")

    async def create_user(
        self,
        email: str,
        password_hash: Optional[str] = None,
        attributes: Optional[dict[str, Any]] = None
    ) -> User:
        """
        Create new user.
        Args:
            email: User email
            password_hash: Optional password hash
            attributes: Optional user attributes
        Returns:
            Created user
        Raises:
            XWUserAlreadyExistsError: If user already exists
        """
        # Validate email
        if not email:
            raise XWUserError(
                "Email is required",
                error_code="invalid_email"
            )
        # Check if user exists
        existing = await self._storage.get_user_by_email(email)
        if existing:
            raise XWUserAlreadyExistsError(
                f"User with email {email} already exists",
                email=email,
                error_code="user_exists"
            )
        # Create user
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            password_hash=password_hash,
            attributes=attributes or {}
        )
        # Save to storage
        await self._storage.save_user(user)
        logger.debug(f"Created user: {user.id}")
        return user

    async def get_user(self, user_id: str) -> Optional[User]:
        """
        Get user by ID.
        Args:
            user_id: User identifier
        Returns:
            User object or None
        """
        return await self._storage.get_user(user_id)

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email.
        Args:
            email: User email
        Returns:
            User object or None
        """
        return await self._storage.get_user_by_email(email)

    async def update_user(
        self,
        user_id: str,
        updates: dict[str, Any]
    ) -> User:
        """
        Update user.
        Args:
            user_id: User identifier
            updates: Dictionary of fields to update
        Returns:
            Updated user
        Raises:
            XWUserNotFoundError: If user not found
        """
        user = await self._storage.get_user(user_id)
        if not user:
            raise XWUserNotFoundError(
                f"User not found: {user_id}",
                error_code="user_not_found"
            )
        # Update user
        await self._storage.update_user(user_id, updates)
        # Get updated user
        updated_user = await self._storage.get_user(user_id)
        logger.debug(f"Updated user: {user_id}")
        return updated_user

    async def delete_user(self, user_id: str) -> None:
        """
        Delete user.
        Args:
            user_id: User identifier
        Raises:
            XWUserNotFoundError: If user not found
        """
        user = await self._storage.get_user(user_id)
        if not user:
            raise XWUserNotFoundError(
                f"User not found: {user_id}",
                error_code="user_not_found"
            )
        await self._storage.delete_user(user_id)
        logger.debug(f"Deleted user: {user_id}")

    async def list_users(self, filters: Optional[dict[str, Any]] = None) -> list[User]:
        """
        List users with optional filters.
        Args:
            filters: Optional filter dictionary
        Returns:
            List of users
        """
        return await self._storage.list_users(filters)
