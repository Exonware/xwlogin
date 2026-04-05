#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/authentication/account_linking.py
Account Linking
Account linking and merging functionality.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 20-Dec-2025
"""

from typing import Optional
from exonware.xwsystem import get_logger
from exonware.xwlogin.auth_connector import (
    ABaseAuth,
    IStorageProvider,
    XWUserAlreadyExistsError,
    XWUserError,
)
logger = get_logger(__name__)


class AccountLinking:
    """
    Account linking and merging implementation.
    Handles linking multiple authentication methods to a single user account.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize account linking.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._storage = auth.storage
        logger.debug("AccountLinking initialized")

    async def link_account(
        self,
        primary_user_id: str,
        provider: str,
        provider_user_id: str,
        provider_data: Optional[dict] = None
    ) -> None:
        """
        Link external provider account to user.
        Args:
            primary_user_id: Primary user ID
            provider: Provider name (e.g., 'google', 'github')
            provider_user_id: Provider user ID
            provider_data: Additional provider data
        """
        # Get user
        user = await self._storage.get_user(primary_user_id)
        if not user:
            raise XWUserError(
                f"User not found: {primary_user_id}",
                error_code="user_not_found"
            )
        # Store linked account info in user attributes
        linked_accounts = user.attributes.get('linked_accounts', {}) if hasattr(user, 'attributes') else {}
        linked_accounts[provider] = {
            'provider_user_id': provider_user_id,
            'provider_data': provider_data or {}
        }
        # Update user
        await self._storage.update_user(primary_user_id, {
            'linked_accounts': linked_accounts
        })
        logger.debug(f"Linked {provider} account to user: {primary_user_id}")

    async def unlink_account(self, user_id: str, provider: str) -> None:
        """
        Unlink external provider account from user.
        Args:
            user_id: User ID
            provider: Provider name
        """
        user = await self._storage.get_user(user_id)
        if not user:
            raise XWUserError(
                f"User not found: {user_id}",
                error_code="user_not_found"
            )
        linked_accounts = user.attributes.get('linked_accounts', {}) if hasattr(user, 'attributes') else {}
        if provider in linked_accounts:
            del linked_accounts[provider]
            await self._storage.update_user(user_id, {
                'linked_accounts': linked_accounts
            })
            logger.debug(f"Unlinked {provider} account from user: {user_id}")

    async def get_linked_accounts(self, user_id: str) -> dict[str, dict]:
        """
        Get all linked accounts for user.
        Args:
            user_id: User ID
        Returns:
            Dictionary of linked accounts
        """
        user = await self._storage.get_user(user_id)
        if not user:
            return {}
        return user.attributes.get('linked_accounts', {}) if hasattr(user, 'attributes') else {}

    async def find_user_by_provider(
        self,
        provider: str,
        provider_user_id: str
    ) -> Optional[str]:
        """
        Find user by provider account.
        Uses efficient indexed lookup if available, falls back to iteration.
        Args:
            provider: Provider name
            provider_user_id: Provider user ID
        Returns:
            User ID if found, None otherwise
        """
        # Try efficient indexed lookup first (if storage supports it)
        if hasattr(self._storage, 'find_user_by_provider'):
            user = await self._storage.find_user_by_provider(provider, provider_user_id)
            if user:
                return user.id
        # Fallback: iterate through users (for storages without provider index)
        users = await self._storage.list_users()
        for user in users:
            linked_accounts = user.attributes.get('linked_accounts', {}) if hasattr(user, 'attributes') else {}
            if provider in linked_accounts:
                if linked_accounts[provider].get('provider_user_id') == provider_user_id:
                    return user.id
        return None
