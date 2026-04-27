#!/usr/bin/env python3

"""

#exonware/xwauth.connector/tests/1.unit/authentication_tests/test_account_linking.py

Unit tests for account linking.

Company: eXonware.com

Author: eXonware Backend Team

Email: connect@exonware.com

Version: 0.0.1.0

Generation Date: 20-Dec-2025

"""



import pytest

from exonware.xwauth.identity.errors import XWUserError
from exonware.xwauth.identity.authentication.account_linking import AccountLinking

from exonware.xwauth.identity.config.config import XWAuthConfig

from exonware.xwauth.identity.facade import XWAuth

from exonware.xwauth.identity.storage.mock import MockUser
from exonware.xwsystem.security.crypto import hash_password

@pytest.mark.xwlogin_unit



class TestAccountLinking:

    """Test AccountLinking implementation."""

    @pytest.fixture



    def auth(self):

        """Create XWAuth instance."""

        config = XWAuthConfig(jwt_secret="test-secret-key", allow_mock_storage_fallback=True)

        return XWAuth(config=config)

    @pytest.fixture



    def linker(self, auth):

        """Create AccountLinking instance."""

        return AccountLinking(auth)

    @pytest.mark.asyncio



    async def test_link_account(self, linker, auth):

        """Test linking provider account to user."""

        user = MockUser(id="user1", email="user1@example.com", attributes={})

        await auth.storage.save_user(user)

        await linker.link_account(

            primary_user_id="user1",

            provider="google",

            provider_user_id="google_user_123",

            provider_data={"email": "google@example.com"}

        )

        # Verify linked

        linked = await linker.get_linked_accounts("user1")

        assert "google" in linked

        assert linked["google"]["provider_user_id"] == "google_user_123"

    @pytest.mark.asyncio



    async def test_unlink_account(self, linker, auth):

        """Test unlinking provider account from user."""

        user = MockUser(id="user1", email="user1@example.com", attributes={})

        await auth.storage.save_user(user)

        # Link first

        await linker.link_account(

            primary_user_id="user1",

            provider="google",

            provider_user_id="google_user_123"

        )

        # Unlink

        await linker.unlink_account("user1", "google")

        # Verify unlinked

        linked = await linker.get_linked_accounts("user1")

        assert "google" not in linked

    @pytest.mark.asyncio



    async def test_get_linked_accounts(self, linker, auth):

        """Test getting linked accounts."""

        user = MockUser(id="user1", email="user1@example.com", attributes={})

        await auth.storage.save_user(user)

        # Link multiple providers

        await linker.link_account("user1", "google", "google_user_123")

        await linker.link_account("user1", "github", "github_user_456")

        linked = await linker.get_linked_accounts("user1")

        assert "google" in linked

        assert "github" in linked

    @pytest.mark.asyncio



    async def test_find_user_by_provider(self, linker, auth):

        """Test finding user by provider account."""

        user = MockUser(id="user1", email="user1@example.com", attributes={})

        await auth.storage.save_user(user)

        # Link provider

        await linker.link_account("user1", "google", "google_user_123")

        # Find user

        found_user_id = await linker.find_user_by_provider("google", "google_user_123")

        assert found_user_id == "user1"

    @pytest.mark.asyncio



    async def test_link_account_nonexistent_user(self, linker):

        """Test linking account to nonexistent user."""

        with pytest.raises(XWUserError):

            await linker.link_account(

                primary_user_id="nonexistent",

                provider="google",

                provider_user_id="google_user_123"

            )

    @pytest.mark.asyncio



    async def test_unlink_account_nonexistent_user(self, linker):

        """Test unlinking account from nonexistent user."""

        with pytest.raises(XWUserError):

            await linker.unlink_account("nonexistent", "google")

