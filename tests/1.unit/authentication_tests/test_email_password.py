#!/usr/bin/env python3
"""
#exonware/xwauth/tests/1.unit/authentication_tests/test_email_password.py
Unit tests for email/password authentication.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.0
Generation Date: 20-Dec-2025
"""

import pytest
from exonware.xwlogin.auth_connector import XWInvalidCredentialsError
from exonware.xwlogin.authentication.email_password import EmailPasswordAuthenticator
from exonware.xwlogin.test_support import MockStorageProvider, MockUser, XWAuth, XWAuthConfig
@pytest.mark.xwlogin_unit

class TestEmailPasswordAuthenticator:
    """Test EmailPasswordAuthenticator implementation."""
    @pytest.fixture

    def auth(self):
        """Create XWAuth instance."""
        config = XWAuthConfig(jwt_secret="test-secret-key")
        return XWAuth(config=config)
    @pytest.fixture

    def authenticator(self, auth):
        """Create EmailPasswordAuthenticator instance."""
        return EmailPasswordAuthenticator(auth)
    @pytest.fixture

    def test_user(self, auth):
        """Create test user."""
        import asyncio
        from exonware.xwsystem.security.crypto import hash_password
        user = MockUser(
            id="user123",
            email="test@example.com",
            password_hash=hash_password("testpassword123")
        )
        # Save user synchronously in fixture
        asyncio.run(auth.storage.save_user(user))
        return user
    @pytest.mark.asyncio

    async def test_authenticate_success(self, authenticator, test_user):
        """Test successful authentication."""
        user_id = await authenticator.authenticate({
            'email': 'test@example.com',
            'password': 'testpassword123'
        })
        assert user_id == 'user123'
    @pytest.mark.asyncio

    async def test_authenticate_invalid_password(self, authenticator, test_user):
        """Test authentication with invalid password."""
        with pytest.raises(XWInvalidCredentialsError):
            await authenticator.authenticate({
                'email': 'test@example.com',
                'password': 'wrongpassword'
            })
    @pytest.mark.asyncio

    async def test_authenticate_invalid_email(self, authenticator):
        """Test authentication with invalid email."""
        with pytest.raises(XWInvalidCredentialsError):
            await authenticator.authenticate({
                'email': 'nonexistent@example.com',
                'password': 'testpassword123'
            })
    @pytest.mark.asyncio

    async def test_authenticate_missing_credentials(self, authenticator):
        """Test authentication with missing credentials."""
        with pytest.raises(XWInvalidCredentialsError):
            await authenticator.authenticate({
                'email': 'test@example.com'
                # Missing password
            })
    @pytest.mark.asyncio

    async def test_hash_password(self, authenticator):
        """Test password hashing."""
        hashed = await authenticator.hash_password("testpassword123")
        assert hashed is not None
        assert isinstance(hashed, str)
        assert hashed != "testpassword123"  # Should be hashed
