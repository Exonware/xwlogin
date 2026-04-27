#!/usr/bin/env python3

"""

#exonware/xwauth.connector/tests/1.unit/authentication_tests/test_anonymous.py

Unit tests for anonymous authentication.

Company: eXonware.com

Author: eXonware Backend Team

Email: connect@exonware.com

Version: 0.0.1.0

Generation Date: 20-Dec-2025

"""



import pytest

from exonware.xwauth.identity.config.config import XWAuthConfig

from exonware.xwauth.identity.facade import XWAuth
from exonware.xwauth.identity.authentication.anonymous import AnonymousAuthenticator

@pytest.mark.xwlogin_unit



class TestAnonymousAuthenticator:

    """Test AnonymousAuthenticator implementation."""

    @pytest.fixture



    def auth(self):

        """Create XWAuth instance."""

        config = XWAuthConfig(jwt_secret="test-secret-key", allow_mock_storage_fallback=True)

        return XWAuth(config=config)

    @pytest.fixture



    def authenticator(self, auth):

        """Create AnonymousAuthenticator instance."""

        return AnonymousAuthenticator(auth)

    @pytest.mark.asyncio



    async def test_authenticate_anonymous(self, authenticator):

        """Test anonymous authentication."""

        user_id = await authenticator.authenticate({})

        assert user_id is not None

        assert isinstance(user_id, str)

        assert len(user_id) > 0

    @pytest.mark.asyncio



    async def test_authenticate_anonymous_multiple(self, authenticator):

        """Test multiple anonymous authentications create different users."""

        user_id1 = await authenticator.authenticate({})

        user_id2 = await authenticator.authenticate({})

        assert user_id1 != user_id2

    @pytest.mark.asyncio



    async def test_authenticate_anonymous_with_metadata(self, authenticator):

        """Test anonymous authentication with metadata."""

        user_id = await authenticator.authenticate({

            'device_id': 'device123',

            'ip_address': '192.168.1.1'

        })

        assert user_id is not None

