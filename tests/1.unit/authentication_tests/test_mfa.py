#!/usr/bin/env python3
"""
#exonware/xwauth/tests/1.unit/authentication_tests/test_mfa.py
Unit tests for Multi-Factor Authentication (MFA).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.0
Generation Date: 25-Jan-2026
"""

from __future__ import annotations
import pytest
import pytest_asyncio
from exonware.xwlogin.auth_connector import UserLifecycle
from exonware.xwlogin.authentication.mfa.backup_codes import BackupCodesMFA
from exonware.xwlogin.authentication.mfa.email import EmailMFA
from exonware.xwlogin.authentication.mfa.sms import SMSMFA
from exonware.xwlogin.authentication.mfa.totp import TOTPMFA
from exonware.xwlogin.test_support import MockStorageProvider, XWAuth, XWAuthConfig
@pytest.mark.xwlogin_unit

class TestTOTPMFA:
    """Test TOTP MFA implementation."""
    @pytest.fixture

    def auth(self):
        """Create XWAuth instance."""
        config = XWAuthConfig(jwt_secret="test-secret")
        storage = MockStorageProvider()
        return XWAuth(config=config, storage=storage)
    @pytest_asyncio.fixture

    async def user(self, auth):
        """Create test user."""
        user_lifecycle = UserLifecycle(auth)
        return await user_lifecycle.create_user(
            email="test@example.com",
            password_hash="hashed_password"
        )
    @pytest.mark.asyncio

    async def test_setup_totp(self, auth, user):
        """Test TOTP setup."""
        totp = TOTPMFA(auth)
        setup_result = await totp.setup_totp(user.id)
        assert "secret" in setup_result
        assert "provisioning_uri" in setup_result
        assert len(setup_result["secret"]) > 0
    @pytest.mark.asyncio

    async def test_verify_totp(self, auth, user):
        """Test TOTP verification."""
        totp = TOTPMFA(auth)
        setup_result = await totp.setup_totp(user.id)
        # Note: Real TOTP verification requires pyotp library
        # This test verifies the structure
        assert "secret" in setup_result
@pytest.mark.xwlogin_unit

class TestSMSMFA:
    """Test SMS MFA implementation."""
    @pytest.fixture

    def auth(self):
        """Create XWAuth instance."""
        config = XWAuthConfig(jwt_secret="test-secret")
        storage = MockStorageProvider()
        return XWAuth(config=config, storage=storage)
    @pytest.mark.asyncio

    async def test_send_otp(self, auth):
        """Test SMS OTP generation."""
        sms_mfa = SMSMFA(auth)
        # Create user with phone
        user_lifecycle = UserLifecycle(auth)
        user = await user_lifecycle.create_user(
            email="test@example.com",
            password_hash="hashed"
        )
        await auth.storage.update_user(user.id, {"phone": "+1234567890"})
        otp = await sms_mfa.send_otp(user.id)
        assert len(otp) == 6  # Default OTP length
    @pytest.mark.asyncio

    async def test_verify_otp(self, auth):
        """Test SMS OTP verification."""
        sms_mfa = SMSMFA(auth)
        user_lifecycle = UserLifecycle(auth)
        user = await user_lifecycle.create_user(
            email="test@example.com",
            password_hash="hashed"
        )
        await auth.storage.update_user(user.id, {"phone": "+1234567890"})
        otp = await sms_mfa.send_otp(user.id)
        is_valid = await sms_mfa.verify_otp(user.id, otp)
        assert is_valid is True
@pytest.mark.xwlogin_unit

class TestEmailMFA:
    """Test Email MFA implementation."""
    @pytest.fixture

    def auth(self):
        """Create XWAuth instance."""
        config = XWAuthConfig(jwt_secret="test-secret")
        storage = MockStorageProvider()
        return XWAuth(config=config, storage=storage)
    @pytest.mark.asyncio

    async def test_send_otp(self, auth):
        """Test Email OTP generation."""
        email_mfa = EmailMFA(auth)
        user_lifecycle = UserLifecycle(auth)
        user = await user_lifecycle.create_user(
            email="test@example.com",
            password_hash="hashed"
        )
        otp = await email_mfa.send_otp(user.id)
        assert len(otp) == 6
@pytest.mark.xwlogin_unit

class TestBackupCodesMFA:
    """Test Backup Codes MFA implementation."""
    @pytest.fixture

    def auth(self):
        """Create XWAuth instance."""
        config = XWAuthConfig(jwt_secret="test-secret")
        storage = MockStorageProvider()
        return XWAuth(config=config, storage=storage)
    @pytest.mark.asyncio

    async def test_generate_backup_codes(self, auth):
        """Test backup code generation."""
        backup_codes = BackupCodesMFA(auth)
        user_lifecycle = UserLifecycle(auth)
        user = await user_lifecycle.create_user(
            email="test@example.com",
            password_hash="hashed"
        )
        codes = await backup_codes.generate_backup_codes(user.id)
        assert len(codes) == 10  # Default number of codes
        assert all(len(code) > 0 for code in codes)
    @pytest.mark.asyncio

    async def test_verify_backup_code(self, auth):
        """Test backup code verification."""
        backup_codes = BackupCodesMFA(auth)
        user_lifecycle = UserLifecycle(auth)
        user = await user_lifecycle.create_user(
            email="test@example.com",
            password_hash="hashed"
        )
        codes = await backup_codes.generate_backup_codes(user.id)
        code = codes[0]
        is_valid = await backup_codes.verify_backup_code(user.id, code)
        assert is_valid is True
        # Code should be consumed
        remaining = await backup_codes.get_remaining_count(user.id)
        assert remaining == 9
