#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/authentication/mfa/sms.py
SMS MFA Implementation
SMS-based multi-factor authentication using OTP codes sent via SMS.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 25-Jan-2026
"""

from typing import Optional
from datetime import datetime, timedelta
import random
from exonware.xwsystem import get_logger
from exonware.xwlogin.auth_connector import (
    ABaseAuth,
    IStorageProvider,
    XWAuthenticationError,
    XWInvalidCredentialsError,
)
logger = get_logger(__name__)


class SMSMFA:
    """
    SMS-based MFA implementation.
    Sends OTP codes via SMS for multi-factor authentication.
    """

    def __init__(self, auth: ABaseAuth, otp_length: int = 6, otp_lifetime: int = 300):
        """
        Initialize SMS MFA.
        Args:
            auth: XWAuth instance
            otp_length: OTP code length (default: 6)
            otp_lifetime: OTP lifetime in seconds (default: 5 minutes)
        """
        self._auth = auth
        self._storage = auth.storage
        self._config = auth.config
        self._otp_length = otp_length
        self._otp_lifetime = otp_lifetime
        # Temporary OTP storage (should use storage abstraction in production)
        self._otps: dict[str, dict] = {}  # user_id -> {code, expires_at, attempts}
        logger.debug("SMSMFA initialized")

    async def send_otp(self, user_id: str) -> str:
        """
        Send SMS OTP to user's phone number.
        Args:
            user_id: User identifier
        Returns:
            OTP code (for testing - in production, code is sent via SMS)
        """
        # Get user
        user = await self._storage.get_user(user_id)
        if not user:
            raise XWAuthenticationError(
                "User not found",
                error_code="user_not_found"
            )
        # Get phone number from user
        phone = getattr(user, 'phone', None) or (user.attributes.get('phone') if hasattr(user, 'attributes') else None)
        if not phone:
            raise XWAuthenticationError(
                "User has no phone number",
                error_code="no_phone_number",
                suggestions=["User must have a phone number to use SMS MFA"]
            )
        # Generate OTP
        otp_code = ''.join([str(random.randint(0, 9)) for _ in range(self._otp_length)])
        # Store OTP
        self._otps[user_id] = {
            'code': otp_code,
            'expires_at': datetime.now() + timedelta(seconds=self._otp_lifetime),
            'attempts': 0,
            'phone': phone
        }
        # TODO: Send SMS via SMS provider (format-agnostic SMS service)
        # For now, just log (in production, integrate with SMS service)
        logger.info(f"SMS OTP generated for user {user_id} to {phone}: {otp_code}")
        logger.warning("SMS not actually sent - integrate with SMS service in production")
        return otp_code  # Return for testing - remove in production

    async def verify_otp(self, user_id: str, otp_code: str) -> bool:
        """
        Verify SMS OTP code.
        Args:
            user_id: User identifier
            otp_code: OTP code to verify
        Returns:
            True if code is valid, False otherwise
        """
        # Get stored OTP
        otp_data = self._otps.get(user_id)
        if not otp_data:
            raise XWInvalidCredentialsError(
                "OTP not found or expired",
                error_code="otp_not_found"
            )
        # Check if expired
        if datetime.now() > otp_data['expires_at']:
            del self._otps[user_id]
            raise XWInvalidCredentialsError(
                "OTP has expired",
                error_code="otp_expired"
            )
        # Check attempts (prevent brute force)
        if otp_data['attempts'] >= 3:
            del self._otps[user_id]
            raise XWInvalidCredentialsError(
                "Too many failed attempts",
                error_code="too_many_attempts"
            )
        # Verify OTP
        if otp_code != otp_data['code']:
            otp_data['attempts'] += 1
            raise XWInvalidCredentialsError(
                "Invalid OTP code",
                error_code="invalid_otp"
            )
        # OTP verified, remove it
        del self._otps[user_id]
        logger.debug(f"SMS OTP verified successfully for user: {user_id}")
        return True

    async def is_enabled(self, user_id: str) -> bool:
        """
        Check if SMS MFA is enabled for user.
        Args:
            user_id: User identifier
        Returns:
            True if SMS MFA is enabled, False otherwise
        """
        user = await self._storage.get_user(user_id)
        if not user:
            return False
        user_attrs = user.attributes if hasattr(user, 'attributes') else {}
        return user_attrs.get('mfa_sms_enabled', False) and (getattr(user, 'phone', None) or user_attrs.get('phone'))

    async def enable_sms_mfa(self, user_id: str) -> None:
        """
        Enable SMS MFA for user.
        Args:
            user_id: User identifier
        """
        user = await self._storage.get_user(user_id)
        if not user:
            raise XWAuthenticationError(
                "User not found",
                error_code="user_not_found"
            )
        # Check if user has phone number
        phone = getattr(user, 'phone', None) or (user.attributes.get('phone') if hasattr(user, 'attributes') else None)
        if not phone:
            raise XWAuthenticationError(
                "User must have a phone number to enable SMS MFA",
                error_code="no_phone_number"
            )
        user_attrs = user.attributes.copy() if hasattr(user, 'attributes') else {}
        user_attrs['mfa_sms_enabled'] = True
        await self._storage.update_user(user_id, {'attributes': user_attrs})
        logger.debug(f"SMS MFA enabled for user: {user_id}")

    async def disable_sms_mfa(self, user_id: str) -> None:
        """
        Disable SMS MFA for user.
        Args:
            user_id: User identifier
        """
        user = await self._storage.get_user(user_id)
        if not user:
            raise XWAuthenticationError(
                "User not found",
                error_code="user_not_found"
            )
        user_attrs = user.attributes.copy() if hasattr(user, 'attributes') else {}
        user_attrs['mfa_sms_enabled'] = False
        await self._storage.update_user(user_id, {'attributes': user_attrs})
        logger.debug(f"SMS MFA disabled for user: {user_id}")
