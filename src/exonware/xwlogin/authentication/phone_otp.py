#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/authentication/phone_otp.py
Phone OTP Authentication
Phone number OTP (One-Time Password) authentication.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 20-Dec-2025
"""

from typing import Optional
from datetime import datetime, timedelta
import random
from exonware.xwsystem import get_logger
from exonware.xwlogin.auth_connector import (
    ABaseAuth,
    ABaseAuthenticator,
    IAuthenticator,
    XWAuthenticationError,
    XWInvalidCredentialsError,
)
logger = get_logger(__name__)


class PhoneOTPAuthenticator(ABaseAuthenticator, IAuthenticator):
    """
    Phone OTP authentication implementation.
    Generates and validates OTP codes sent via SMS.
    """

    def __init__(self, auth: ABaseAuth, otp_length: int = 6, otp_lifetime: int = 300):
        """
        Initialize phone OTP authenticator.
        Args:
            auth: XWAuth instance
            otp_length: OTP code length (default: 6)
            otp_lifetime: OTP lifetime in seconds (default: 5 minutes)
        """
        super().__init__(auth.storage if hasattr(auth, 'storage') else None)
        self._auth = auth
        self._config = auth.config
        self._otp_length = otp_length
        self._otp_lifetime = otp_lifetime
        self._otps: dict[str, dict] = {}  # phone -> {code, expires_at, attempts}
        logger.debug("PhoneOTPAuthenticator initialized")

    async def generate_otp(self, phone_number: str) -> str:
        """
        Generate OTP code for phone number.
        Args:
            phone_number: Phone number
        Returns:
            OTP code string
        """
        # Generate random OTP
        otp = ''.join([str(random.randint(0, 9)) for _ in range(self._otp_length)])
        # Store OTP
        self._otps[phone_number] = {
            'code': otp,
            'expires_at': datetime.now() + timedelta(seconds=self._otp_lifetime),
            'attempts': 0
        }
        logger.debug(f"Generated OTP for: {phone_number}")
        return otp

    async def authenticate(self, credentials: dict) -> Optional[str]:
        """
        Authenticate user with phone number and OTP.
        Args:
            credentials: Dictionary with 'phone_number' and 'otp' keys
        Returns:
            User ID if authenticated, None otherwise
        Raises:
            XWInvalidCredentialsError: If OTP is invalid
        """
        phone_number = credentials.get('phone_number')
        otp = credentials.get('otp')
        if not phone_number or not otp:
            raise XWInvalidCredentialsError(
                "Phone number and OTP are required",
                error_code="missing_credentials"
            )
        # Get OTP data
        otp_data = self._otps.get(phone_number)
        if not otp_data:
            raise XWInvalidCredentialsError(
                "OTP not found or expired",
                error_code="otp_not_found"
            )
        # Check if expired
        if datetime.now() > otp_data['expires_at']:
            del self._otps[phone_number]
            raise XWInvalidCredentialsError(
                "OTP has expired",
                error_code="otp_expired"
            )
        # Check attempts (prevent brute force)
        if otp_data['attempts'] >= 3:
            del self._otps[phone_number]
            raise XWInvalidCredentialsError(
                "Too many failed attempts",
                error_code="too_many_attempts"
            )
        # Verify OTP
        if otp != otp_data['code']:
            otp_data['attempts'] += 1
            raise XWInvalidCredentialsError(
                "Invalid OTP",
                error_code="invalid_otp"
            )
        # OTP verified, remove it
        del self._otps[phone_number]
        # Get user by phone number
        user = await self._storage.get_user_by_phone(phone_number)
        if not user:
            # User doesn't exist yet - could create anonymous user or return None
            # For now, return None (user must be created separately or via registration)
            logger.debug(f"OTP verified for: {phone_number}, but user not found")
            return None
        logger.debug(f"OTP verified and authenticated user: {user.id}")
        return user.id
