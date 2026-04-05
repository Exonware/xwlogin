#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/authentication/mfa/totp.py
TOTP MFA Implementation
Time-based One-Time Password (TOTP) multi-factor authentication.
Uses RFC 6238 TOTP algorithm.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from typing import Optional
import base64
from exonware.xwsystem import get_logger
from exonware.xwlogin.auth_connector import (
    ABaseAuth,
    IStorageProvider,
    XWAuthenticationError,
    XWInvalidCredentialsError,
)
logger = get_logger(__name__)
# Try to import pyotp
try:
    import pyotp
    USE_PYOTP = True
except ImportError:
    USE_PYOTP = False
    logger.warning("pyotp library not installed. TOTP MFA will not be available.")


class TOTPMFA:
    """
    TOTP (Time-based One-Time Password) MFA implementation.
    Generates and validates TOTP codes using RFC 6238.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize TOTP MFA.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._storage = auth.storage
        self._config = auth.config
        if not USE_PYOTP:
            logger.warning("TOTP MFA requires pyotp library. Install with: pip install pyotp")
        logger.debug("TOTPMFA initialized")

    async def setup_totp(self, user_id: str, issuer: Optional[str] = None) -> dict[str, str]:
        """
        Setup TOTP for user.
        Generates a TOTP secret and returns provisioning URI for authenticator app.
        Args:
            user_id: User identifier
            issuer: Issuer name (default: from config or "xwauth")
        Returns:
            Dictionary with secret, provisioning_uri, and QR code data
        """
        if not USE_PYOTP:
            raise XWAuthenticationError(
                "TOTP library not installed",
                error_code="totp_not_available",
                suggestions=["Install pyotp: pip install pyotp"]
            )
        # Get user
        user = await self._storage.get_user(user_id)
        if not user:
            raise XWAuthenticationError(
                "User not found",
                error_code="user_not_found"
            )
        # Generate TOTP secret
        totp_secret = pyotp.random_base32()
        # Get user email for provisioning URI
        user_email = user.email or f"user_{user_id}"
        issuer_name = issuer or getattr(self._config, "totp_issuer", "xwauth")
        # Create TOTP instance
        totp = pyotp.TOTP(totp_secret)
        # Generate provisioning URI
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name=issuer_name
        )
        # Store secret in user attributes (should be encrypted in production)
        user_attrs = user.attributes.copy() if hasattr(user, 'attributes') else {}
        user_attrs['mfa_totp_secret'] = totp_secret
        user_attrs['mfa_totp_enabled'] = False  # Will be enabled after verification
        user_attrs['mfa_totp_setup_at'] = None
        await self._storage.update_user(user_id, {'attributes': user_attrs})
        logger.debug(f"TOTP setup initiated for user: {user_id}")
        return {
            'secret': totp_secret,
            'provisioning_uri': provisioning_uri,
            'issuer': issuer_name,
        }

    async def verify_totp(self, user_id: str, totp_code: str) -> bool:
        """
        Verify TOTP code for user.
        Args:
            user_id: User identifier
            totp_code: 6-digit TOTP code from authenticator app
        Returns:
            True if code is valid, False otherwise
        """
        if not USE_PYOTP:
            raise XWAuthenticationError(
                "TOTP library not installed",
                error_code="totp_not_available"
            )
        # Get user
        user = await self._storage.get_user(user_id)
        if not user:
            raise XWAuthenticationError(
                "User not found",
                error_code="user_not_found"
            )
        # Get TOTP secret from user attributes
        user_attrs = user.attributes if hasattr(user, 'attributes') else {}
        totp_secret = user_attrs.get('mfa_totp_secret')
        if not totp_secret:
            raise XWInvalidCredentialsError(
                "TOTP not set up for user",
                error_code="totp_not_setup"
            )
        # Verify TOTP code
        totp = pyotp.TOTP(totp_secret)
        is_valid = totp.verify(totp_code, valid_window=1)  # Allow 1 time step tolerance
        if is_valid:
            # Enable TOTP if not already enabled (first successful verification)
            if not user_attrs.get('mfa_totp_enabled', False):
                user_attrs['mfa_totp_enabled'] = True
                from datetime import datetime
                user_attrs['mfa_totp_setup_at'] = datetime.now().isoformat()
                await self._storage.update_user(user_id, {'attributes': user_attrs})
            logger.debug(f"TOTP verified successfully for user: {user_id}")
        else:
            logger.debug(f"TOTP verification failed for user: {user_id}")
        return is_valid

    async def is_enabled(self, user_id: str) -> bool:
        """
        Check if TOTP MFA is enabled for user.
        Args:
            user_id: User identifier
        Returns:
            True if TOTP is enabled, False otherwise
        """
        user = await self._storage.get_user(user_id)
        if not user:
            return False
        user_attrs = user.attributes if hasattr(user, 'attributes') else {}
        return user_attrs.get('mfa_totp_enabled', False)

    async def disable_totp(self, user_id: str) -> None:
        """
        Disable TOTP MFA for user.
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
        user_attrs.pop('mfa_totp_secret', None)
        user_attrs['mfa_totp_enabled'] = False
        user_attrs.pop('mfa_totp_setup_at', None)
        await self._storage.update_user(user_id, {'attributes': user_attrs})
        logger.debug(f"TOTP disabled for user: {user_id}")
