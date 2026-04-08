#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/authentication/mfa/backup_codes.py
Backup Codes MFA Implementation
Backup codes for multi-factor authentication recovery.
Generates secure one-time backup codes for account recovery.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 25-Jan-2026
"""

from typing import Optional
import secrets
import hashlib
from exonware.xwsystem import get_logger
from exonware.xwsystem.security.crypto import hash_password, verify_password
from exonware.xwlogin.auth_connector import (
    ABaseAuth,
    IStorageProvider,
    XWAuthenticationError,
    XWInvalidCredentialsError,
)
logger = get_logger(__name__)


class BackupCodesMFA:
    """
    Backup codes MFA implementation.
    Generates and manages backup codes for MFA recovery.
    """

    def __init__(self, auth: ABaseAuth, code_length: int = 10, num_codes: int = 10):
        """
        Initialize Backup Codes MFA.
        Args:
            auth: XWAuth instance
            code_length: Length of each backup code (default: 10)
            num_codes: Number of backup codes to generate (default: 10)
        """
        self._auth = auth
        self._storage = auth.storage
        self._config = auth.config
        self._code_length = code_length
        self._num_codes = num_codes
        logger.debug("BackupCodesMFA initialized")

    def _generate_code(self) -> str:
        """
        Generate a single backup code.
        Returns:
            Secure random backup code string
        """
        # Generate secure random code
        # Use URL-safe base64 encoding for readability
        random_bytes = secrets.token_bytes(self._code_length)
        code = secrets.token_urlsafe(self._code_length)[:self._code_length].upper()
        # Format as XXXXX-XXXXX for readability
        if len(code) >= 10:
            return f"{code[:5]}-{code[5:10]}"
        return code

    def _hash_code(self, code: str) -> str:
        """
        Hash backup code for storage.
        Args:
            code: Plain text backup code
        Returns:
            Hashed code string
        """
        # Use secure hashing (bcrypt via xwsystem)
        return hash_password(code)

    async def generate_backup_codes(self, user_id: str) -> list[str]:
        """
        Generate new backup codes for user.
        Args:
            user_id: User identifier
        Returns:
            List of plain text backup codes (show to user once, then discard)
        """
        # Get user
        user = await self._storage.get_user(user_id)
        if not user:
            raise XWAuthenticationError(
                "User not found",
                error_code="user_not_found"
            )
        # Generate backup codes
        plaintext_codes = [self._generate_code() for _ in range(self._num_codes)]
        # Hash codes for storage
        hashed_codes = [self._hash_code(code) for code in plaintext_codes]
        # Store hashed codes in user attributes
        user_attrs = user.attributes.copy() if hasattr(user, 'attributes') else {}
        user_attrs['mfa_backup_codes_hashed'] = hashed_codes
        user_attrs['mfa_backup_codes_generated_at'] = None  # Will be set after user confirms
        await self._storage.update_user(user_id, {'attributes': user_attrs})
        logger.debug(f"Generated {len(plaintext_codes)} backup codes for user: {user_id}")
        # Return plaintext codes (user must save these)
        return plaintext_codes

    async def verify_backup_code(self, user_id: str, code: str) -> bool:
        """
        Verify and consume backup code.
        Args:
            user_id: User identifier
            code: Backup code to verify
        Returns:
            True if code is valid, False otherwise
        """
        # Get user
        user = await self._storage.get_user(user_id)
        if not user:
            raise XWAuthenticationError(
                "User not found",
                error_code="user_not_found"
            )
        # Get hashed backup codes
        user_attrs = user.attributes.copy() if hasattr(user, 'attributes') else {}
        hashed_codes = user_attrs.get('mfa_backup_codes_hashed', [])
        if not hashed_codes:
            raise XWInvalidCredentialsError(
                "No backup codes available",
                error_code="no_backup_codes"
            )
        # Verify code against hashed codes
        code_verified = False
        remaining_codes = []
        for hashed_code in hashed_codes:
            if verify_password(code, hashed_code):
                # Code matches - don't add to remaining (consume it)
                code_verified = True
                logger.debug(f"Backup code verified and consumed for user: {user_id}")
            else:
                # Code doesn't match - keep in list
                remaining_codes.append(hashed_code)
        if not code_verified:
            raise XWInvalidCredentialsError(
                "Invalid backup code",
                error_code="invalid_backup_code"
            )
        # Update user with remaining codes
        user_attrs['mfa_backup_codes_hashed'] = remaining_codes
        await self._storage.update_user(user_id, {'attributes': user_attrs})
        return True

    async def get_remaining_count(self, user_id: str) -> int:
        """
        Get number of remaining backup codes.
        Args:
            user_id: User identifier
        Returns:
            Number of remaining backup codes
        """
        user = await self._storage.get_user(user_id)
        if not user:
            return 0
        user_attrs = user.attributes if hasattr(user, 'attributes') else {}
        hashed_codes = user_attrs.get('mfa_backup_codes_hashed', [])
        return len(hashed_codes)

    async def has_backup_codes(self, user_id: str) -> bool:
        """
        Check if user has backup codes.
        Args:
            user_id: User identifier
        Returns:
            True if user has backup codes, False otherwise
        """
        return await self.get_remaining_count(user_id) > 0
