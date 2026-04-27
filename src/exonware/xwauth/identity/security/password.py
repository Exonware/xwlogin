#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/security/password.py
Password Security
Password hashing and breach detection using xwsystem SecureHash.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Optional
from exonware.xwsystem import get_logger
from exonware.xwsystem.security.crypto import hash_password, verify_password
from exonware.xwauth.identity.defs import PasswordHashAlgorithm
logger = get_logger(__name__)


class PasswordSecurity:
    """
    Password security utilities.
    Uses xwsystem SecureHash for password hashing.
    """
    @staticmethod

    def hash_password(password: str, algorithm: PasswordHashAlgorithm = PasswordHashAlgorithm.BCRYPT) -> str:
        """
        Hash password using xwsystem SecureHash.
        Args:
            password: Plain text password
            algorithm: Hash algorithm to use
        Returns:
            Hashed password string
        """
        # xwsystem hash_password uses bcrypt by default
        return hash_password(password)
    @staticmethod

    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Verify password against hash.
        Args:
            password: Plain text password
            hashed_password: Hashed password
        Returns:
            True if password matches, False otherwise
        """
        return verify_password(password, hashed_password)
    @staticmethod

    async def check_password_breach(password: str) -> bool:
        """
        Check if password has been breached using Have I Been Pwned API.
        Uses k-anonymity approach (RFC 6234) - only sends first 5 chars of SHA-1 hash.
        This protects user privacy while checking against breach database.
        Args:
            password: Plain text password
        Returns:
            True if password is breached, False otherwise
        """
        try:
            import hashlib
            import httpx
            # Compute SHA-1 hash of password
            password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            # Use k-anonymity: send only first 5 characters
            prefix = password_hash[:5]
            suffix = password_hash[5:]
            # Query Have I Been Pwned API
            # Format: https://api.pwnedpasswords.com/range/{prefix}
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(url)
                response.raise_for_status()
                # Response contains list of suffixes (with count)
                # Format: SUFFIX:COUNT (one per line)
                response_text = response.text
                # Check if our suffix is in the response
                for line in response_text.splitlines():
                    if ':' in line:
                        line_suffix, count = line.split(':', 1)
                        if line_suffix == suffix:
                            logger.warning(f"Password found in breach database (appeared {count} times)")
                            return True
            # Password not found in breach database
            return False
        except ImportError:
            logger.warning("httpx not installed. Password breach detection unavailable. Install with: pip install httpx")
            return False
        except Exception as e:
            logger.error(f"Error checking password breach: {e}")
            # Fail open (don't block user if API is down)
            return False
