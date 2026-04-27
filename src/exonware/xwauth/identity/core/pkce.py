#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/pkce.py
PKCE (RFC 7636) Implementation
Proof Key for Code Exchange - mandatory for OAuth 2.1, recommended for all clients.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

import base64
import hashlib
from typing import Optional
from exonware.xwsystem import get_logger
from exonware.xwsystem.security.hazmat import secure_random
from exonware.xwauth.identity.errors import XWOAuthError, XWInvalidRequestError
logger = get_logger(__name__)


class PKCE:
    """
    PKCE (Proof Key for Code Exchange) implementation.
    Following RFC 7636 for OAuth 2.0 authorization code flow security.
    OAuth 2.1 makes PKCE mandatory for all clients.
    """
    CODE_VERIFIER_MIN_LENGTH = 43
    CODE_VERIFIER_MAX_LENGTH = 128
    CODE_CHALLENGE_METHOD = "S256"  # SHA256 (recommended)
    @staticmethod

    def generate_code_verifier() -> str:
        """
        Generate code verifier (RFC 7636 Section 4.1).
        Code verifier: high-entropy cryptographic random string
        - 43-128 characters
        - URL-safe base64 encoding (A-Z, a-z, 0-9, -, _, .)
        Returns:
            Code verifier string
        """
        # Generate 32 random bytes (256 bits)
        # Base64 encoding: 32 bytes = 43 characters (minimum length)
        random_bytes = secure_random(32)
        code_verifier = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        # Ensure minimum length (pad if needed, though 32 bytes should be enough)
        if len(code_verifier) < PKCE.CODE_VERIFIER_MIN_LENGTH:
            # This shouldn't happen, but ensure minimum length
            while len(code_verifier) < PKCE.CODE_VERIFIER_MIN_LENGTH:
                extra = base64.urlsafe_b64encode(secure_random(1)).decode('ascii').rstrip('=')
                code_verifier += extra
        # Truncate to maximum length if needed
        if len(code_verifier) > PKCE.CODE_VERIFIER_MAX_LENGTH:
            code_verifier = code_verifier[:PKCE.CODE_VERIFIER_MAX_LENGTH]
        logger.debug(f"Generated code verifier: {len(code_verifier)} characters")
        return code_verifier
    @staticmethod

    def generate_code_challenge(code_verifier: str, method: str = "S256") -> str:
        """
        Generate code challenge from code verifier (RFC 7636 Section 4.2).
        Args:
            code_verifier: Code verifier string
            method: Challenge method ("S256" for SHA256, "plain" for plaintext)
        Returns:
            Code challenge string
        """
        # Normalize method to uppercase for comparison
        method_upper = method.upper()
        if method_upper == "S256":
            # SHA256 hash, then base64url encode
            sha256_hash = hashlib.sha256(code_verifier.encode('ascii')).digest()
            code_challenge = base64.urlsafe_b64encode(sha256_hash).decode('ascii').rstrip('=')
            return code_challenge
        elif method_upper == "PLAIN":
            # Plain text (not recommended, but supported)
            return code_verifier
        else:
            raise XWInvalidRequestError(
                f"Unsupported code_challenge_method: {method}",
                error_code="invalid_request",
                error_description=f"code_challenge_method must be 'S256' or 'plain'"
            )
    @staticmethod

    def generate_code_pair(method: str = "S256") -> tuple[str, str]:
        """
        Generate code verifier and challenge pair.
        Args:
            method: Challenge method ("S256" or "plain")
        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        code_verifier = PKCE.generate_code_verifier()
        code_challenge = PKCE.generate_code_challenge(code_verifier, method)
        return code_verifier, code_challenge
    @staticmethod

    def validate_code_verifier(code_verifier: str) -> bool:
        """
        Validate code verifier format (RFC 7636 Section 4.1).
        Args:
            code_verifier: Code verifier to validate
        Returns:
            True if valid
        Raises:
            XWInvalidRequestError: If invalid
        """
        if not code_verifier:
            raise XWInvalidRequestError(
                "code_verifier is required",
                error_code="invalid_request",
                error_description="code_verifier parameter is required"
            )
        length = len(code_verifier)
        if length < PKCE.CODE_VERIFIER_MIN_LENGTH:
            raise XWInvalidRequestError(
                f"code_verifier too short (minimum {PKCE.CODE_VERIFIER_MIN_LENGTH} characters)",
                error_code="invalid_request",
                error_description=f"code_verifier must be at least {PKCE.CODE_VERIFIER_MIN_LENGTH} characters"
            )
        if length > PKCE.CODE_VERIFIER_MAX_LENGTH:
            raise XWInvalidRequestError(
                f"code_verifier too long (maximum {PKCE.CODE_VERIFIER_MAX_LENGTH} characters)",
                error_code="invalid_request",
                error_description=f"code_verifier must be at most {PKCE.CODE_VERIFIER_MAX_LENGTH} characters"
            )
        # Validate URL-safe base64 characters
        import re
        if not re.match(r'^[A-Za-z0-9\-_.]+$', code_verifier):
            raise XWInvalidRequestError(
                "code_verifier contains invalid characters",
                error_code="invalid_request",
                error_description="code_verifier must contain only URL-safe base64 characters (A-Z, a-z, 0-9, -, _, .)"
            )
        return True
    @staticmethod

    def verify_code_challenge(
        code_verifier: str,
        code_challenge: str,
        code_challenge_method: str = "S256"
    ) -> bool:
        """
        Verify code challenge against code verifier (RFC 7636 Section 4.6).
        Args:
            code_verifier: Code verifier from token request
            code_challenge: Code challenge from authorization request
            code_challenge_method: Challenge method used
        Returns:
            True if challenge matches verifier
        Raises:
            XWInvalidRequestError: If verification fails
        """
        # Normalize method to uppercase
        code_challenge_method = code_challenge_method.upper()
        # Validate code verifier format
        PKCE.validate_code_verifier(code_verifier)
        # Generate expected challenge from verifier
        expected_challenge = PKCE.generate_code_challenge(code_verifier, code_challenge_method)
        # Constant-time comparison to prevent timing attacks
        from exonware.xwsystem.security.hazmat import constant_time_compare
        if not constant_time_compare(code_challenge.encode('ascii'), expected_challenge.encode('ascii')):
            raise XWInvalidRequestError(
                "code_verifier does not match code_challenge",
                error_code="invalid_grant",
                error_description="code_verifier verification failed"
            )
        return True
