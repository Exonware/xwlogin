#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/sessions/security.py

Session Security

CSRF protection and session security using xwsystem crypto.

Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

import base64

from exonware.xwsystem import get_logger
from exonware.xwsystem.security.hazmat import secure_random, constant_time_compare

from exonware.xwauth.identity.errors import XWSessionError, XWInvalidRequestError

logger = get_logger(__name__)


class SessionSecurity:
    """
    Session security utilities.
    
    Provides CSRF protection and secure session token generation.
    """
    
    @staticmethod
    def generate_csrf_token() -> str:
        """
        Generate CSRF token using xwsystem crypto.
        
        Returns:
            CSRF token string
        """
        # Generate 32 random bytes, encode as URL-safe base64
        random_bytes = secure_random(32)
        token = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        return token
    
    @staticmethod
    def validate_csrf_token(provided_token: str, expected_token: str) -> bool:
        """
        Validate CSRF token using constant-time comparison.
        
        Args:
            provided_token: Token provided by client
            expected_token: Expected token from session
            
        Returns:
            True if tokens match
            
        Raises:
            XWInvalidRequestError: If tokens don't match
        """
        if not provided_token:
            raise XWInvalidRequestError(
                "CSRF token is required",
                error_code="invalid_request",
                error_description="CSRF token parameter is required"
            )
        
        if not expected_token:
            raise XWSessionError(
                "Session CSRF token not found",
                error_code="session_error"
            )
        
        # Constant-time comparison to prevent timing attacks
        if not constant_time_compare(
            provided_token.encode('ascii'),
            expected_token.encode('ascii')
        ):
            raise XWSessionError(
                "CSRF token validation failed",
                error_code="csrf_validation_failed"
            )
        
        return True
