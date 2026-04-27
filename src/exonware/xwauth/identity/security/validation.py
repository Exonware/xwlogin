#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/security/validation.py
Input Validation
Input validation using xwsystem validation utilities.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any, Optional
import re
from exonware.xwsystem import get_logger
from exonware.xwsystem.validation.data_validator import DataValidator
from exonware.xwsystem.validation import ValidationError
from exonware.xwauth.identity.errors import XWAuthError, XWInvalidUserDataError
logger = get_logger(__name__)


class InputValidator:
    """
    Input validation utilities.
    Uses xwsystem validation (DataValidator) for data structure validation.
    """

    def __init__(self):
        """Initialize input validator."""
        self._validator = DataValidator()
        logger.debug("InputValidator initialized")

    def validate_email(self, email: str) -> bool:
        """
        Validate email address.
        Args:
            email: Email address to validate
        Returns:
            True if valid, False otherwise
        """
        if not email:
            return False
        # Basic email regex
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def validate_password(self, password: str, min_length: int = 8) -> bool:
        """
        Validate password strength.
        Args:
            password: Password to validate
            min_length: Minimum password length
        Returns:
            True if valid, False otherwise
        """
        if not password:
            return False
        if len(password) < min_length:
            return False
        # Check for at least one uppercase, one lowercase, one digit
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        return has_upper and has_lower and has_digit

    def validate_redirect_uri(self, redirect_uri: str) -> bool:
        """
        Validate redirect URI.
        Args:
            redirect_uri: Redirect URI to validate
        Returns:
            True if valid, False otherwise
        """
        if not redirect_uri:
            return False
        # Basic URL validation
        try:
            from urllib.parse import urlparse
            parsed = urlparse(redirect_uri)
            # Reject dangerous schemes
            if parsed.scheme.lower() in ('javascript', 'data', 'vbscript'):
                return False
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False

    def sanitize_email(self, email: str) -> str:
        """
        Sanitize email address.
        Args:
            email: Email address to sanitize
        Returns:
            Sanitized email address
        """
        if not email:
            return ""
        # Remove whitespace and convert to lowercase
        return email.strip().lower()

    def sanitize_string(self, value: str, max_length: Optional[int] = None) -> str:
        """
        Sanitize string input.
        Args:
            value: String to sanitize
            max_length: Maximum length (optional)
        Returns:
            Sanitized string
        """
        if not value:
            return ""
        # Remove HTML tags (basic)
        import re
        sanitized = re.sub(r'<[^>]+>', '', value)
        # Trim whitespace
        sanitized = sanitized.strip()
        # Limit length if specified
        if max_length and len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        return sanitized

    def validate_scope(self, scope: str) -> bool:
        """
        Validate OAuth scope.
        Args:
            scope: Scope string to validate (can be space-separated)
        Returns:
            True if valid, False otherwise
        """
        if not scope:
            return False
        # Scope can be space-separated, validate each part
        scope_parts = scope.split()
        for part in scope_parts:
            # Each part should be alphanumeric with dots, colons, underscores, hyphens
            pattern = r'^[a-zA-Z0-9._:-]+$'
            if not re.match(pattern, part):
                return False
        return True

    def validate_state(self, state: str) -> bool:
        """
        Validate OAuth state parameter.
        Args:
            state: State string to validate
        Returns:
            True if valid, False otherwise
        """
        if not state:
            return False
        # State should be reasonable length (1-512 characters)
        if len(state) < 1 or len(state) > 512:
            return False
        # State should be URL-safe
        pattern = r'^[A-Za-z0-9\-_.~]+$'
        return bool(re.match(pattern, state))
