#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/authentication/magic_link.py
Magic Link Authentication
Passwordless authentication via magic links.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 20-Dec-2025
"""

from typing import Optional
from datetime import datetime, timedelta
import uuid
import base64
from exonware.xwsystem import get_logger
from exonware.xwsystem.security.hazmat import secure_random
from exonware.xwlogin.auth_connector import (
    ABaseAuth,
    ABaseAuthenticator,
    IAuthenticator,
    XWAuthenticationError,
    XWInvalidCredentialsError,
)
logger = get_logger(__name__)


class MagicLinkAuthenticator(ABaseAuthenticator, IAuthenticator):
    """
    Magic link (passwordless) authentication implementation.
    Generates secure tokens sent via email for passwordless login.
    """

    def __init__(self, auth: ABaseAuth, token_lifetime: int = 3600):
        """
        Initialize magic link authenticator.
        Args:
            auth: XWAuth instance
            token_lifetime: Token lifetime in seconds (default: 1 hour)
        """
        super().__init__(auth.storage if hasattr(auth, 'storage') else None)
        self._auth = auth
        self._config = auth.config
        self._token_lifetime = token_lifetime
        self._tokens: dict[str, dict] = {}  # token -> {email, expires_at, used}
        logger.debug("MagicLinkAuthenticator initialized")

    async def generate_magic_link(self, email: str, base_url: str) -> str:
        """
        Generate magic link token and URL.
        Args:
            email: User email address
            base_url: Base URL for magic link
        Returns:
            Magic link URL
        """
        # Generate secure token
        random_bytes = secure_random(32)
        token = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        # Store token
        self._tokens[token] = {
            'email': email,
            'expires_at': datetime.now() + timedelta(seconds=self._token_lifetime),
            'used': False
        }
        # Build magic link URL
        magic_link = f"{base_url}/auth/magic-link?token={token}"
        logger.debug(f"Generated magic link for: {email}")
        return magic_link

    async def authenticate(self, credentials: dict) -> Optional[str]:
        """
        Authenticate user with magic link token.
        Args:
            credentials: Dictionary with 'token' key
        Returns:
            User ID if authenticated, None otherwise
        Raises:
            XWInvalidCredentialsError: If token is invalid
        """
        token = credentials.get('token')
        if not token:
            raise XWInvalidCredentialsError(
                "Magic link token is required",
                error_code="missing_token"
            )
        # Get token data
        token_data = self._tokens.get(token)
        if not token_data:
            raise XWInvalidCredentialsError(
                "Invalid magic link token",
                error_code="invalid_token"
            )
        # Check if expired
        if datetime.now() > token_data['expires_at']:
            del self._tokens[token]
            raise XWInvalidCredentialsError(
                "Magic link token has expired",
                error_code="token_expired"
            )
        # Check if already used
        if token_data['used']:
            raise XWInvalidCredentialsError(
                "Magic link token has already been used",
                error_code="token_used"
            )
        # Mark as used
        token_data['used'] = True
        # Get user by email
        email = token_data['email']
        user = await self._storage.get_user_by_email(email)
        if not user:
            raise XWInvalidCredentialsError(
                "User not found",
                error_code="user_not_found"
            )
        logger.debug(f"Authenticated user via magic link: {user.id}")
        return user.id
