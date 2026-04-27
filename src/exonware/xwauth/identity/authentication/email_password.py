#!/usr/bin/env python3

"""

#exonware/xwauth.identity/src/exonware/xwauth.identity/authentication/email_password.py

Email/Password Authentication

Email and password authentication using xwsystem SecureHash.

Company: eXonware.com

Author: eXonware Backend Team

Email: connect@exonware.com

Version: 0.0.1.4

Generation Date: 20-Dec-2025

"""



from typing import Optional

from exonware.xwsystem import get_logger

from exonware.xwsystem.security.crypto import hash_password, verify_password

from exonware.xwauth.identity.base import ABaseAuth, ABaseAuthenticator

from exonware.xwauth.identity.errors import XWAuthenticationError, XWInvalidCredentialsError

from exonware.xwauth.identity.foundation.contracts import IAuthenticator

logger = get_logger(__name__)





class EmailPasswordAuthenticator(ABaseAuthenticator, IAuthenticator):

    """

    Email/password authentication implementation.

    Uses xwsystem SecureHash for password hashing and verification.

    """



    def __init__(self, auth: ABaseAuth):

        """

        Initialize email/password authenticator.

        Args:

            auth: XWAuth instance

        """

        super().__init__(auth.storage if hasattr(auth, 'storage') else None)

        self._auth = auth

        self._config = auth.config

        logger.debug("EmailPasswordAuthenticator initialized")



    async def authenticate(self, credentials: dict) -> Optional[str]:

        """

        Authenticate user with email and password.

        Args:

            credentials: Dictionary with 'email' and 'password' keys

        Returns:

            User ID if authenticated, None otherwise

        Raises:

            XWInvalidCredentialsError: If credentials are invalid

        """

        email = credentials.get('email')

        password = credentials.get('password')

        if not email or not password:

            raise XWInvalidCredentialsError(

                "Email and password are required",

                error_code="missing_credentials"

            )

        # Get user from storage

        user = await self._storage.get_user_by_email(email)

        if not user:

            raise XWInvalidCredentialsError(

                "Invalid email or password",

                error_code="invalid_credentials"

            )

        # Verify password

        password_hash = user.password_hash if hasattr(user, 'password_hash') else None

        if not password_hash:

            raise XWInvalidCredentialsError(

                "User has no password set",

                error_code="no_password"

            )

        # Verify password using xwsystem

        if not verify_password(password, password_hash):

            raise XWInvalidCredentialsError(

                "Invalid email or password",

                error_code="invalid_credentials"

            )

        logger.debug(f"Authenticated user: {user.id}")

        return user.id



    async def hash_password(self, password: str) -> str:

        """

        Hash password using xwsystem SecureHash.

        Args:

            password: Plain text password

        Returns:

            Hashed password string

        """

        return hash_password(password)

