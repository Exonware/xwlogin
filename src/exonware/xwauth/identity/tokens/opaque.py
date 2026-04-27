#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/tokens/opaque.py
Opaque Token Management
Opaque token generation and storage via IStorageProvider.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any, Optional
from datetime import datetime, timedelta
import uuid
from exonware.xwsystem import get_logger
from exonware.xwsystem.security.hazmat import secure_random
import base64
from exonware.xwauth.identity.errors import XWTokenError, XWInvalidTokenError, XWExpiredTokenError
from exonware.xwauth.identity.storage.interface import IStorageProvider
logger = get_logger(__name__)


class OpaqueTokenManager:
    """
    Opaque token generation and management.
    Opaque tokens are random strings stored in storage with associated metadata.
    """

    def __init__(self, storage: IStorageProvider):
        """
        Initialize opaque token manager.
        Args:
            storage: Storage provider for token persistence
        """
        self._storage = storage
        logger.debug("OpaqueTokenManager initialized")

    def generate_token(self) -> str:
        """
        Generate cryptographically random opaque token.
        Returns:
            Opaque token string
        """
        # Generate 32 random bytes, encode as URL-safe base64
        random_bytes = secure_random(32)
        token = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        return token

    async def save_token(
        self,
        token: str,
        user_id: Optional[str],
        client_id: str,
        scopes: list[str],
        expires_in: int = 3600,
        additional_data: Optional[dict[str, Any]] = None
    ) -> str:
        """
        Save opaque token to storage.
        Args:
            token: Opaque token string
            user_id: User identifier (None for client credentials)
            client_id: Client identifier
            scopes: List of granted scopes
            expires_in: Token expiration in seconds
            additional_data: Additional token data
        Returns:
            Token ID (for linking with refresh tokens)
        """
        from ..storage.mock import MockToken
        token_id = str(uuid.uuid4())
        expires_at = datetime.now() + timedelta(seconds=expires_in)
        token_obj = MockToken(
            id=token_id,
            user_id=user_id,
            client_id=client_id,
            token_type="Bearer",
            access_token=token,
            refresh_token=None,
            expires_at=expires_at,
            scopes=scopes,
            attributes=additional_data or {}
        )
        await self._storage.save_token(token_obj)
        logger.debug(f"Saved opaque token: {token_id}")
        return token_id

    async def get_token(self, token: str) -> Optional[dict[str, Any]]:
        """
        Get token data from storage.
        Args:
            token: Opaque token string
        Returns:
            Token data dictionary or None
        """
        token_obj = await self._storage.get_token_by_access_token(token)
        if not token_obj:
            return None
        # Check expiration
        if hasattr(token_obj, 'expires_at') and token_obj.expires_at:
            if datetime.now() > token_obj.expires_at:
                raise XWExpiredTokenError(
                    "Opaque token has expired",
                    error_code="token_expired"
                )
        return {
            'token_id': token_obj.id,
            'user_id': token_obj.user_id,
            'client_id': token_obj.client_id,
            'scopes': token_obj.scopes if hasattr(token_obj, 'scopes') else [],
            'expires_at': token_obj.expires_at.isoformat() if hasattr(token_obj, 'expires_at') and token_obj.expires_at else None,
            'attributes': token_obj.attributes if hasattr(token_obj, 'attributes') else {},
        }

    async def validate_token(self, token: str) -> dict[str, Any]:
        """
        Validate opaque token.
        Args:
            token: Opaque token string
        Returns:
            Token data dictionary
        Raises:
            XWInvalidTokenError: If token is invalid
            XWExpiredTokenError: If token is expired
        """
        token_data = await self.get_token(token)
        if not token_data:
            raise XWInvalidTokenError(
                "Invalid opaque token",
                error_code="invalid_token"
            )
        return token_data

    async def revoke_token(self, token: str) -> None:
        """
        Revoke opaque token.
        Args:
            token: Opaque token string to revoke
        """
        token_obj = await self._storage.get_token_by_access_token(token)
        if token_obj:
            await self._storage.delete_token(token_obj.id)
            logger.debug(f"Revoked opaque token: {token_obj.id}")
