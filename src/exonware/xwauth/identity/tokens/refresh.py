#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/tokens/refresh.py
Refresh Token Management
Refresh token generation, validation, and rotation.
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


class RefreshTokenManager:
    """
    Refresh token generation and management.
    Handles refresh token lifecycle including rotation.
    """

    def __init__(self, storage: IStorageProvider, enable_rotation: bool = True):
        """
        Initialize refresh token manager.
        Args:
            storage: Storage provider for token persistence
            enable_rotation: Enable refresh token rotation (recommended)
        """
        self._storage = storage
        self._enable_rotation = enable_rotation
        logger.debug("RefreshTokenManager initialized")

    def generate_refresh_token(self) -> str:
        """
        Generate cryptographically random refresh token.
        Returns:
            Refresh token string
        """
        # Generate 32 random bytes, encode as URL-safe base64
        random_bytes = secure_random(32)
        token = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        return token

    async def save_refresh_token(
        self,
        refresh_token: str,
        access_token_id: str,
        user_id: Optional[str],
        client_id: str,
        expires_in: int = 86400 * 7,  # 7 days default
        additional_data: Optional[dict[str, Any]] = None
    ) -> None:
        """
        Save refresh token to storage.
        Args:
            refresh_token: Refresh token string
            access_token_id: Associated access token ID
            user_id: User identifier
            client_id: Client identifier
            expires_in: Token expiration in seconds
            additional_data: Additional token data
        """
        from ..storage.mock import MockToken
        token_id = str(uuid.uuid4())
        expires_at = datetime.now() + timedelta(seconds=expires_in)
        token_obj = MockToken(
            id=token_id,
            user_id=user_id,
            client_id=client_id,
            token_type="Bearer",
            access_token="",  # Refresh token doesn't have access token
            refresh_token=refresh_token,
            expires_at=expires_at,
            scopes=[],  # Refresh tokens don't have scopes
            attributes={
                'access_token_id': access_token_id,
                **(additional_data or {})
            }
        )
        await self._storage.save_token(token_obj)
        logger.debug(f"Saved refresh token: {token_id}")

    async def get_refresh_token(self, refresh_token: str) -> Optional[dict[str, Any]]:
        """
        Get refresh token data from storage.
        Args:
            refresh_token: Refresh token string
        Returns:
            Token data dictionary or None
        """
        token_obj = await self._storage.get_token_by_refresh_token(refresh_token)
        if not token_obj:
            return None
        # Check expiration
        if hasattr(token_obj, 'expires_at') and token_obj.expires_at:
            if datetime.now() > token_obj.expires_at:
                raise XWExpiredTokenError(
                    "Refresh token has expired",
                    error_code="token_expired"
                )
        return {
            'token_id': token_obj.id,
            'user_id': token_obj.user_id,
            'client_id': token_obj.client_id,
            'access_token_id': token_obj.attributes.get('access_token_id') if hasattr(token_obj, 'attributes') else None,
            'expires_at': token_obj.expires_at.isoformat() if hasattr(token_obj, 'expires_at') and token_obj.expires_at else None,
            'attributes': token_obj.attributes if hasattr(token_obj, 'attributes') else {},
        }

    async def validate_refresh_token(self, refresh_token: str) -> dict[str, Any]:
        """
        Validate refresh token.
        Args:
            refresh_token: Refresh token string
        Returns:
            Token data dictionary
        Raises:
            XWInvalidTokenError: If token is invalid
            XWExpiredTokenError: If token is expired
        """
        token_data = await self.get_refresh_token(refresh_token)
        if not token_data:
            raise XWInvalidTokenError(
                "Invalid refresh token",
                error_code="invalid_token"
            )
        return token_data

    async def revoke_refresh_token(self, refresh_token: str) -> None:
        """
        Revoke refresh token.
        Args:
            refresh_token: Refresh token string to revoke
        """
        token_obj = await self._storage.get_token_by_refresh_token(refresh_token)
        if token_obj:
            await self._storage.delete_token(token_obj.id)
            logger.debug(f"Revoked refresh token: {token_obj.id}")

    async def rotate_refresh_token(self, old_refresh_token: str) -> str:
        """
        Rotate refresh token (revoke old, generate new).
        Args:
            old_refresh_token: Old refresh token to revoke
        Returns:
            New refresh token string
        """
        # Get old token data
        old_token_data = await self.validate_refresh_token(old_refresh_token)
        # Generate new refresh token
        new_refresh_token = self.generate_refresh_token()
        # Revoke old token
        await self.revoke_refresh_token(old_refresh_token)
        # Save new token with same metadata
        await self.save_refresh_token(
            new_refresh_token,
            old_token_data['access_token_id'],
            old_token_data['user_id'],
            old_token_data['client_id'],
            additional_data=old_token_data.get('attributes', {})
        )
        logger.debug("Rotated refresh token")
        return new_refresh_token
