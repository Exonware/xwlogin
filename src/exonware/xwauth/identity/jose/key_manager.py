#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/jose/key_manager.py
JOSE Key Manager
Manages cryptographic keys for JOSE operations using format-agnostic storage.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any, Optional
import secrets
import base64
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.storage.interface import IStorageProvider
from .jwk import JWKManager
logger = get_logger(__name__)


class JOSEKeyManager:
    """
    JOSE key manager with format-agnostic storage.
    Manages cryptographic keys for JWT, JWS, JWE operations.
    Uses storage abstraction - works with any storage backend.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize JOSE key manager.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._storage = auth.storage
        self._config = auth.config
        self._jwk_manager = JWKManager(auth)
        logger.debug("JOSEKeyManager initialized")

    async def get_signing_key(
        self,
        algorithm: str,
        key_id: Optional[str] = None
    ) -> bytes:
        """
        Get signing key for algorithm.
        Args:
            algorithm: Signing algorithm (HS256, RS256, etc.)
            key_id: Key ID (optional, uses default if not provided)
        Returns:
            Signing key as bytes
        """
        # For HS* algorithms, use JWT secret
        if algorithm.startswith("HS"):
            secret = self._config.jwt_secret
            return secret.encode('utf-8')
        # For other algorithms, get from JWK
        if key_id:
            jwk = await self._jwk_manager.get_jwk(key_id)
            if jwk:
                return self._extract_key_from_jwk(jwk, algorithm)
        # Fallback: generate default key
        return self._generate_default_key(algorithm)

    async def get_encryption_key(
        self,
        algorithm: str,
        key_id: Optional[str] = None
    ) -> bytes:
        """
        Get encryption key for algorithm.
        Args:
            algorithm: Encryption algorithm
            key_id: Key ID (optional)
        Returns:
            Encryption key as bytes
        """
        # Similar to signing key
        if key_id:
            jwk = await self._jwk_manager.get_jwk(key_id)
            if jwk:
                return self._extract_key_from_jwk(jwk, algorithm)
        return self._generate_default_key(algorithm)

    def _extract_key_from_jwk(self, jwk: dict[str, Any], algorithm: str) -> bytes:
        """Extract key bytes from JWK."""
        if jwk.get("kty") == "oct":
            # Symmetric key
            key_value = jwk.get("k", "")
            return base64.urlsafe_b64decode(key_value + '=' * (4 - len(key_value) % 4))
        else:
            # RSA/EC keys would be extracted here
            raise ValueError(f"Key type {jwk.get('kty')} not yet implemented")

    def _generate_default_key(self, algorithm: str) -> bytes:
        """Generate default key for algorithm."""
        if algorithm.startswith("HS"):
            key_size = {
                "HS256": 32,
                "HS384": 48,
                "HS512": 64,
            }.get(algorithm, 32)
            return secrets.token_bytes(key_size)
        else:
            raise ValueError(f"Algorithm {algorithm} requires key_id or JWK")
