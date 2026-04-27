#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/jose/jwk.py
JWK (JSON Web Key) Manager
Implements JSON Web Key (JWK) for key management.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.storage.interface import IStorageProvider
logger = get_logger(__name__)


class JWKManager:
    """
    JSON Web Key (JWK) manager.
    Handles JWK generation, storage, and retrieval.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize JWK manager.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._storage = auth.storage
        logger.debug("JWKManager initialized")

    def generate_jwk(
        self,
        key_type: str = "oct",  # oct, RSA, EC
        key_id: str | None = None,
        algorithm: str = "HS256"
    ) -> dict[str, Any]:
        """
        Generate JSON Web Key.
        Args:
            key_type: Key type (oct, RSA, EC)
            key_id: Key ID (optional, auto-generated if not provided)
            algorithm: Algorithm this key is for
        Returns:
            JWK dictionary
        """
        import secrets
        import base64
        key_type_normalized = key_type.upper()

        def _b64url_uint(value: int) -> str:
            byte_length = max(1, (value.bit_length() + 7) // 8)
            raw = value.to_bytes(byte_length, "big")
            return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

        if not key_id:
            key_id = self._generate_key_id()
        if key_type_normalized == "OCT":
            # Symmetric key (octet sequence)
            key_size = {
                "HS256": 32,
                "HS384": 48,
                "HS512": 64,
            }.get(algorithm, 32)
            key_bytes = secrets.token_bytes(key_size)
            key_value = base64.urlsafe_b64encode(key_bytes).decode('ascii').rstrip('=')
            jwk = {
                "kty": "oct",
                "kid": key_id,
                "k": key_value,
                "alg": algorithm,
                "use": "sig",  # signature
            }
        elif key_type_normalized == "RSA":
            from cryptography.hazmat.primitives.asymmetric import rsa

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            numbers = private_key.private_numbers()
            public_numbers = numbers.public_numbers
            jwk = {
                "kty": "RSA",
                "kid": key_id,
                "alg": algorithm,
                "use": "sig",
                "n": _b64url_uint(public_numbers.n),
                "e": _b64url_uint(public_numbers.e),
                "d": _b64url_uint(numbers.d),
                "p": _b64url_uint(numbers.p),
                "q": _b64url_uint(numbers.q),
                "dp": _b64url_uint(numbers.dmp1),
                "dq": _b64url_uint(numbers.dmq1),
                "qi": _b64url_uint(numbers.iqmp),
            }
        elif key_type_normalized == "EC":
            from cryptography.hazmat.primitives.asymmetric import ec

            curve_map = {
                "ES256": (ec.SECP256R1(), "P-256"),
                "ES384": (ec.SECP384R1(), "P-384"),
                "ES512": (ec.SECP521R1(), "P-521"),
            }
            curve, curve_name = curve_map.get(algorithm, (ec.SECP256R1(), "P-256"))
            private_key = ec.generate_private_key(curve)
            numbers = private_key.private_numbers()
            public_numbers = numbers.public_numbers
            jwk = {
                "kty": "EC",
                "kid": key_id,
                "alg": algorithm,
                "use": "sig",
                "crv": curve_name,
                "x": _b64url_uint(public_numbers.x),
                "y": _b64url_uint(public_numbers.y),
                "d": _b64url_uint(numbers.private_value),
            }
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        return jwk

    async def save_jwk(self, jwk: dict[str, Any]) -> None:
        """
        Save JWK to storage.
        Args:
            jwk: JWK dictionary
        """
        key_id = jwk.get("kid")
        if not key_id:
            raise ValueError("JWK must have 'kid' (key ID)")
        if hasattr(self._storage, 'write'):
            await self._storage.write(f"jwk:{key_id}", jwk)
        else:
            if not hasattr(self._storage, '_jwks'):
                self._storage._jwks = {}
            self._storage._jwks[key_id] = jwk

    async def get_jwk(self, key_id: str) -> dict[str, Any] | None:
        """
        Get JWK by key ID.
        Args:
            key_id: Key ID
        Returns:
            JWK dictionary or None
        """
        if hasattr(self._storage, 'read'):
            return await self._storage.read(f"jwk:{key_id}")
        else:
            if hasattr(self._storage, '_jwks'):
                return self._storage._jwks.get(key_id)
        return None

    async def get_jwks(self, key_ids: list[str] | None = None) -> dict[str, Any]:
        """
        Get JWK Set (JWKS) for multiple keys.
        Args:
            key_ids: List of key IDs (None for all keys)
        Returns:
            JWKS dictionary with 'keys' array
        """
        keys = []
        if key_ids:
            for kid in key_ids:
                jwk = await self.get_jwk(kid)
                if jwk:
                    keys.append(jwk)
        else:
            # Get all keys (would need storage method to list all JWKs)
            if hasattr(self._storage, '_jwks'):
                keys = list(self._storage._jwks.values())
        return {"keys": keys}

    def _generate_key_id(self) -> str:
        """Generate key ID."""
        import secrets
        import base64
        random_bytes = secrets.token_bytes(8)
        return base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
