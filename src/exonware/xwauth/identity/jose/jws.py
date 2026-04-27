#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/jose/jws.py
JWS (JSON Web Signature) Manager
Implements JSON Web Signature (JWS) for signing JSON payloads.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any
from exonware.xwsystem.io.serialization.formats.text import json as xw_json
import base64
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from .key_manager import JOSEKeyManager
logger = get_logger(__name__)


class JWSManager:
    """
    JSON Web Signature (JWS) manager.
    Handles signing and verification of JSON payloads.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize JWS manager.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._config = auth.config
        self._key_manager = JOSEKeyManager(auth)
        logger.debug("JWSManager initialized")

    async def sign(
        self,
        payload: dict[str, Any],
        algorithm: str = "HS256",
        key_id: str | None = None
    ) -> str:
        """
        Sign JSON payload (JWS Compact Serialization).
        Args:
            payload: JSON payload to sign
            algorithm: Signing algorithm (HS256, RS256, ES256, etc.)
            key_id: Key ID (optional)
        Returns:
            JWS compact serialization string
        """
        # Encode header
        header = {
            "alg": algorithm,
            "typ": "JWT"
        }
        if key_id:
            header["kid"] = key_id
        header_b64 = self._base64url_encode(xw_json.dumps(header, separators=(',', ':')).encode('utf-8'))
        # Encode payload
        payload_b64 = self._base64url_encode(xw_json.dumps(payload, separators=(',', ':')).encode('utf-8'))
        # Create signing input
        signing_input = f"{header_b64}.{payload_b64}"
        # Sign
        signature = await self._sign_data(signing_input, algorithm, key_id)
        signature_b64 = self._base64url_encode(signature)
        # Return compact serialization
        return f"{signing_input}.{signature_b64}"

    async def verify(
        self,
        jws: str,
        key_id: str | None = None
    ) -> dict[str, Any]:
        """
        Verify JWS and return payload.
        Args:
            jws: JWS compact serialization string
            key_id: Key ID (optional)
        Returns:
            Decoded payload
        """
        parts = jws.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWS format")
        header_b64, payload_b64, signature_b64 = parts
        # Decode header
        header_json = self._base64url_decode(header_b64)
        header = xw_json.loads(header_json)
        algorithm = header.get("alg", "HS256")
        kid = header.get("kid") or key_id
        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}"
        expected_signature = await self._sign_data(signing_input, algorithm, kid)
        provided_signature = self._base64url_decode(signature_b64)
        import secrets
        if not secrets.compare_digest(expected_signature, provided_signature):
            raise ValueError("Invalid JWS signature")
        # Decode payload
        payload_json = self._base64url_decode(payload_b64)
        payload = xw_json.loads(payload_json)
        return payload

    async def _sign_data(
        self,
        data: str,
        algorithm: str,
        key_id: str | None
    ) -> bytes:
        """Sign data using specified algorithm."""
        key = await self._key_manager.get_signing_key(algorithm, key_id)
        if algorithm.startswith("HS"):
            # HMAC-based algorithms
            import hmac
            import hashlib
            hash_func = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512,
            }.get(algorithm, hashlib.sha256)
            return hmac.new(key, data.encode('utf-8'), hash_func).digest()
        else:
            # RSA/ECDSA algorithms would go here
            raise ValueError(f"Algorithm {algorithm} not yet implemented")

    def _base64url_encode(self, data: bytes) -> str:
        """Base64URL encode."""
        return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

    def _base64url_decode(self, data: str) -> bytes:
        """Base64URL decode."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)
