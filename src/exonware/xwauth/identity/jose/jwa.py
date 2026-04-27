#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/jose/jwa.py
JWA (JSON Web Algorithms) Manager
Implements JSON Web Algorithms support for JOSE.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any
from enum import Enum
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class JWAAlgorithm(str, Enum):
    """JSON Web Algorithms (JWA) enumeration."""
    # Signature Algorithms
    HS256 = "HS256"  # HMAC-SHA256
    HS384 = "HS384"  # HMAC-SHA384
    HS512 = "HS512"  # HMAC-SHA512
    RS256 = "RS256"  # RSASSA-PKCS1-v1_5 with SHA-256
    RS384 = "RS384"  # RSASSA-PKCS1-v1_5 with SHA-384
    RS512 = "RS512"  # RSASSA-PKCS1-v1_5 with SHA-512
    ES256 = "ES256"  # ECDSA with P-256 and SHA-256
    ES384 = "ES384"  # ECDSA with P-384 and SHA-384
    ES512 = "ES512"  # ECDSA with P-521 and SHA-512
    # Key Encryption Algorithms
    RSA_OAEP = "RSA-OAEP"
    RSA_OAEP_256 = "RSA-OAEP-256"
    A128KW = "A128KW"
    A192KW = "A192KW"
    A256KW = "A256KW"
    A128GCMKW = "A128GCMKW"
    A192GCMKW = "A192GCMKW"
    A256GCMKW = "A256GCMKW"
    # Content Encryption Algorithms
    A128CBC_HS256 = "A128CBC-HS256"
    A192CBC_HS384 = "A192CBC-HS384"
    A256CBC_HS512 = "A256CBC-HS512"
    A128GCM = "A128GCM"
    A192GCM = "A192GCM"
    A256GCM = "A256GCM"


class JWAManager:
    """
    JSON Web Algorithms (JWA) manager.
    Provides algorithm information and validation.
    """
    @staticmethod

    def is_signing_algorithm(algorithm: str) -> bool:
        """
        Check if algorithm is a signing algorithm.
        Args:
            algorithm: Algorithm name
        Returns:
            True if signing algorithm, False otherwise
        """
        signing_algorithms = [
            "HS256", "HS384", "HS512",
            "RS256", "RS384", "RS512",
            "ES256", "ES384", "ES512",
        ]
        return algorithm in signing_algorithms
    @staticmethod

    def is_encryption_algorithm(algorithm: str) -> bool:
        """
        Check if algorithm is an encryption algorithm.
        Args:
            algorithm: Algorithm name
        Returns:
            True if encryption algorithm, False otherwise
        """
        encryption_algorithms = [
            "RSA-OAEP", "RSA-OAEP-256",
            "A128KW", "A192KW", "A256KW",
            "A128GCMKW", "A192GCMKW", "A256GCMKW",
            "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
            "A128GCM", "A192GCM", "A256GCM",
        ]
        return algorithm in encryption_algorithms
    @staticmethod

    def get_algorithm_info(algorithm: str) -> dict[str, Any]:
        """
        Get algorithm information.
        Args:
            algorithm: Algorithm name
        Returns:
            Algorithm information dictionary
        """
        info = {
            "name": algorithm,
            "type": None,
            "key_type": None,
            "key_size": None,
        }
        if JWAManager.is_signing_algorithm(algorithm):
            info["type"] = "signing"
            if algorithm.startswith("HS"):
                info["key_type"] = "oct"
                info["key_size"] = {
                    "HS256": 32,
                    "HS384": 48,
                    "HS512": 64,
                }.get(algorithm, 32)
            elif algorithm.startswith("RS") or algorithm.startswith("ES"):
                info["key_type"] = "RSA" if algorithm.startswith("RS") else "EC"
        elif JWAManager.is_encryption_algorithm(algorithm):
            info["type"] = "encryption"
        return info
