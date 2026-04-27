#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/oauth1/signature.py
OAuth 1.0 Signature Handling
Implements HMAC-SHA1 signature generation and verification for OAuth 1.0 (RFC 5849).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
import hmac
import hashlib
import base64
import secrets
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.errors import XWInvalidRequestError
logger = get_logger(__name__)


class OAuth1Signature:
    """
    OAuth 1.0 signature generation and verification (RFC 5849).
    Supports HMAC-SHA1 signature method.
    """
    @staticmethod

    def generate_signature_base_string(
        method: str,
        url: str,
        parameters: dict[str, Any]
    ) -> str:
        """
        Generate signature base string (RFC 5849 Section 3.4.1.1).
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            parameters: Request parameters (including OAuth parameters)
        Returns:
            Signature base string
        """
        # Normalize URL (remove query string and fragment)
        parsed = urlparse(url)
        normalized_url = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            None,
            None,
            None
        ))
        # Normalize parameters
        normalized_params = OAuth1Signature._normalize_parameters(parameters)
        # Create signature base string
        base_string = f"{method.upper()}&{OAuth1Signature._percent_encode(normalized_url)}&{OAuth1Signature._percent_encode(normalized_params)}"
        return base_string
    @staticmethod

    def _normalize_parameters(parameters: dict[str, Any]) -> str:
        """
        Normalize parameters (RFC 5849 Section 3.4.1.3.2).
        Args:
            parameters: Parameter dictionary
        Returns:
            Normalized parameter string
        """
        # Sort parameters by name, then by value
        sorted_params = sorted(
            [(OAuth1Signature._percent_encode(str(k)), OAuth1Signature._percent_encode(str(v))) 
             for k, v in parameters.items()],
            key=lambda x: (x[0], x[1])
        )
        # Join as key=value pairs
        return "&".join([f"{k}={v}" for k, v in sorted_params])
    @staticmethod

    def _percent_encode(value: str) -> str:
        """
        Percent-encode string (RFC 5849 Section 3.6).
        Args:
            value: String to encode
        Returns:
            Percent-encoded string
        """
        from urllib.parse import quote
        return quote(str(value), safe="")
    @staticmethod

    def generate_signature(
        base_string: str,
        consumer_secret: str,
        token_secret: str = ""
    ) -> str:
        """
        Generate HMAC-SHA1 signature (RFC 5849 Section 3.4.2).
        Args:
            base_string: Signature base string
            consumer_secret: Consumer secret
            token_secret: Token secret (empty for request token)
        Returns:
            Base64-encoded signature
        """
        # Signing key is consumer_secret&token_secret
        signing_key = f"{OAuth1Signature._percent_encode(consumer_secret)}&{OAuth1Signature._percent_encode(token_secret)}"
        # Generate HMAC-SHA1
        signature = hmac.new(
            signing_key.encode('utf-8'),
            base_string.encode('utf-8'),
            hashlib.sha1
        ).digest()
        # Base64 encode
        return base64.b64encode(signature).decode('utf-8')
    @staticmethod

    def verify_signature(
        method: str,
        url: str,
        parameters: dict[str, Any],
        consumer_secret: str,
        token_secret: str = "",
        provided_signature: str = ""
    ) -> bool:
        """
        Verify OAuth 1.0 signature.
        Args:
            method: HTTP method
            url: Request URL
            parameters: Request parameters
            consumer_secret: Consumer secret
            token_secret: Token secret
            provided_signature: Signature from request
        Returns:
            True if signature is valid, False otherwise
        """
        # Base string must exclude oauth_signature (RFC 5849)
        params_for_base = {k: v for k, v in parameters.items() if k != "oauth_signature"}
        base_string = OAuth1Signature.generate_signature_base_string(method, url, params_for_base)
        expected_signature = OAuth1Signature.generate_signature(
            base_string,
            consumer_secret,
            token_secret
        )
        # Compare signatures (constant-time)
        return secrets.compare_digest(expected_signature, provided_signature)
    @staticmethod

    def generate_nonce() -> str:
        """
        Generate OAuth nonce (RFC 5849 Section 3.3).
        Returns:
            Random nonce string
        """
        return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode('ascii').rstrip('=')
    @staticmethod

    def generate_timestamp() -> int:
        """
        Generate OAuth timestamp (RFC 5849 Section 3.3).
        Returns:
            Unix timestamp
        """
        import time
        return int(time.time())
