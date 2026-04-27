#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/rfc/rfc9207.py
RFC 9207: OAuth 2.0 Authorization Server Issuer Identification
Implements issuer identification for OAuth 2.0 authorization servers.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any, Optional
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.errors import XWInvalidRequestError
logger = get_logger(__name__)


class RFC9207IssuerIdentification:
    """
    RFC 9207: OAuth 2.0 Authorization Server Issuer Identification.
    Provides issuer identification support for OAuth 2.0 authorization servers.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize RFC 9207 support.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._config = auth.config
        logger.debug("RFC9207IssuerIdentification initialized")

    def get_issuer(self) -> str:
        """
        Get authorization server issuer identifier.
        Returns:
            Issuer identifier (typically the authorization server's URL)
        """
        issuer = getattr(self._config, "issuer", None)
        if issuer:
            return issuer
        # Fallback: derive from config
        api_base_url = getattr(self._config, "api_base_url", None)
        if api_base_url:
            return api_base_url.rstrip("/")
        return "xwauth"

    def validate_issuer(self, issuer: str) -> bool:
        """
        Validate issuer identifier.
        Args:
            issuer: Issuer identifier to validate
        Returns:
            True if valid, False otherwise
        """
        expected_issuer = self.get_issuer()
        return issuer == expected_issuer

    def get_issuer_metadata(self) -> dict[str, Any]:
        """
        Get issuer metadata (RFC 9207).
        Returns:
            Issuer metadata dictionary
        """
        issuer = self.get_issuer()
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth/authorize",
            "token_endpoint": f"{issuer}/oauth/token",
            "jwks_uri": f"{issuer}/.well-known/jwks.json",
            "issuer_identification_endpoint": f"{issuer}/.well-known/oauth-authorization-server",
        }
