#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/rfc/rfc9068.py
RFC 9068: JWT Profile for OAuth 2.0 Access Tokens
Implements JWT profile for OAuth 2.0 access tokens.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any, Optional
from datetime import datetime, timezone
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.tokens.jwt import JWTTokenManager
logger = get_logger(__name__)


class RFC9068JWTProfile:
    """
    RFC 9068: JWT Profile for OAuth 2.0 Access Tokens.
    Implements JWT profile for OAuth 2.0 access tokens with:
    - Standard JWT claims (iss, sub, aud, exp, iat, jti)
    - OAuth 2.0 claims (scope, client_id)
    - Optional claims (auth_time, acr, amr)
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize RFC 9068 support.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._config = auth.config
        logger.debug("RFC9068JWTProfile initialized")

    def generate_jwt_access_token(
        self,
        user_id: Optional[str],
        client_id: str,
        scopes: list[str],
        auth_time: Optional[datetime] = None,
        acr: Optional[str] = None,
        amr: Optional[list[str]] = None,
        additional_claims: Optional[dict[str, Any]] = None
    ) -> str:
        """
        Generate JWT access token following RFC 9068 profile.
        Args:
            user_id: User identifier (None for client credentials)
            client_id: Client identifier
            scopes: List of granted scopes
            auth_time: Authentication time (RFC 9068)
            acr: Authentication Context Class Reference (RFC 9068)
            amr: Authentication Methods References (RFC 9068)
            additional_claims: Additional JWT claims
        Returns:
            JWT access token string
        """
        token_manager = getattr(self._auth, "_token_manager", None)
        if not token_manager or not hasattr(token_manager, '_jwt_manager'):
            raise ValueError("JWT token manager not available")
        jwt_manager: JWTTokenManager = token_manager._jwt_manager
        now = datetime.now(timezone.utc)
        expires_at = now.timestamp() + self._config.access_token_lifetime
        # RFC 9068 required claims
        claims = {
            "iss": self._get_issuer(),
            "sub": user_id or client_id,
            "aud": client_id,  # Audience is the client
            "exp": int(expires_at),
            "iat": int(now.timestamp()),
            "jti": self._generate_jti(),
            "scope": " ".join(scopes),
            "client_id": client_id,
        }
        # RFC 9068 optional claims
        if auth_time:
            claims["auth_time"] = int(auth_time.timestamp())
        if acr:
            claims["acr"] = acr
        if amr:
            claims["amr"] = amr
        # Additional claims
        if additional_claims:
            claims.update(additional_claims)
        # Generate JWT
        token = jwt_manager.generate_token(
            user_id=user_id,
            client_id=client_id,
            scopes=scopes,
            expires_in=self._config.access_token_lifetime,
            additional_claims=claims
        )
        return token

    def _get_issuer(self) -> str:
        """Get issuer identifier."""
        return getattr(self._config, "issuer", "xwauth")

    def _generate_jti(self) -> str:
        """Generate JWT ID."""
        import secrets
        import base64
        random_bytes = secrets.token_bytes(16)
        return base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
