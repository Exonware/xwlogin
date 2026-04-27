#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/jose/jwt.py
JWT (JSON Web Token) Manager
Enhanced JWT implementation with full JOSE support.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any, Optional
from datetime import datetime, timezone, timedelta
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.tokens.jwt import JWTTokenManager
logger = get_logger(__name__)


class JWTManager:
    """
    Enhanced JWT manager with full JOSE support.
    Extends base JWTTokenManager with additional JOSE features.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize JWT manager.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._config = auth.config
        # Use existing JWT token manager
        token_manager = getattr(auth, "_token_manager", None)
        if token_manager and hasattr(token_manager, '_jwt_manager'):
            self._jwt_manager = token_manager._jwt_manager
        else:
            # Create new JWT manager
            self._jwt_manager = JWTTokenManager(
                secret=self._config.jwt_secret,
                algorithm=self._config.jwt_algorithm,
                issuer=getattr(self._config, "issuer", "xwauth")
            )
        logger.debug("JWTManager initialized")

    def encode(
        self,
        payload: dict[str, Any],
        headers: Optional[dict[str, Any]] = None
    ) -> str:
        """
        Encode JWT with optional headers.
        Args:
            payload: JWT payload
            headers: Optional JWT headers
        Returns:
            Encoded JWT string
        """
        # Add standard claims if missing
        now = datetime.now(timezone.utc)
        if 'iat' not in payload:
            payload['iat'] = int(now.timestamp())
        if 'exp' not in payload:
            expires_in = self._config.access_token_lifetime
            payload['exp'] = int((now + timedelta(seconds=expires_in)).timestamp())
        # Use existing JWT manager
        return self._jwt_manager.generate_token(
            user_id=payload.get('sub'),
            client_id=payload.get('aud', 'default'),
            scopes=payload.get('scope', '').split() if isinstance(payload.get('scope'), str) else payload.get('scope', []),
            expires_in=self._config.access_token_lifetime,
            additional_claims=payload
        )

    def decode(self, token: str, verify: bool = True) -> dict[str, Any]:
        """
        Decode JWT.
        Args:
            token: JWT token string
            verify: Whether to verify signature
        Returns:
            Decoded JWT payload
        """
        if verify:
            return self._jwt_manager.validate_token(token)
        else:
            return self._jwt_manager.get_token_info(token)

    def get_header(self, token: str) -> dict[str, Any]:
        """
        Get JWT header without verification.
        Args:
            token: JWT token string
        Returns:
            JWT header dictionary
        """
        import jwt as pyjwt
        try:
            header = pyjwt.get_unverified_header(token)
            return header
        except Exception as e:
            logger.error(f"Failed to get JWT header: {e}")
            return {}
