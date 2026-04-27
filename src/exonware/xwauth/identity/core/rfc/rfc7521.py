#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/rfc/rfc7521.py
RFC 7521/7523: JWT Bearer Token Profiles for OAuth 2.0
Implements JWT Bearer Token Profiles for OAuth 2.0.
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
from exonware.xwauth.identity.errors import XWInvalidRequestError, XWInvalidTokenError
from exonware.xwauth.identity.tokens.jwt import JWTTokenManager
logger = get_logger(__name__)


class RFC7521JWTBearerToken:
    """
    RFC 7521/7523: JWT Bearer Token Profiles for OAuth 2.0.
    Implements JWT Bearer Token usage for OAuth 2.0:
    - JWT assertion for client authentication
    - JWT assertion for authorization grants
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize RFC 7521/7523 support.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._config = auth.config
        logger.debug("RFC7521JWTBearerToken initialized")

    async def validate_jwt_assertion(
        self,
        assertion: str,
        assertion_type: str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    ) -> dict[str, Any]:
        """
        Validate JWT assertion (RFC 7523).
        Args:
            assertion: JWT assertion string
            assertion_type: Assertion type (default: jwt-bearer)
        Returns:
            Decoded JWT claims
        Raises:
            XWInvalidTokenError: If assertion is invalid
        """
        if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
            raise XWInvalidRequestError(
                f"Unsupported assertion type: {assertion_type}",
                error_code="unsupported_assertion_type"
            )
        # Decode and validate JWT
        token_manager = getattr(self._auth, "_token_manager", None)
        if not token_manager or not hasattr(token_manager, '_jwt_manager'):
            raise XWInvalidTokenError(
                "JWT token manager not available",
                error_code="server_error"
            )
        jwt_manager: JWTTokenManager = token_manager._jwt_manager
        try:
            # Validate JWT
            claims = jwt_manager.validate_token(assertion)
            # RFC 7523: Validate required claims
            required_claims = ["iss", "sub", "aud", "exp", "iat"]
            for claim in required_claims:
                if claim not in claims:
                    raise XWInvalidTokenError(
                        f"Missing required claim: {claim}",
                        error_code="invalid_assertion"
                    )
            # Validate expiration
            exp = claims.get("exp")
            if exp and datetime.now(timezone.utc).timestamp() > exp:
                raise XWInvalidTokenError(
                    "JWT assertion has expired",
                    error_code="expired_assertion"
                )
            # Validate issuer
            issuer = claims.get("iss")
            expected_issuer = getattr(self._config, "issuer", "xwauth")
            if issuer != expected_issuer:
                raise XWInvalidTokenError(
                    f"Invalid issuer: {issuer}",
                    error_code="invalid_issuer"
                )
            return claims
        except Exception as e:
            raise XWInvalidTokenError(
                f"Invalid JWT assertion: {str(e)}",
                error_code="invalid_assertion"
            )

    def generate_client_assertion(
        self,
        client_id: str,
        audience: str,
        expires_in: int = 300
    ) -> str:
        """
        Generate JWT client assertion for client authentication (RFC 7523).
        Args:
            client_id: Client identifier
            audience: Token endpoint URL (audience)
            expires_in: Assertion lifetime in seconds (default: 5 minutes)
        Returns:
            JWT assertion string
        """
        token_manager = getattr(self._auth, "_token_manager", None)
        if not token_manager or not hasattr(token_manager, '_jwt_manager'):
            raise ValueError("JWT token manager not available")
        jwt_manager: JWTTokenManager = token_manager._jwt_manager
        now = datetime.now(timezone.utc)
        expires_at = now.timestamp() + expires_in
        claims = {
            "iss": client_id,  # Issuer is the client
            "sub": client_id,  # Subject is the client
            "aud": audience,  # Audience is the token endpoint
            "exp": int(expires_at),
            "iat": int(now.timestamp()),
            "jti": self._generate_jti(),
        }
        # Generate JWT
        assertion = jwt_manager.generate_token(
            user_id=None,
            client_id=client_id,
            scopes=[],
            expires_in=expires_in,
            additional_claims=claims
        )
        return assertion

    def _generate_jti(self) -> str:
        """Generate JWT ID."""
        import secrets
        import base64
        random_bytes = secrets.token_bytes(16)
        return base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
