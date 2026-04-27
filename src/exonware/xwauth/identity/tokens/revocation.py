#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/tokens/revocation.py
Token Revocation (RFC 7009)
Token revocation endpoint implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from exonware.xwsystem import get_logger
from exonware.xwauth.identity.errors import XWExpiredTokenError, XWInvalidTokenError, XWTokenError
from .opaque import OpaqueTokenManager
from .refresh import RefreshTokenManager
from .jwt import JWTTokenManager
logger = get_logger(__name__)


class TokenRevocation:
    """
    Token revocation implementation (RFC 7009).
    Provides token revocation endpoint for revoking access and refresh tokens.
    """

    def __init__(
        self,
        opaque_manager: OpaqueTokenManager | None = None,
        refresh_manager: RefreshTokenManager | None = None,
        jwt_manager: JWTTokenManager | None = None
    ):
        """
        Initialize token revocation.
        Args:
            opaque_manager: Opaque token manager (optional)
            refresh_manager: Refresh token manager (optional)
        """
        self._opaque_manager = opaque_manager
        self._refresh_manager = refresh_manager
        self._jwt_manager = jwt_manager
        logger.debug("TokenRevocation initialized")

    async def revoke(
        self,
        token: str,
        token_type_hint: str | None = None
    ) -> None:
        """
        Revoke token (RFC 7009 Section 2.1).
        Args:
            token: Token to revoke
            token_type_hint: Optional hint about token type ("access_token" or "refresh_token")
        """
        # Try to revoke as refresh token first (if hint provided)
        if token_type_hint == "refresh_token" and self._refresh_manager:
            try:
                await self._refresh_manager.revoke_refresh_token(token)
                logger.debug("Revoked refresh token")
                return
            except Exception:
                # Not a refresh token, continue
                pass
        # Try JWT revocation via verified claims only (never trust unverified payloads).
        if self._jwt_manager:
            try:
                payload = self._jwt_manager.validate_token(token)
                jti = payload.get("jti")
                if jti:
                    # Forward the original ``exp`` so distributed stores
                    # (Redis / DB) can TTL-prune the revocation record once
                    # the underlying token has naturally expired.
                    exp_ts = payload.get("exp")
                    self._jwt_manager.revoke_jti(
                        str(jti),
                        exp_ts=int(exp_ts) if isinstance(exp_ts, (int, float)) else None,
                    )
                    logger.debug("Revoked JWT token by jti")
                    return
            except (XWInvalidTokenError, XWExpiredTokenError, XWTokenError):
                pass
        # Try to revoke as access token (opaque)
        if self._opaque_manager:
            try:
                await self._opaque_manager.revoke_token(token)
                logger.debug("Revoked access token")
                return
            except Exception:
                pass
        # Try to revoke as refresh token (without hint)
        if self._refresh_manager:
            try:
                await self._refresh_manager.revoke_refresh_token(token)
                logger.debug("Revoked refresh token")
                return
            except Exception:
                pass
        # Token not found - RFC 7009 says we should return success anyway
        logger.warning(f"Token not found for revocation: {token[:10]}...")
