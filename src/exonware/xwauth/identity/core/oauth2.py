#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/oauth2.py
OAuth 2.0 Core Implementation
Main OAuth 2.0 authorization server logic.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any, Optional
from datetime import datetime
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.defs import GrantType
from exonware.xwauth.identity.errors import XWOAuthError, XWInvalidRequestError, XWUnsupportedResponseTypeError
from exonware.xwauth.identity.base import ABaseAuth
from .grants.base import ABaseGrant
from .grants.authorization_code import AuthorizationCodeGrant
from .grants.client_credentials import ClientCredentialsGrant
from .grants.resource_owner_password import ResourceOwnerPasswordGrant
from .grants.device_code import DeviceCodeGrant
from .grants.refresh_token import RefreshTokenGrant
from .grants.token_exchange import TokenExchangeGrant
logger = get_logger(__name__)


class OAuth2Server(ABaseAuth):
    """
    OAuth 2.0 authorization server implementation.
    Handles OAuth 2.0 authorization and token endpoints.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize OAuth 2.0 server.
        Args:
            auth: XWAuth instance
        """
        super().__init__(auth.storage if hasattr(auth, 'storage') else None)
        self._auth = auth
        self._config = auth.config
        # Register grant handlers
        self._grant_handlers: dict[GrantType, ABaseGrant] = {
            GrantType.AUTHORIZATION_CODE: AuthorizationCodeGrant(auth),
            GrantType.CLIENT_CREDENTIALS: ClientCredentialsGrant(auth),
            GrantType.RESOURCE_OWNER_PASSWORD: ResourceOwnerPasswordGrant(auth),
            GrantType.DEVICE_CODE: DeviceCodeGrant(auth),
            GrantType.REFRESH_TOKEN: RefreshTokenGrant(auth),
            GrantType.TOKEN_EXCHANGE: TokenExchangeGrant(auth),
        }
        logger.info("OAuth2Server initialized")

    async def authorize(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Handle authorization endpoint (RFC 6749 Section 4.1.1).
        Supports PAR (RFC 9126): If request_uri is provided, retrieve stored parameters.
        Args:
            request: Authorization request parameters (or request_uri for PAR)
        Returns:
            Authorization response
        """
        cfg = self._config
        if getattr(cfg, "fapi20_require_par", False):
            ru = request.get("request_uri")
            if not (isinstance(ru, str) and ru.strip()):
                raise XWInvalidRequestError(
                    "Pushed authorization request required (RFC 9126)",
                    error_code="invalid_request",
                    error_description="This server requires PAR; obtain request_uri from the pushed authorization request endpoint",
                )

        # Handle PAR (Pushed Authorization Requests) - RFC 9126
        request_uri = request.get("request_uri")
        if request_uri:
            from .par import PARManager, PAR_AUTHORIZE_QUERY_ALLOWED_KEYS

            par_manager = PARManager(self._auth)
            if getattr(cfg, "par_strict_authorize_query", True):
                for k, v in request.items():
                    if v is None or v == "":
                        continue
                    if k not in PAR_AUTHORIZE_QUERY_ALLOWED_KEYS:
                        raise XWInvalidRequestError(
                            f"Parameter {k} must not be sent with request_uri",
                            error_code="invalid_request",
                            error_description="Duplicate authorization parameters are not allowed alongside request_uri; use the PAR payload only",
                        )

            consumed = await par_manager.consume_request(str(request_uri).strip())
            if not consumed:
                raise XWInvalidRequestError(
                    "Invalid or expired request_uri",
                    error_code="invalid_request_uri",
                    error_description="The request_uri is invalid, expired, or has already been used",
                )
            stored_params, par_client_id = consumed
            merged_request = stored_params.copy()
            q_client = request.get("client_id")
            if q_client is not None and str(q_client).strip() and str(q_client) != par_client_id:
                raise XWInvalidRequestError(
                    "client_id does not match pushed request",
                    error_code="invalid_request",
                    error_description="client_id must match the authenticated client that registered the PAR request",
                )
            for key in ("client_id", "response_type"):
                if key in request and request[key] != stored_params.get(key):
                    raise XWInvalidRequestError(
                        f"Parameter {key} cannot be overridden when using request_uri",
                        error_code="invalid_request",
                        error_description=f"Parameter {key} must match stored request",
                    )
            merged_request.update({k: v for k, v in request.items() if k != "request_uri"})
            merged_request.setdefault("client_id", par_client_id)
            request = merged_request
        # Validate response_type (authorization code and hybrid with `code`; implicit-only not supported)
        response_type = str(request.get("response_type", "code")).strip()
        parts = set(response_type.split())
        allowed_tokens = {"code", "token", "id_token"}
        if not parts or not parts <= allowed_tokens:
            raise XWUnsupportedResponseTypeError(
                f"Unsupported response_type: {response_type}",
                error_code="unsupported_response_type",
                error_description=f"response_type '{response_type}' is not supported",
            )
        if "code" not in parts:
            raise XWUnsupportedResponseTypeError(
                "Implicit-only response_type is not supported",
                error_code="unsupported_response_type",
                error_description=(
                    "Use authorization code or hybrid flows that include `code` "
                    "(e.g. code id_token); pure implicit response types are not implemented"
                ),
            )
        grant_handler = self._grant_handlers[GrantType.AUTHORIZATION_CODE]
        validated_request = await grant_handler.validate_request(request)
        return await grant_handler.process(validated_request)

    async def token(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Handle token endpoint (RFC 6749 Section 4.1.3).
        Args:
            request: Token request parameters
        Returns:
            Token response
        """
        # Validate grant_type
        grant_type_str = request.get('grant_type')
        if not grant_type_str:
            raise XWInvalidRequestError(
                "grant_type is required",
                error_code="invalid_request",
                error_description="grant_type parameter is required"
            )
        try:
            grant_type = GrantType(grant_type_str)
        except ValueError:
            raise XWInvalidRequestError(
                f"Unsupported grant_type: {grant_type_str}",
                error_code="unsupported_grant_type",
                error_description=f"grant_type '{grant_type_str}' is not supported"
            )
        # OAuth 2.1: Reject password grant if disabled
        if grant_type == GrantType.RESOURCE_OWNER_PASSWORD:
            if getattr(self._config, "oauth21_compliant", True):
                if not getattr(self._config, "allow_password_grant", False):
                    raise XWInvalidRequestError(
                        "Password grant is disabled (OAuth 2.1 compliance)",
                        error_code="unsupported_grant_type",
                        error_description="Resource owner password credentials grant is not allowed. Use authorization code grant with PKCE instead."
                    )
        # Get grant handler
        grant_handler = self._grant_handlers.get(grant_type)
        if not grant_handler:
            raise XWInvalidRequestError(
                f"Grant handler not found for grant_type: {grant_type}",
                error_code="unsupported_grant_type"
            )
        # Validate and process grant
        validated_request = await grant_handler.validate_request(request)
        return await grant_handler.process(validated_request)

    async def device_authorization(
        self, request: dict[str, Any], verification_uri_base: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Handle device authorization endpoint (RFC 8628).
        Client sends client_id, optional scope; AS returns device_code, user_code,
        verification_uri, expires_in, interval.
        Args:
            request: Device authorization request (client_id, scope?)
            verification_uri_base: Base URL for verification_uri (e.g. https://as.example/auth)
        Returns:
            Device authorization response
        """
        grant_handler = self._grant_handlers.get(GrantType.DEVICE_CODE)
        if not grant_handler:
            raise XWInvalidRequestError(
                "Device flow not supported",
                error_code="unsupported_grant_type",
                error_description="Device authorization grant is not configured",
            )
        validated = await grant_handler.validate_request(request)
        if verification_uri_base:
            base = verification_uri_base.rstrip("/")
            validated["verification_uri"] = f"{base}/device"
        return await grant_handler.process(validated)
