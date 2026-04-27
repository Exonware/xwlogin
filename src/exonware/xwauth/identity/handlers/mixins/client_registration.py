# exonware/xwauth/handlers/mixins/client_registration.py
"""DCR (RFC 7591/7592): register, register_get, register_put, register_delete."""

from __future__ import annotations
from typing import Any
from fastapi import Request, Depends, Header
from fastapi.responses import JSONResponse, RedirectResponse, Response
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwsystem.io.serialization.formats.text import json as xw_json
from exonware.xwsystem.security.oauth_errors import oauth_error_response
from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
from exonware.xwauth.identity.ops_hooks import track_critical_handler
from .._common import (
    AUTH_TAGS, AUTH_PREFIX, get_auth
)


def _oauth_json_error(
    error: str,
    description: str,
    *,
    status_code: int | None = None,
) -> JSONResponse:
    body, status = oauth_error_response(
        error,
        description,
        status_code=status_code,
    )
    return JSONResponse(content=body, status_code=status)
@XWAction(
    operationId="auth_register",
    summary="Dynamic Client Registration (RFC 7591)",
    method="POST",
    description="""
    Dynamic Client Registration endpoint (RFC 7591).
    Allows clients to register themselves with the authorization server
    programmatically, receiving client_id and client_secret.
    Required Parameters:
    - redirect_uris: Array of redirect URIs
    Optional Parameters:
    - token_endpoint_auth_method: Authentication method (client_secret_basic, client_secret_post, none)
    - grant_types: Array of grant types (authorization_code, client_credentials, etc.)
    - response_types: Array of response types (code, token, etc.)
    - client_name: Human-readable client name
    - client_uri: Client homepage URL
    - logo_uri: Client logo URL
    - scope: Space-separated list of scopes
    - contacts: Array of contact email addresses
    - tos_uri: Terms of service URI
    - policy_uri: Privacy policy URI
    Returns:
    - client_id: Generated client identifier
    - client_secret: Generated client secret (for confidential clients)
    - registration_client_uri: URI for client management
    - registration_access_token: Token for client management operations
    - client_id_issued_at: Timestamp when client_id was issued
    - client_secret_expires_at: Timestamp when client_secret expires (0 = never)
    Security: No authentication required for initial registration (may be restricted by policy).
    Rate Limiting: Applied per IP address.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        201: {"description": "Client registered successfully"},
        400: {"description": "Invalid request (missing/invalid parameters)"},
    },
    examples={
        "request": {
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "client_secret_basic",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": "Example Client",
            "scope": "read write"
        },
        "response": {
            "client_id": "abc123...",
            "client_secret": "xyz789...",
            "registration_client_uri": "https://as.example.com/v1/auth/register/abc123",
            "registration_access_token": "token123...",
            "client_id_issued_at": 1737849600,
            "client_secret_expires_at": 0,
            "redirect_uris": ["https://client.example.com/callback"],
            "grant_types": ["authorization_code", "refresh_token"]
        }
    },
    rate_limit="10/hour",
    audit=True,
    in_types={
        "redirect_uris": {
            "type": "array",
            "items": {"type": "string", "format": "uri"},
            "description": "Array of redirect URIs (required)",
            "minItems": 1
        },
        "token_endpoint_auth_method": {
            "type": "string",
            "description": "Token endpoint authentication method",
            "enum": ["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none"],
            "default": "client_secret_basic"
        },
        "grant_types": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Array of grant types",
            "default": ["authorization_code"]
        },
        "response_types": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Array of response types",
            "default": ["code"]
        },
        "client_name": {
            "type": "string",
            "description": "Human-readable client name",
            "maxLength": 256
        },
        "client_uri": {
            "type": "string",
            "format": "uri",
            "description": "Client homepage URL",
            "maxLength": 2048
        },
        "logo_uri": {
            "type": "string",
            "format": "uri",
            "description": "Client logo URL",
            "maxLength": 2048
        },
        "scope": {
            "type": "string",
            "description": "Space-separated list of scopes",
            "maxLength": 512
        },
        "contacts": {
            "type": "array",
            "items": {"type": "string", "format": "email"},
            "description": "Array of contact email addresses"
        },
        "tos_uri": {
            "type": "string",
            "format": "uri",
            "description": "Terms of service URI",
            "maxLength": 2048
        },
        "policy_uri": {
            "type": "string",
            "format": "uri",
            "description": "Privacy policy URI",
            "maxLength": 2048
        }
    },
)
async def register(request: Request) -> Any:
    """Handle Dynamic Client Registration (RFC 7591)."""
    try:
        body = await request.body()
        if body:
            client_metadata = xw_json.loads(body.decode('utf-8'))
        else:
            # Try form data as fallback
            form = await request.form()
            client_metadata = dict(form)
            # Convert list-like strings to arrays
            for key in ["redirect_uris", "grant_types", "response_types", "contacts"]:
                if key in client_metadata:
                    val = client_metadata[key]
                    if isinstance(val, str):
                        # Try to parse as JSON array, or split by comma
                        try:
                            client_metadata[key] = xw_json.loads(val)
                        except xw_json.JSONDecodeError:
                            client_metadata[key] = [v.strip() for v in val.split(",")]
    except Exception as e:
        return _oauth_json_error("invalid_request", f"Invalid JSON: {str(e)}")
    auth = get_auth(request)
    # Get registration endpoint base URL
    issuer = (getattr(request.app.state, "xwauth_issuer", None) or "").rstrip("/")
    auth_prefix = (getattr(request.app.state, "xwauth_auth_prefix", None) or AUTH_PREFIX).rstrip("/")
    registration_endpoint_base = f"{issuer}{auth_prefix}/register" if issuer else f"{auth_prefix}/register"
    try:
        async with track_critical_handler(request, "auth_register"):
            # Initialize DCR manager
            from exonware.xwauth.identity.core.dcr import DCRManager
            dcr_manager = DCRManager(auth, registration_endpoint_base)
            # Register client
            result = await dcr_manager.register_client(client_metadata)
            # Return 201 Created with registration response
            return JSONResponse(content=result, status_code=201)
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /auth/register/{client_id} (RFC 7592)
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_register_get",
    summary="Get Client Registration (RFC 7592)",
    method="GET",
    description="""
    Get client registration metadata (RFC 7592 Section 2.1).
    Retrieves client metadata using registration_client_uri.
    Security: Requires registration_access_token (Bearer token).
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Client metadata returned"},
        401: {"description": "Authentication required"},
        404: {"description": "Client not found"},
    },
    in_types={
        "client_id": {
            "type": "string",
            "description": "Client identifier",
            "minLength": 1,
            "maxLength": 256
        }
    },
)
async def register_get(client_id: str, request: Request) -> Any:
    """Get client registration metadata."""
    auth = get_auth(request)
    # Extract registration_access_token from Authorization header
    registration_access_token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        registration_access_token = auth_header[7:].strip()
    try:
        async with track_critical_handler(request, "auth_register_get"):
            from exonware.xwauth.identity.core.dcr import DCRManager
            dcr_manager = DCRManager(auth)
            client_data = await dcr_manager.get_client(client_id, registration_access_token=registration_access_token)
            if not client_data:
                return _oauth_json_error("invalid_client_id", "Client not found", status_code=404)
            return client_data
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# PUT /auth/register/{client_id} (RFC 7592)
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_register_put",
    summary="Update Client Registration (RFC 7592)",
    method="PUT",
    description="""
    Update client registration metadata (RFC 7592 Section 2.2).
    Updates client metadata. Cannot change client_id or registration_client_uri.
    Security: Requires registration_access_token (Bearer token).
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Client metadata updated"},
        400: {"description": "Invalid request"},
        401: {"description": "Authentication required"},
        404: {"description": "Client not found"},
    },
    in_types={
        "client_id": {
            "type": "string",
            "description": "Client identifier",
            "minLength": 1,
            "maxLength": 256
        }
    },
)
async def register_put(client_id: str, request: Request) -> Any:
    """Update client registration metadata."""
    auth = get_auth(request)
    # Extract registration_access_token from Authorization header
    registration_access_token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        registration_access_token = auth_header[7:].strip()
    try:
        body = await request.body()
        if body:
            client_metadata = xw_json.loads(body.decode('utf-8'))
        else:
            return _oauth_json_error("invalid_request", "Request body required")
    except Exception as e:
        return _oauth_json_error("invalid_request", f"Invalid JSON: {str(e)}")
    try:
        async with track_critical_handler(request, "auth_register_put"):
            from exonware.xwauth.identity.core.dcr import DCRManager
            dcr_manager = DCRManager(auth)
            result = await dcr_manager.update_client(
                client_id, 
                client_metadata,
                registration_access_token=registration_access_token
            )
            return result
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# DELETE /auth/register/{client_id} (RFC 7592)
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_register_delete",
    summary="Delete Client Registration (RFC 7592)",
    method="DELETE",
    description="Delete client registration (RFC 7592 Section 2.3). Permanently deletes the client.",
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        204: {"description": "Client deleted successfully"},
        401: {"description": "Authentication required"},
        404: {"description": "Client not found"},
    },
    in_types={
        "client_id": {
            "type": "string",
            "description": "Client identifier",
            "minLength": 1,
            "maxLength": 256,
        }
    },
)
async def register_delete(client_id: str, request: Request) -> Any:
    """Delete client registration."""
    auth = get_auth(request)
    # Extract registration_access_token from Authorization header
    registration_access_token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        registration_access_token = auth_header[7:].strip()
    try:
        async with track_critical_handler(request, "auth_register_delete"):
            from exonware.xwauth.identity.core.dcr import DCRManager
            dcr_manager = DCRManager(auth)
            await dcr_manager.delete_client(client_id, registration_access_token=registration_access_token)
            return Response(status_code=204)
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
