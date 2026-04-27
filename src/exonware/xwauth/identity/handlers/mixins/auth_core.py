# exonware/xwauth/handlers/mixins/auth_core.py
"""OAuth 2.0 core + OIDC: token, authorize, introspect, revoke, jwks, device, PAR, userinfo, logout."""

from __future__ import annotations
import base64
import time

from exonware.xwsystem.io.serialization.formats.text import json as xw_json
from exonware.xwsystem.security.oauth_errors import oauth_error_response
from typing import Any
from fastapi import Request
import html

from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
from exonware.xwauth.identity.ops_hooks import notify_critical_handler, track_critical_handler
from .._common import (
    AUTH_TAGS,
    OAUTH2_PREFIX,
    get_auth,
    get_bearer_user_and_introspection,
    merge_token_endpoint_client_auth,
    require_client_auth,
)
def _fallback_render_oidc_form_post_html(
    redirect_uri: str, form_fields: dict[str, Any]
) -> str:
    """OIDC ``response_mode=form_post`` auto-submit HTML (RFC/OIDC-friendly)."""
    action = html.escape(str(redirect_uri))
    inputs = "".join(
        f'<input type="hidden" name="{html.escape(str(k))}" value="{html.escape(str(v))}"/>'
        for k, v in form_fields.items()
    )
    return (
        "<!DOCTYPE html><html><body onload=\"document.forms[0].submit()\">"
        f'<form method="post" action="{action}">{inputs}</form>'
        "</body></html>"
    )


def _render_oidc_form_post_html(redirect_uri: str, form_fields: dict[str, Any]) -> str:
    return _fallback_render_oidc_form_post_html(redirect_uri, form_fields)


_AUTHORIZE_PASSTHROUGH = (
    "response_type", "response_mode", "client_id", "redirect_uri", "scope", "state",
    "code_challenge", "code_challenge_method", "request_uri", "request",
    "authorization_details", "resource", "nonce", "prompt", "max_age",
    "org_id", "organization_id", "project_id", "tenant_id", "tid",
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
# -----------------------------------------------------------------------------
# POST /auth/token
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_token",
    summary="OAuth 2.0 Token Endpoint",
    method="POST",
    description="""
    Exchange authorization grants for access tokens (RFC 6749 Section 3.2).
    Supports multiple grant types:
    - authorization_code: Exchange authorization code for tokens (with PKCE)
    - refresh_token: Refresh access tokens
    - password: Resource Owner Password Credentials (discouraged)
    - client_credentials: Client credentials grant
    - device_code: Device authorization flow
    Content-Type: application/x-www-form-urlencoded
    Security: Requires client authentication for confidential clients.
    Rate Limiting: Applied per client_id and IP address.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Token issued successfully"},
        400: {"description": "Invalid request (missing/invalid parameters)"},
        401: {"description": "Authentication failed (invalid client credentials)"},
    },
    examples={
        "authorization_code": {
            "grant_type": "authorization_code",
            "code": "abc123",
            "redirect_uri": "https://client.example.com/callback",
            "client_id": "client123",
            "code_verifier": "s256_verifier"
        },
        "refresh_token": {
            "grant_type": "refresh_token",
            "refresh_token": "refresh_token_value",
            "client_id": "client123"
        },
        "password": {
            "grant_type": "password",
            "username": "user@example.com",
            "password": "userpassword",
            "client_id": "client123"
        }
    },
    rate_limit="100/hour",
    audit=True,
    in_types={
        "grant_type": {
            "type": "string",
            "description": "OAuth grant type (authorization_code, refresh_token, password, client_credentials, device_code)",
            "enum": ["authorization_code", "refresh_token", "password", "client_credentials", "device_code"]
        },
        "code": {
            "type": "string",
            "description": "Authorization code (for authorization_code grant)",
            "maxLength": 2048,
            "default": None
        },
        "redirect_uri": {
            "type": "string",
            "format": "uri",
            "description": "Redirect URI (must match registered)",
            "maxLength": 2048,
            "default": None
        },
        "client_id": {
            "type": "string",
            "description": "Client identifier",
            "minLength": 1,
            "maxLength": 256,
            "default": None
        },
        "client_secret": {
            "type": "string",
            "description": "Client secret (for confidential clients)",
            "maxLength": 512,
            "default": None
        },
        "refresh_token": {
            "type": "string",
            "description": "Refresh token (for refresh_token grant)",
            "maxLength": 2048,
            "default": None
        },
        "device_code": {
            "type": "string",
            "description": "Device code (for device_code grant)",
            "maxLength": 256,
            "default": None
        },
        "username": {
            "type": "string",
            "description": "Username (for password grant)",
            "maxLength": 256,
            "default": None
        },
        "password": {
            "type": "string",
            "description": "Password (for password grant)",
            "maxLength": 512,
            "default": None
        },
        "code_verifier": {
            "type": "string",
            "description": "PKCE code verifier",
            "maxLength": 256,
            "default": None
        }
    },
)
async def token(request: Request) -> Any:
    form = await request.form()
    req: dict[str, Any] = {"grant_type": form.get("grant_type") or ""}
    for k in ("code", "redirect_uri", "client_id", "client_secret", "refresh_token",
              "device_code", "scope", "username", "password", "state", "code_verifier"):
        v = form.get(k)
        if v is not None:
            req[k] = v
    merge_token_endpoint_client_auth(request, req)
    auth = get_auth(request)
    t0 = time.perf_counter()
    try:
        out = await auth.token(req)
        notify_critical_handler(
            request, "oauth2_token", (time.perf_counter() - t0) * 1000.0, True
        )
        return out
    except Exception as e:
        notify_critical_handler(
            request, "oauth2_token", (time.perf_counter() - t0) * 1000.0, False
        )
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# POST /oauth2/token/exchange
# -----------------------------------------------------------------------------
@XWAction(
    operationId="token_exchange",
    summary="Token Exchange (RFC 8693)",
    method="POST",
    description="""
    Exchange one token for another token (RFC 8693).
    Allows exchanging an access token or refresh token for a new access token
    with potentially different scopes, audiences, or resource identifiers.
    This is useful for:
    - Delegating access to downstream services
    - Obtaining tokens with different scopes
    - Cross-service authentication
    Content-Type: application/x-www-form-urlencoded
    Security: Requires client authentication.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Token exchanged successfully"},
        400: {"description": "Invalid request"},
        401: {"description": "Authentication failed"},
    },
    examples={
        "exchange_access_token": {
            "subject_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "https://api.example.com",
            "scope": "read write",
            "client_id": "client123",
            "client_secret": "secret123"
        }
    },
    rate_limit="100/hour",
    audit=True,
    in_types={
        "subject_token": {
            "type": "string",
            "description": "The token to exchange",
            "minLength": 1,
            "maxLength": 8192
        },
        "subject_token_type": {
            "type": "string",
            "description": "Type of subject token",
            "enum": [
                "urn:ietf:params:oauth:token-type:access_token",
                "urn:ietf:params:oauth:token-type:refresh_token"
            ]
        },
        "requested_token_type": {
            "type": "string",
            "description": "Type of token requested (default: access_token)",
            "enum": ["urn:ietf:params:oauth:token-type:access_token"],
            "default": "urn:ietf:params:oauth:token-type:access_token"
        },
        "audience": {
            "type": "string",
            "description": "Audience for the new token (optional)",
            "format": "uri",
            "maxLength": 512
        },
        "scope": {
            "type": "string",
            "description": "Requested scopes (must be subset of subject token scopes)",
            "maxLength": 1024
        },
        "resource": {
            "type": "string",
            "description": "Resource identifier (optional)",
            "format": "uri",
            "maxLength": 512
        },
        "client_id": {
            "type": "string",
            "description": "Client identifier",
            "minLength": 1,
            "maxLength": 256
        },
        "client_secret": {
            "type": "string",
            "description": "Client secret (required for confidential clients)",
            "maxLength": 512
        }
    },
)
async def token_exchange(request: Request) -> Any:
    """Exchange token for another token (RFC 8693)."""
    auth = get_auth(request)
    # Get form data
    form = await request.form()
    # Build token exchange request
    token_request = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'subject_token': form.get('subject_token'),
        'subject_token_type': form.get('subject_token_type'),
        'requested_token_type': form.get('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token'),
        'client_id': form.get('client_id'),
        'client_secret': form.get('client_secret'),
    }
    # Optional parameters
    if form.get('audience'):
        token_request['audience'] = form.get('audience')
    if form.get('scope'):
        token_request['scope'] = form.get('scope')
    if form.get('resource'):
        token_request['resource'] = form.get('resource')
    try:
        async with track_critical_handler(request, "oauth2_token_exchange"):
            # Use the standard token endpoint logic
            result = await auth.token(token_request)
            return result
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# POST /auth/introspect
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_introspect",
    summary="Token Introspection",
    method="POST",
    description="""
    Introspect access or refresh tokens (RFC 7662).
    Returns token metadata including:
    - active: Whether token is active
    - scope: Token scopes
    - exp: Expiration timestamp
    - sub: Subject (user ID)
    - client_id: Client identifier
    Security: Requires client authentication (client_id + client_secret or Bearer token).
    Rate Limiting: Applied per client_id.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Introspection result (active: true/false)"},
        400: {"description": "Invalid request (missing token)"},
        401: {"description": "Authentication required"},
    },
    examples={
        "request": {
            "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type_hint": "access_token"
        },
        "response_active": {
            "active": True,
            "scope": "read write",
            "exp": 1737849600,
            "sub": "user123"
        },
        "response_inactive": {
            "active": False
        }
    },
    rate_limit="200/hour",
    audit=True,
    in_types={
        "token": {
            "type": "string",
            "description": "Access token or refresh token to introspect",
            "minLength": 1,
            "maxLength": 8192
        },
        "token_type_hint": {
            "type": "string",
            "description": "Hint about token type (access_token, refresh_token)",
            "enum": ["access_token", "refresh_token"],
            "maxLength": 32
        }
    },
)
async def introspect(request: Request) -> Any:
    form = await request.form()
    auth = get_auth(request)
    err = require_client_auth(request, form, auth)
    if err is not None:
        return JSONResponse(content=err[0], status_code=err[1])
    t = form.get("token")
    if not t:
        return _oauth_json_error("invalid_request", "Missing token", status_code=400)
    t0 = time.perf_counter()
    try:
        out = await auth.introspect_token(t)
        notify_critical_handler(
            request, "oauth2_introspect", (time.perf_counter() - t0) * 1000.0, True
        )
        return out
    except Exception as e:
        notify_critical_handler(
            request, "oauth2_introspect", (time.perf_counter() - t0) * 1000.0, False
        )
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# POST /auth/revoke
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_revoke",
    summary="Token revocation",
    method="POST",
    description="Revoke token (RFC 7009). Returns 200 even if token unknown.",
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "token": {
            "type": "string",
            "description": "Access token or refresh token to revoke",
            "minLength": 1,
            "maxLength": 8192
        },
        "token_type_hint": {
            "type": "string",
            "description": "Hint about token type (access_token, refresh_token)",
            "enum": ["access_token", "refresh_token"],
            "maxLength": 32
        }
    },
)
async def revoke(request: Request) -> Response:
    form = await request.form()
    auth = get_auth(request)
    err = require_client_auth(request, form, auth)
    if err is not None:
        return JSONResponse(content=err[0], status_code=err[1])
    t = form.get("token") or ""
    token_type_hint = form.get("token_type_hint")
    t0 = time.perf_counter()
    try:
        await auth.revoke_token(t, token_type_hint=token_type_hint)
        notify_critical_handler(
            request, "oauth2_revoke", (time.perf_counter() - t0) * 1000.0, True
        )
    except Exception:
        notify_critical_handler(
            request, "oauth2_revoke", (time.perf_counter() - t0) * 1000.0, False
        )
    return Response(status_code=200)
# -----------------------------------------------------------------------------
# GET /auth/authorize
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_authorize",
    summary="OAuth 2.0 Authorization Endpoint",
    method="GET",
    description="""
    OAuth 2.0 authorization endpoint (RFC 6749 Section 4.1.1).
    Supports both traditional authorization requests and PAR (RFC 9126):
    - Traditional: All parameters passed directly in query string
    - PAR: Use request_uri parameter to reference pushed request
    Initiates the authorization code flow:
    1. Client redirects user to this endpoint (with parameters or request_uri)
    2. User authenticates and authorizes
    3. Server redirects back to client with authorization code
    Required Parameters (traditional):
    - client_id: Client identifier
    - redirect_uri: Callback URI (must match registered)
    - response_type: "code" for authorization code flow
    - state: CSRF protection token (required)
    Required Parameters (PAR):
    - request_uri: URI from PAR endpoint (RFC 9126)
    Optional Parameters:
    - scope: Requested scopes
    - code_challenge: PKCE challenge (S256 recommended)
    - code_challenge_method: "S256" or "plain"
    - nonce: OIDC nonce for ID tokens
    Security:
    - PKCE required for public clients
    - State parameter required for CSRF protection
    - Redirect URI must be registered and match exactly
    - PAR provides additional security by preventing parameter tampering
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        302: {"description": "Redirect to client with authorization code"},
        200: {"description": "Authorization response (JSON, if no redirect)"},
        400: {"description": "Invalid request (missing/invalid parameters)"},
    },
    examples={
        "request": {
            "client_id": "client123",
            "redirect_uri": "https://client.example.com/callback",
            "response_type": "code",
            "state": "random_state_value",
            "scope": "read write",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256"
        }
    },
    rate_limit="100/hour",
    audit=True,
    in_types={
        "response_type": {
            "type": "string",
            "description": "Response type (code for authorization code flow)",
            "enum": ["code"],
            "default": "code"
        },
        "client_id": {
            "type": "string",
            "description": "Client identifier",
            "minLength": 1,
            "maxLength": 256
        },
        "redirect_uri": {
            "type": "string",
            "format": "uri",
            "description": "Callback URI (must match registered)",
            "maxLength": 2048
        },
        "scope": {
            "type": "string",
            "description": "Requested scopes (space-separated)",
            "maxLength": 512
        },
        "state": {
            "type": "string",
            "description": "State parameter for CSRF protection (required)",
            "minLength": 1,
            "maxLength": 512
        },
        "code_challenge": {
            "type": "string",
            "description": "PKCE code challenge",
            "maxLength": 256
        },
        "code_challenge_method": {
            "type": "string",
            "description": "PKCE code challenge method (S256 or plain)",
            "enum": ["S256", "plain"],
            "default": "S256"
        },
        "nonce": {
            "type": "string",
            "description": "OIDC nonce for ID tokens",
            "maxLength": 256
        },
        "request_uri": {
            "type": "string",
            "description": "Request URI from PAR endpoint (RFC 9126)",
            "format": "uri",
            "maxLength": 2048
        }
    },
)
async def authorize(request: Request) -> Any:
    query = dict(request.query_params)
    req = {k: query[k] for k in _AUTHORIZE_PASSTHROUGH if k in query and query[k] is not None}
    if "response_type" not in req:
        req["response_type"] = "code"
    bearer_sub, _ = await get_bearer_user_and_introspection(request)
    if bearer_sub:
        req["_xwauth_authorize_subject_id"] = bearer_sub
    auth = get_auth(request)
    t0 = time.perf_counter()
    try:
        out = await auth.authorize(req)
        notify_critical_handler(
            request, "oauth2_authorize", (time.perf_counter() - t0) * 1000.0, True
        )
        if out.get("response_mode") == "form_post":
            action = str(out.get("redirect_uri") or "")
            fields = dict(out.get("form_fields") or {})
            page = _render_oidc_form_post_html(action, fields)
            return HTMLResponse(content=page, status_code=200)
        redirect_url = out.get("redirect_uri")
        if redirect_url:
            return RedirectResponse(url=redirect_url, status_code=302)
        return out
    except Exception as e:
        notify_critical_handler(
            request, "oauth2_authorize", (time.perf_counter() - t0) * 1000.0, False
        )
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /auth/jwks
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_jwks",
    summary="JSON Web Key Set",
    method="GET",
    description="JWKS for JWT validation (RS256). Empty if HS256 only.",
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={},  # Exclude Request parameter from schema (FastAPI dependency, not user input)
)
async def jwks(request: Request) -> Any:
    auth = get_auth(request)
    async with track_critical_handler(request, "oauth2_jwks"):
        config = getattr(auth, "config", None)
        active_keys = list(getattr(config, "jwks_active_keys", []) or [])
        next_keys = list(getattr(config, "jwks_next_keys", []) or [])
        include_next = bool(getattr(config, "jwks_publish_next_keys", False))
        keys = active_keys + (next_keys if include_next else [])
        # Deduplicate by kid while preserving first-seen order.
        seen_kids: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for key in keys:
            if not isinstance(key, dict):
                continue
            kid = str(key.get("kid") or "")
            if not kid or kid in seen_kids:
                continue
            seen_kids.add(kid)
            deduped.append(key)
        return {"keys": deduped}
# -----------------------------------------------------------------------------
# POST /auth/device_authorization
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_device_authorization",
    summary="Device Authorization Flow",
    method="POST",
    description="""
    Device authorization endpoint (RFC 8628).
    Used for devices without browsers or input capabilities:
    - Smart TVs
    - IoT devices
    - Command-line tools
    Returns:
    - device_code: Device verification code
    - user_code: User-friendly code for verification
    - verification_uri: URL for user to visit
    - verification_uri_complete: Full URL with user_code
    - expires_in: Device code expiration time
    - interval: Polling interval in seconds
    Flow:
    1. Device calls this endpoint to get codes
    2. User visits verification_uri and enters user_code
    3. Device polls /auth/token with device_code
    4. When user authorizes, device receives tokens
    Security: Requires client_id. Rate limiting applied.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Device authorization initiated"},
        400: {"description": "Invalid request (missing client_id)"},
    },
    examples={
        "request": {
            "client_id": "device_client",
            "scope": "read write"
        },
        "response": {
            "device_code": "device_code_value",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?user_code=ABCD-EFGH",
            "expires_in": 1800,
            "interval": 5
        }
    },
    rate_limit="10/hour",
    audit=True,
    in_types={
        "client_id": {
            "type": "string",
            "description": "Client identifier",
            "minLength": 1,
            "maxLength": 256
        },
        "scope": {
            "type": "string",
            "description": "Requested scopes (space-separated)",
            "maxLength": 512
        }
    },
)
async def device_authorization(request: Request) -> Any:
    form = await request.form()
    client_id = form.get("client_id")
    if not client_id:
        return _oauth_json_error("invalid_request", "Missing client_id", status_code=400)
    req: dict[str, Any] = {"client_id": client_id}
    scope = form.get("scope")
    if scope is not None:
        req["scope"] = scope
    client_secret = form.get("client_secret")
    if client_secret is not None:
        req["client_secret"] = client_secret
    auth = get_auth(request)
    issuer = (getattr(request.app.state, "xwauth_issuer", None) or "").rstrip("/")
    prefix = (getattr(request.app.state, "xwauth_prefix", None) or OAUTH2_PREFIX).rstrip("/") or ""
    verification_base = f"{issuer}{prefix}" if issuer else None
    try:
        async with track_critical_handler(request, "oauth2_device_authorization"):
            return await auth.device_authorization(req, verification_uri_base=verification_base)
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# POST {OAUTH2_PREFIX}/par (RFC 9126); registered as /v1/oauth2/par in xwauth-api.
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_par",
    summary="Pushed Authorization Requests (RFC 9126)",
    method="POST",
    description="""
    Pushed Authorization Requests endpoint (RFC 9126).
    Allows clients to push authorization request parameters to the server
    before redirecting the user, improving security by:
    - Preventing parameter tampering in browser
    - Reducing URL length issues
    - Enabling request signing
    Process:
    1. Client sends authorization parameters to this endpoint
    2. Server stores parameters and returns request_uri
    3. Client uses request_uri in authorize endpoint instead of parameters
    Security: Requires client authentication (client_id + client_secret or Bearer token).
    Rate Limiting: Applied per client_id.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        201: {"description": "Request URI created (RFC 9126 Section 2.2)"},
        400: {"description": "Invalid request (missing/invalid parameters)"},
        401: {"description": "Authentication required"},
    },
    examples={
        "request": {
            "response_type": "code",
            "client_id": "client123",
            "redirect_uri": "https://client.example.com/callback",
            "scope": "read write",
            "state": "random_state_value",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256"
        },
        "response": {
            "request_uri": "urn:ietf:params:oauth:request_uri:abc123...",
            "expires_in": 60
        }
    },
    rate_limit="100/hour",
    audit=True,
    in_types={
        "response_type": {
            "type": "string",
            "description": "Response type (code for authorization code flow)",
            "enum": ["code"],
            "default": "code"
        },
        "client_id": {
            "type": "string",
            "description": "Client identifier",
            "minLength": 1,
            "maxLength": 256
        },
        "redirect_uri": {
            "type": "string",
            "format": "uri",
            "description": "Callback URI (must match registered)",
            "maxLength": 2048
        },
        "scope": {
            "type": "string",
            "description": "Requested scopes (space-separated)",
            "maxLength": 512
        },
        "state": {
            "type": "string",
            "description": "State parameter for CSRF protection",
            "maxLength": 512
        },
        "code_challenge": {
            "type": "string",
            "description": "PKCE code challenge",
            "maxLength": 256
        },
        "code_challenge_method": {
            "type": "string",
            "description": "PKCE code challenge method (S256 or plain)",
            "enum": ["S256", "plain"],
            "maxLength": 8
        },
        "nonce": {
            "type": "string",
            "description": "OIDC nonce for ID tokens",
            "maxLength": 256
        }
    },
)
async def par(request: Request) -> Any:
    """Handle Pushed Authorization Requests (RFC 9126)."""
    form = await request.form()
    auth = get_auth(request)
    # Require client authentication
    err = require_client_auth(request, form, auth)
    if err is not None:
        return JSONResponse(content=err[0], status_code=err[1])
    # Extract client_id
    client_id = form.get("client_id")
    if not client_id:
        # Try to get from Basic Auth
        h = request.headers.get("authorization") or ""
        if h.lower().startswith("basic "):
            try:
                raw = base64.b64decode(h[6:].strip()).decode("utf-8")
                if ":" in raw:
                    client_id, _ = raw.split(":", 1)
            except Exception:
                pass
    if not client_id:
        return _oauth_json_error("invalid_request", "client_id required", status_code=400)
    # Extract all request parameters (excluding client_id and client_secret)
    request_params = {}
    for key in form.keys():
        if key not in ("client_id", "client_secret"):
            request_params[key] = form.get(key)
    # Add client_id to request params (required for authorize endpoint)
    request_params["client_id"] = client_id
    try:
        async with track_critical_handler(request, "oauth2_par"):
            # Initialize PAR manager
            from exonware.xwauth.identity.core.par import PARManager
            par_manager = PARManager(auth)
            # Push request
            result = await par_manager.push_request(request_params, client_id)
            # RFC 9126: successful PAR uses HTTP 201 Created
            return JSONResponse(content=result, status_code=201)
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# POST /auth/register (RFC 7591)
# -----------------------------------------------------------------------------
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
        return _oauth_json_error("invalid_request", f"Invalid JSON: {str(e)}", status_code=400)
    auth = get_auth(request)
    # Get registration endpoint base URL
    issuer = (getattr(request.app.state, "xwauth_issuer", None) or "").rstrip("/")
    auth_prefix = (getattr(request.app.state, "xwauth_auth_prefix", None) or AUTH_PREFIX).rstrip("/")
    registration_endpoint_base = f"{issuer}{auth_prefix}/register" if issuer else f"{auth_prefix}/register"
    try:
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
        from exonware.xwauth.identity.core.dcr import DCRManager
        dcr_manager = DCRManager(auth)
        # Validate registration_access_token if provided
        if registration_access_token:
            await dcr_manager.validate_registration_access_token(client_id, registration_access_token)
        client_data = await dcr_manager.get_client(client_id, registration_access_token)
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
    if not registration_access_token:
        return _oauth_json_error(
            "invalid_token",
            "registration_access_token required in Authorization header",
            status_code=401,
        )
    try:
        body = await request.body()
        if body:
            client_metadata = xw_json.loads(body.decode('utf-8'))
        else:
            return _oauth_json_error("invalid_request", "Request body required", status_code=400)
    except Exception as e:
        return _oauth_json_error("invalid_request", f"Invalid JSON: {str(e)}", status_code=400)
    try:
        from exonware.xwauth.identity.core.dcr import DCRManager
        dcr_manager = DCRManager(auth)
        result = await dcr_manager.update_client(client_id, client_metadata, registration_access_token)
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
    description="""
    Delete client registration (RFC 7592 Section 2.3).
    Permanently deletes the client registration.
    Security: Requires registration_access_token (Bearer token).
    """,
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
            "maxLength": 256
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
    if not registration_access_token:
        return _oauth_json_error(
            "invalid_token",
            "registration_access_token required in Authorization header",
            status_code=401,
        )
    try:
        from exonware.xwauth.identity.core.dcr import DCRManager
        dcr_manager = DCRManager(auth)
        await dcr_manager.delete_client(client_id, registration_access_token)
        return Response(status_code=204)
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /auth/userinfo
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_userinfo",
    summary="OpenID Connect UserInfo",
    method="GET",
    description="""
    OpenID Connect UserInfo endpoint (OIDC Core Section 5.3).
    Returns user information claims for the authenticated user:
    - sub: Subject identifier (user ID)
    - email: Email address
    - email_verified: Email verification status
    - name: Full name
    - picture: Profile picture URL
    - Additional claims based on requested scopes
    Security: Requires Bearer token (access token).
    Scopes: Requires 'openid' scope, additional claims based on 'profile', 'email' scopes.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "User information returned"},
        401: {"description": "Authentication required (missing/invalid Bearer token)"},
    },
    examples={
        "response": {
            "sub": "user123",
            "email": "user@example.com",
            "email_verified": True,
            "name": "John Doe"
        }
    },
    audit=True,
    in_types={},  # Exclude Request parameter from schema (FastAPI dependency, not user input)
)
async def userinfo(request: Request) -> Any:
    h = request.headers.get("authorization") or ""
    if not h.lower().startswith("bearer "):
        return _oauth_json_error("invalid_request", "Missing Bearer token", status_code=401)
    token = h[7:].strip()
    auth = get_auth(request)
    t0 = time.perf_counter()
    try:
        out = await auth.get_userinfo(token)
        notify_critical_handler(
            request, "oidc_userinfo", (time.perf_counter() - t0) * 1000.0, True
        )
        return out
    except Exception as e:
        notify_critical_handler(
            request, "oidc_userinfo", (time.perf_counter() - t0) * 1000.0, False
        )
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /oidc/logout (OIDC Session Management)
# -----------------------------------------------------------------------------
@XWAction(
    operationId="oidc_logout",
    summary="RP-Initiated Logout (OIDC Session Management)",
    method="GET",
    description="""
    OpenID Connect RP-initiated logout endpoint (OIDC Session Management).
    Supports both front-channel and back-channel logout:
    - Front-channel: Uses iframe-based logout (browser-based)
    - Back-channel: Uses server-to-server logout token delivery
    Parameters:
    - id_token_hint: ID token hint (optional, helps identify session)
    - post_logout_redirect_uri: URI to redirect after logout
    - state: State parameter for CSRF protection
    - client_id: Client identifier (optional)
    Process:
    1. Validates id_token_hint (if provided)
    2. Revokes user sessions and tokens
    3. Generates logout token for back-channel logout (if client configured)
    4. Redirects to post_logout_redirect_uri (if provided)
    Security: No authentication required (public endpoint).
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Logout successful"},
        302: {"description": "Redirect to post_logout_redirect_uri"},
        400: {"description": "Invalid request"},
    },
    examples={
        "request": {
            "id_token_hint": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            "post_logout_redirect_uri": "https://client.example.com/logged-out",
            "state": "random_state_value"
        }
    },
    rate_limit="100/hour",
    audit=True,
    in_types={
        "id_token_hint": {
            "type": "string",
            "description": "ID token hint (helps identify session)",
            "maxLength": 8192
        },
        "post_logout_redirect_uri": {
            "type": "string",
            "format": "uri",
            "description": "URI to redirect after logout",
            "maxLength": 2048
        },
        "state": {
            "type": "string",
            "description": "State parameter for CSRF protection",
            "maxLength": 512
        },
        "client_id": {
            "type": "string",
            "description": "Client identifier",
            "maxLength": 256
        }
    },
)
async def logout(request: Request) -> Any:
    """Handle RP-initiated logout (OIDC Session Management)."""
    query = dict(request.query_params)
    id_token_hint = query.get("id_token_hint")
    post_logout_redirect_uri = query.get("post_logout_redirect_uri")
    state = query.get("state")
    client_id = query.get("client_id")
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "oidc_logout"):
            # Initialize logout manager
            from exonware.xwauth.identity.core.logout import LogoutManager
            logout_manager = LogoutManager(auth)
            # Process logout
            result = await logout_manager.logout(
                id_token_hint=id_token_hint,
                post_logout_redirect_uri=post_logout_redirect_uri,
                state=state,
                client_id=client_id,
            )
            # Redirect if redirect_uri provided
            if result.get("redirect_uri"):
                return RedirectResponse(url=result["redirect_uri"], status_code=302)
            # Return confirmation
            return {"logged_out": True, "message": "Logout successful"}
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
