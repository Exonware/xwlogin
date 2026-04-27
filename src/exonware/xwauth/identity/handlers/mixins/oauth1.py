# exonware/xwauth/handlers/mixins/oauth1.py
"""OAuth 1.0 (RFC 5849): request_token, authorize, access_token."""

from __future__ import annotations
from typing import Any, Optional
from urllib.parse import urlencode
from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
from exonware.xwauth.identity.ops_hooks import track_critical_handler
from .._common import (
    AUTH_TAGS,
    get_auth,
    get_current_user_id,
)


def _headers_from_request(request: Request) -> dict[str, str]:
    """Build headers dict for OAuth1Server from Request. Use canonical 'Authorization' key."""
    v = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    return {"Authorization": v} if v else {}
@XWAction(
    operationId="oauth1_request_token",
    summary="OAuth 1.0 Request Token",
    method="POST",
    description="""
    OAuth 1.0 request token endpoint (RFC 5849 Section 2.1).
    Client obtains temporary credentials (request token) using HMAC-SHA1 signed request.
    Requires Authorization: OAuth ... with oauth_consumer_key, oauth_signature, etc.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Request token returned"},
        400: {"description": "Invalid request"},
        401: {"description": "Invalid consumer or signature"},
    },
    in_types={},
)
async def oauth1_request_token(request: Request) -> Any:
    """Obtain OAuth 1.0 request token."""
    auth = get_auth(request)
    try:
        body = await request.body()
        body_str = body.decode("utf-8") if body else None
    except Exception:
        body_str = None
    headers = _headers_from_request(request)
    url = str(request.url)
    method = request.method
    try:
        async with track_critical_handler(request, "oauth1_request_token"):
            from exonware.xwauth.identity.core.oauth1 import OAuth1Server
            server = OAuth1Server(auth)
            result = await server.request_token(method, url, headers, body_str)
            return result
    except Exception as e:
        body_out, status = oauth_error_to_http(e)
        return JSONResponse(content=body_out, status_code=status)
@XWAction(
    operationId="oauth1_authorize",
    summary="OAuth 1.0 User Authorization",
    method="GET",
    description="""
    OAuth 1.0 user authorization (RFC 5849 Section 2.2).
    Resource owner authorizes the request token. Requires Bearer authentication.
    Query: oauth_token (required), oauth_callback (optional).
    If oauth_callback provided, redirects there with oauth_token&oauth_verifier; else returns JSON.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "Authorization result (JSON)"},
        302: {"description": "Redirect to oauth_callback"},
        401: {"description": "Authentication required"},
        400: {"description": "Invalid request token"},
    },
    in_types={
        "oauth_token": {"type": "string", "description": "Request token", "minLength": 1, "maxLength": 512},
        "oauth_callback": {"type": "string", "format": "uri", "description": "Callback URL", "maxLength": 2048},
    },
)
async def oauth1_authorize(request: Request) -> Any:
    """Authorize OAuth 1.0 request token."""
    oauth_token = request.query_params.get("oauth_token")
    oauth_callback = request.query_params.get("oauth_callback")
    if not oauth_token:
        return JSONResponse(
            content={"error": "invalid_request", "error_description": "oauth_token required"},
            status_code=400,
        )
    user_id = await get_current_user_id(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "oauth1_authorize"):
            from exonware.xwauth.identity.core.oauth1 import OAuth1Server
            server = OAuth1Server(auth)
            result = await server.authorize(oauth_token, user_id, oauth_callback)
    except Exception as e:
        body_out, status = oauth_error_to_http(e)
        return JSONResponse(content=body_out, status_code=status)
    if oauth_callback:
        base = oauth_callback if "?" not in oauth_callback else oauth_callback.split("?")[0]
        params = {"oauth_token": result["oauth_token"], "oauth_verifier": result["oauth_verifier"]}
        redirect_url = f"{base}?{urlencode(params)}"
        return RedirectResponse(url=redirect_url, status_code=302)
    return result
@XWAction(
    operationId="oauth1_access_token",
    summary="OAuth 1.0 Access Token",
    method="POST",
    description="""
    OAuth 1.0 access token endpoint (RFC 5849 Section 2.3).
    Exchange authorized request token + verifier for access token.
    Requires Authorization: OAuth ... (including oauth_token, oauth_verifier) or oauth_verifier in POST body.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Access token returned"},
        400: {"description": "Invalid request or verifier"},
        401: {"description": "Invalid consumer or signature"},
    },
    in_types={},
)
async def oauth1_access_token(request: Request) -> Any:
    """Exchange OAuth 1.0 request token for access token."""
    auth = get_auth(request)
    try:
        body = await request.body()
        body_str = body.decode("utf-8") if body else None
    except Exception:
        body_str = None
    headers = _headers_from_request(request)
    url = str(request.url)
    method = request.method
    try:
        async with track_critical_handler(request, "oauth1_access_token"):
            from exonware.xwauth.identity.core.oauth1 import OAuth1Server
            server = OAuth1Server(auth)
            result = await server.access_token(method, url, headers, body_str)
            return result
    except Exception as e:
        body_out, status = oauth_error_to_http(e)
        return JSONResponse(content=body_out, status_code=status)
