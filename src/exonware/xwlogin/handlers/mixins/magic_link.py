# exonware/xwlogin/handlers/mixins/magic_link.py
"""Magic link: send, verify."""

from __future__ import annotations
from typing import Any, Optional
from fastapi import Request, Depends, Header
from fastapi.responses import JSONResponse, RedirectResponse, Response
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwlogin.handlers.connector_http import (
    API_VERSION,
    AUTH_PREFIX,
    AUTH_TAGS,
    get_auth,
    get_magic_link_authenticator,
    oauth_error_to_http,
    track_critical_handler,
)
@XWAction(
    operationId="auth_magic_link_send",
    summary="Send Magic Link",
    method="POST",
    description="Send passwordless authentication magic link via email.",
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "email": {
            "type": "string",
            "format": "email",
            "description": "User email address",
            "minLength": 5,
            "maxLength": 255,
        }
    },
)
async def magic_link_send(request: Request) -> Any:
    form = await request.form()
    email = form.get("email")
    if not email:
        return JSONResponse(
            content={"error": "invalid_request", "error_description": "Email is required"},
            status_code=400,
        )
    auth = get_auth(request)
    magic_link = get_magic_link_authenticator(auth)
    issuer = (getattr(request.app.state, "xwauth_issuer", None) or "").rstrip("/")
    auth_prefix = (getattr(request.app.state, "xwauth_auth_prefix", None) or AUTH_PREFIX).rstrip("/") or ""
    base_url = f"{issuer}{auth_prefix}" if issuer else str(request.url).rsplit(f"/{API_VERSION}", 1)[0] + AUTH_PREFIX
    try:
        async with track_critical_handler(request, "auth_magic_link_send"):
            link = await magic_link.generate_magic_link(email, base_url)
            # Magic link must never be in API response in production. Send via email only.
            if getattr(auth.config, "dev_return_secrets_in_response", False):
                return {"message": "Magic link sent", "link": link}
            return {"message": "Magic link sent"}
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /auth/magic-link/verify
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_magic_link_verify",
    summary="Verify Magic Link",
    method="GET",
    description="Verify magic link token for passwordless authentication.",
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "token": {
            "type": "string",
            "description": "Magic link token from URL query parameter",
            "minLength": 32,
            "maxLength": 256
        }
    },
)
async def magic_link_verify(request: Request) -> Any:
    token = request.query_params.get("token")
    if not token:
        return JSONResponse(
            content={"error": "invalid_request", "error_description": "Token is required"},
            status_code=400,
        )
    auth = get_auth(request)
    magic_link = get_magic_link_authenticator(auth)
    try:
        async with track_critical_handler(request, "auth_magic_link_verify"):
            user_id = await magic_link.authenticate({"token": token})
            if user_id:
                # Issue token for authenticated user
                # This is a simplified flow - in production, redirect to frontend with token
                return {"user_id": user_id, "message": "Magic link verified successfully"}
            else:
                return JSONResponse(
                    content={"error": "invalid_token", "error_description": "Invalid or expired token"},
                    status_code=400,
                )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
