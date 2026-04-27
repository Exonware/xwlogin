# exonware/xwauth.identity/handlers/mixins/password.py
"""Password: reset, change."""

from __future__ import annotations
from typing import Any, Optional
from exonware.xwapi.http import Depends, Header, Request
from exonware.xwapi.http import JSONResponse, RedirectResponse, Response
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwauth.identity.handlers._common import USER_TAGS, get_auth, get_current_user_id, get_user_lifecycle
from exonware.xwauth.identity.handlers.authenticators import get_email_password_authenticator
from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
from exonware.xwauth.identity.ops_hooks import track_critical_handler
@XWAction(
    operationId="auth_password_reset",
    summary="Request Password Reset",
    method="POST",
    description="Request a password reset token to be sent via email.",
    tags=USER_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "email": {
            "type": "string",
            "format": "email",
            "description": "User email address for password reset",
            "minLength": 5,
            "maxLength": 255,
        }
    },
)
async def password_reset(request: Request) -> Any:
    form = await request.form()
    email = form.get("email")
    if not email:
        return JSONResponse(
            content={"error": "invalid_request", "error_description": "Email is required"},
            status_code=400,
        )
    auth = get_auth(request)
    user_lifecycle = get_user_lifecycle(auth)
    try:
        async with track_critical_handler(request, "auth_password_reset"):
            user = await user_lifecycle.get_user_by_email(email)
            if user:
                # In production, send email with reset token
                # For now, return success (don't reveal if user exists)
                return {"message": "If the email exists, a password reset link has been sent"}
            else:
                # Don't reveal if user exists
                return {"message": "If the email exists, a password reset link has been sent"}
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# POST /auth/password/change
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_password_change",
    summary="Change Password",
    method="POST",
    description="Change password for the current authenticated user.",
    tags=USER_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "old_password": {
            "type": "string",
            "description": "Current password",
            "minLength": 1,
            "maxLength": 128
        },
        "new_password": {
            "type": "string",
            "description": "New password (min 8 characters)",
            "minLength": 8,
            "maxLength": 128
        }
    },
)
async def password_change(request: Request) -> Any:
    user_id = await get_current_user_id(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    form = await request.form()
    old_password = form.get("old_password")
    new_password = form.get("new_password")
    if not old_password or not new_password:
        return JSONResponse(
            content={"error": "invalid_request", "error_description": "Old and new passwords are required"},
            status_code=400,
        )
    auth = get_auth(request)
    user_lifecycle = get_user_lifecycle(auth)
    email_auth = get_email_password_authenticator(auth)
    try:
        async with track_critical_handler(request, "auth_password_change"):
            user = await user_lifecycle.get_user(user_id)
            if not user:
                return JSONResponse(
                    content={"error": "user_not_found", "error_description": "User not found"},
                    status_code=404,
                )
            # Verify old password
            password_hash = user.password_hash if hasattr(user, 'password_hash') else None
            if not password_hash:
                return JSONResponse(
                    content={"error": "no_password", "error_description": "User has no password set"},
                    status_code=400,
                )
            from exonware.xwsystem.security.crypto import verify_password
            if not verify_password(old_password, password_hash):
                return JSONResponse(
                    content={"error": "invalid_password", "error_description": "Invalid old password"},
                    status_code=400,
                )
            # Update password
            new_password_hash = await email_auth.hash_password(new_password)
            await user_lifecycle.update_user(user_id, {"password_hash": new_password_hash})
            return {"message": "Password changed successfully"}
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
