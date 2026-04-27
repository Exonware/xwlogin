# exonware/xwauth.identity/handlers/mixins/otp.py
"""OTP: send, verify."""

from __future__ import annotations
from typing import Any, Optional
from exonware.xwapi.http import Depends, Header, Request
from exonware.xwapi.http import JSONResponse, RedirectResponse, Response
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwauth.identity.handlers._common import AUTH_TAGS, get_auth, get_current_user_id
from exonware.xwauth.identity.handlers.authenticators import get_phone_otp_authenticator
from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
from exonware.xwauth.identity.ops_hooks import track_critical_handler
@XWAction(
    operationId="auth_otp_send",
    summary="Send OTP Code",
    method="POST",
    description="Send One-Time Password (OTP) code to phone number via SMS.",
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "phone_number": {
            "type": "string",
            "description": "Phone number in E.164 format (e.g., +1234567890)",
            "pattern": "^\\+[1-9]\\d{1,14}$",
            "minLength": 8,
            "maxLength": 20,
        }
    },
)
async def otp_send(request: Request) -> Any:
    form = await request.form()
    phone_number = form.get("phone_number")
    if not phone_number:
        return JSONResponse(
            content={"error": "invalid_request", "error_description": "Phone number is required"},
            status_code=400,
        )
    auth = get_auth(request)
    phone_otp = get_phone_otp_authenticator(auth)
    try:
        async with track_critical_handler(request, "auth_otp_send"):
            otp_code = await phone_otp.generate_otp(phone_number)
            # OTP must never be in API response in production. Send via SMS only.
            if getattr(auth.config, "dev_return_secrets_in_response", False):
                return {"message": "OTP sent", "otp": otp_code}
            return {"message": "OTP sent"}
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# POST /auth/otp/verify
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_otp_verify",
    summary="Verify OTP",
    method="POST",
    description="Verify OTP code for phone number.",
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "phone_number": {
            "type": "string",
            "description": "Phone number in E.164 format",
            "pattern": "^\\+[1-9]\\d{1,14}$",
            "minLength": 8,
            "maxLength": 20
        },
        "otp": {
            "type": "string",
            "description": "6-digit OTP code",
            "pattern": "^\\d{6}$",
            "minLength": 6,
            "maxLength": 6
        }
    },
)
async def otp_verify(request: Request) -> Any:
    form = await request.form()
    phone_number = form.get("phone_number")
    otp = form.get("otp")
    if not phone_number or not otp:
        return JSONResponse(
            content={"error": "invalid_request", "error_description": "Phone number and OTP are required"},
            status_code=400,
        )
    auth = get_auth(request)
    phone_otp = get_phone_otp_authenticator(auth)
    try:
        async with track_critical_handler(request, "auth_otp_verify"):
            user_id = await phone_otp.authenticate({"phone_number": phone_number, "otp": otp})
            if user_id:
                return {"user_id": user_id, "message": "OTP verified successfully"}
            else:
                return JSONResponse(
                    content={"error": "user_not_found", "error_description": "User not found for this phone number"},
                    status_code=404,
                )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
