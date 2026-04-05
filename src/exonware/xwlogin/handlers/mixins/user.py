# exonware/xwlogin/handlers/mixins/user.py
"""First-party user HTTP handlers: register, current user profile, profile update."""

from __future__ import annotations
from typing import Any
from fastapi import Request
from fastapi.responses import JSONResponse
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwsystem.io.serialization.formats.text import json as xw_json
from exonware.xwsystem.security.oauth_errors import oauth_error_response
from exonware.xwlogin.handlers.connector_http import (
    USER_TAGS,
    XWUserAlreadyExistsError,
    get_auth,
    get_current_user_id,
    get_email_password_authenticator,
    get_user_lifecycle,
    oauth_error_to_http,
    track_critical_handler,
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
    operationId="auth_register_user",
    summary="User Registration",
    method="POST",
    description="""
    Register a new user account with email and password.
    Creates a new user account with:
    - Email address (must be unique)
    - Password (hashed using secure algorithm)
    - Default role: 'user'
    - Status: 'active'
    Security:
    - Password is hashed before storage (never stored in plaintext)
    - Email validation required before account activation
    - Rate limiting applied to prevent abuse
    Rate Limiting: 5 registrations per IP per hour.
    """,
    tags=USER_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "User registered successfully"},
        400: {"description": "Invalid request (missing/invalid email or password)"},
        409: {"description": "User already exists (email already registered)"},
        429: {"description": "Rate limit exceeded"},
    },
    examples={
        "request": {
            "email": "user@example.com",
            "password": "SecurePassword123!"
        },
        "response": {
            "user_id": "550e8400-e29b-41d4-a716-446655440000",
            "email": "user@example.com",
            "message": "User registered successfully"
        }
    },
    rate_limit="5/hour",
    audit=True,
    in_types={
        "email": {
            "type": "string",
            "format": "email",
            "description": "User email address (must be unique)",
            "minLength": 5,
            "maxLength": 255
        },
        "password": {
            "type": "string",
            "description": "User password (min 8 characters, must contain letters and numbers)",
            "minLength": 8,
            "maxLength": 128
        }
    },
)
async def register_user(request: Request) -> Any:
    form = await request.form()
    email = form.get("email")
    password = form.get("password")
    if not email or not password:
        return _oauth_json_error("invalid_request", "Email and password are required")
    auth = get_auth(request)
    user_lifecycle = get_user_lifecycle(auth)
    email_auth = get_email_password_authenticator(auth)
    try:
        async with track_critical_handler(request, "auth_register_user"):
            password_hash = await email_auth.hash_password(password)
            user = await user_lifecycle.create_user(email=email, password_hash=password_hash)
            return {"user_id": user.id, "email": user.email, "message": "User registered successfully"}
    except Exception as e:
        if isinstance(e, XWUserAlreadyExistsError):
            return _oauth_json_error(
                "user_exists",
                "User with this email already exists",
                status_code=409,
            )
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /users/me
# -----------------------------------------------------------------------------
@XWAction(
    operationId="users_me",
    summary="Get Current User Profile",
    method="GET",
    description="""
    Get the current authenticated user's profile information.
    Returns user data including:
    - user_id: Unique user identifier
    - email: User email address
    - created_at: Account creation timestamp
    - attributes: Additional user attributes
    Security: Requires Bearer token authentication.
    """,
    tags=USER_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "User profile retrieved successfully"},
        401: {"description": "Authentication required (missing/invalid Bearer token)"},
        404: {"description": "User not found"},
    },
    examples={
        "response": {
            "user_id": "550e8400-e29b-41d4-a716-446655440000",
            "email": "user@example.com",
            "created_at": "2026-01-25T10:30:00Z",
            "attributes": {}
        }
    },
    audit=True,
    in_types={},  # Exclude Request parameter from schema (FastAPI dependency, not user input)
)
async def get_current_user(request: Request) -> Any:
    user_id = await get_current_user_id(request)
    if not user_id:
        return _oauth_json_error("unauthorized", "Authentication required", status_code=401)
    auth = get_auth(request)
    user_lifecycle = get_user_lifecycle(auth)
    try:
        async with track_critical_handler(request, "users_me"):
            user = await user_lifecycle.get_user(user_id)
            if not user:
                return _oauth_json_error("user_not_found", "User not found", status_code=404)
            return {
                "user_id": user.id,
                "email": user.email,
                "created_at": user.created_at.isoformat() if hasattr(user.created_at, 'isoformat') else str(user.created_at),
                "attributes": user.attributes if hasattr(user, 'attributes') else {},
            }
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# PUT /users/me
# -----------------------------------------------------------------------------
@XWAction(
    operationId="users_me_update",
    summary="Update Current User Profile",
    method="PUT",
    description="Update the current authenticated user's profile.",
    tags=USER_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={},  # Form data extracted from request.form(), not function parameters
)
async def update_current_user(request: Request) -> Any:
    user_id = await get_current_user_id(request)
    if not user_id:
        return _oauth_json_error("unauthorized", "Authentication required", status_code=401)
    form = await request.form()
    updates = {}
    if form.get("email"):
        updates["email"] = form.get("email")
    if form.get("attributes"):
        try:
            updates["attributes"] = xw_json.loads(form.get("attributes"))
        except:
            updates["attributes"] = form.get("attributes")
    if not updates:
        return _oauth_json_error("invalid_request", "No updates provided")
    auth = get_auth(request)
    user_lifecycle = get_user_lifecycle(auth)
    try:
        async with track_critical_handler(request, "users_me_update"):
            user = await user_lifecycle.update_user(user_id, updates)
            return {
                "user_id": user.id,
                "email": user.email,
                "message": "User updated successfully",
            }
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
