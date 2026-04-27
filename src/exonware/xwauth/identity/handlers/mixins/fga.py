# exonware/xwauth/handlers/mixins/fga.py
"""FGA/ReBAC: check, tuples, expand, permissions_me."""

from __future__ import annotations
from typing import Any, Optional
from fastapi import Request, Depends, Header
from fastapi.responses import JSONResponse, RedirectResponse, Response
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
from exonware.xwauth.identity.ops_hooks import track_critical_handler
from .._common import (
    AUTHZ_TAGS, get_auth, get_current_user_id, get_fga_manager
)
# -----------------------------------------------------------------------------
# POST /auth/check
# -----------------------------------------------------------------------------
@XWAction(
    operationId="fga_check",
    summary="Check Permission (Zanzibar-style)",
    method="POST",
    description="""
    Check if a user has a relation to an object (Zanzibar-style permission check).
    This implements fine-grained authorization using relationship tuples.
    Example: Check if user:123 has "viewer" relation to doc:456.
    Security: Requires Bearer token authentication.
    """,
    tags=AUTHZ_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "Permission check result"},
        400: {"description": "Invalid request"},
        401: {"description": "Authentication required"},
    },
    examples={
        "check_permission": {
            "user": "user:123",
            "relation": "viewer",
            "object": "doc:456"
        }
    },
    rate_limit="1000/hour",
    audit=True,
    in_types={
        "user": {
            "type": "string",
            "description": "User identifier (e.g., 'user:123')",
            "minLength": 1,
            "maxLength": 256
        },
        "relation": {
            "type": "string",
            "description": "Relation type (e.g., 'viewer', 'editor', 'owner')",
            "minLength": 1,
            "maxLength": 128
        },
        "object": {
            "type": "string",
            "description": "Object identifier (e.g., 'doc:456')",
            "minLength": 1,
            "maxLength": 256
        }
    },
)
async def fga_check(request: Request) -> Any:
    """Check permission (Zanzibar-style)."""
    user_id = await get_current_user_id(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    auth = get_auth(request)
    body_data = await request.json() if hasattr(request, 'json') else {}
    try:
        async with track_critical_handler(request, "fga_check"):
            manager = get_fga_manager(auth)
            allowed = await manager.check(
                user=body_data.get("user"),
                relation=body_data.get("relation"),
                object=body_data.get("object"),
            )
            return {
                "allowed": allowed,
                "user": body_data.get("user"),
                "relation": body_data.get("relation"),
                "object": body_data.get("object"),
            }
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# POST /auth/tuples
# -----------------------------------------------------------------------------
@XWAction(
    operationId="fga_write_tuples",
    summary="Write Relationship Tuples",
    method="POST",
    description="""
    Write relationship tuples for fine-grained authorization.
    Creates relationships like: (user:123, relation:editor, object:doc:456)
    Security: Requires Bearer token authentication.
    """,
    tags=AUTHZ_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "Tuples written successfully"},
        400: {"description": "Invalid request"},
        401: {"description": "Authentication required"},
    },
    examples={
        "write_tuples": {
            "tuples": [
                {"user": "user:123", "relation": "editor", "object": "doc:456"},
                {"user": "user:789", "relation": "viewer", "object": "doc:456"}
            ]
        }
    },
    rate_limit="100/hour",
    audit=True,
    in_types={
        "tuples": {
            "type": "array",
            "description": "List of tuples to write",
            "items": {
                "type": "object",
                "properties": {
                    "user": {"type": "string"},
                    "relation": {"type": "string"},
                    "object": {"type": "string"}
                },
                "required": ["user", "relation", "object"]
            },
            "minItems": 1,
            "maxItems": 100
        }
    },
)
async def fga_write_tuples(request: Request) -> Any:
    """Write relationship tuples."""
    user_id = await get_current_user_id(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    auth = get_auth(request)
    body_data = await request.json() if hasattr(request, 'json') else {}
    try:
        async with track_critical_handler(request, "fga_write_tuples"):
            tuples = body_data.get("tuples", [])
            if not tuples:
                return JSONResponse(
                    content={"error": "invalid_request", "error_description": "tuples array is required"},
                    status_code=400,
                )
            manager = get_fga_manager(auth)
            result = await manager.write_tuples(tuples)
            return result
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /auth/expand
# -----------------------------------------------------------------------------
@XWAction(
    operationId="fga_expand",
    summary="Expand Permission Tree",
    method="GET",
    description="""
    Expand permission tree for debugging (Zanzibar-style).
    Shows all relationships that grant access, including indirect paths.
    Security: Requires Bearer token authentication.
    """,
    tags=AUTHZ_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "Permission tree expansion"},
        400: {"description": "Invalid request"},
        401: {"description": "Authentication required"},
    },
    rate_limit="100/hour",
    audit=True,
    in_types={
        "user": {
            "type": "string",
            "description": "User identifier",
            "minLength": 1,
            "maxLength": 256
        },
        "relation": {
            "type": "string",
            "description": "Relation type",
            "minLength": 1,
            "maxLength": 128
        },
        "object": {
            "type": "string",
            "description": "Object identifier",
            "minLength": 1,
            "maxLength": 256
        }
    },
)
async def fga_expand(request: Request) -> Any:
    """Expand permission tree for debugging."""
    user_id = await get_current_user_id(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "fga_expand"):
            user = request.query_params.get("user")
            relation = request.query_params.get("relation")
            object = request.query_params.get("object")
            if not all([user, relation, object]):
                return JSONResponse(
                    content={"error": "invalid_request", "error_description": "user, relation, and object parameters are required"},
                    status_code=400,
                )
            manager = get_fga_manager(auth)
            result = await manager.expand(user, relation, object)
            return result
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /auth/permissions/me
# -----------------------------------------------------------------------------
@XWAction(
    operationId="fga_permissions_me",
    summary="List Current User's Permissions",
    method="GET",
    description="""
    List all permissions (relationship tuples) for the current authenticated user.
    Security: Requires Bearer token authentication.
    """,
    tags=AUTHZ_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "List of user permissions"},
        401: {"description": "Authentication required"},
    },
    rate_limit="100/hour",
    audit=True,
    in_types={},  # Exclude Request parameter from schema
)
async def fga_permissions_me(request: Request) -> Any:
    """List all permissions for the current user."""
    user_id = await get_current_user_id(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    auth = get_auth(request)
    manager = get_fga_manager(auth)
    try:
        async with track_critical_handler(request, "fga_permissions_me"):
            perms = await manager.list_user_permissions(user_id)
            return {"permissions": perms}
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
