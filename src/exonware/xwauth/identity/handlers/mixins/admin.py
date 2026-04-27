# exonware/xwauth/handlers/mixins/admin.py
"""Admin: audit logs, impersonate, users CRUD."""

from __future__ import annotations
from datetime import datetime
from typing import Any, Optional
from fastapi import Request, Depends, Header
from fastapi.responses import JSONResponse, RedirectResponse, Response
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
from exonware.xwauth.identity.ops_hooks import track_critical_handler
from .._common import (
    ADMIN_TAGS,
    get_auth,
    get_audit_log_manager,
    get_user_lifecycle,
    introspect_and_check_admin,
)
# -----------------------------------------------------------------------------
# GET /admin/audit-logs
# -----------------------------------------------------------------------------
@XWAction(
    operationId="admin_audit_logs",
    summary="Query Audit Logs (Admin)",
    method="GET",
    description="""
    Query audit logs with filtering and pagination.
    Supports filtering by:
    - user_id: Filter by user identifier
    - event_type: Filter by event type (e.g., "login.succeeded", "user.created")
    - start_date: Filter by start date (ISO 8601 format)
    - end_date: Filter by end date (ISO 8601 format)
    Supports pagination:
    - limit: Maximum number of results (default: 100, max: 1000)
    - offset: Pagination offset (default: 0)
    Security: Requires admin scope.
    """,
    tags=ADMIN_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "Audit logs query result"},
        401: {"description": "Authentication required"},
        403: {"description": "Admin scope required"},
    },
    examples={
        "query_logs": {
            "user_id": "user123",
            "event_type": "login.succeeded",
            "start_date": "2026-01-01T00:00:00Z",
            "end_date": "2026-01-31T23:59:59Z",
            "limit": 50,
            "offset": 0
        }
    },
    rate_limit="100/hour",
    audit=True,
    in_types={
        "user_id": {
            "type": "string",
            "description": "Filter by user identifier",
            "maxLength": 256
        },
        "event_type": {
            "type": "string",
            "description": "Filter by event type",
            "enum": [
                "login.succeeded", "login.failed", "logout",
                "password.changed", "password.reset",
                "mfa.enrolled", "mfa.removed", "mfa.verified",
                "token.issued", "token.revoked",
                "user.created", "user.deleted", "user.updated",
                "role.assigned", "role.removed",
                "org.created", "org.deleted", "org.updated",
                "admin.action"
            ]
        },
        "start_date": {
            "type": "string",
            "description": "Filter by start date (ISO 8601 format)",
            "format": "date-time"
        },
        "end_date": {
            "type": "string",
            "description": "Filter by end date (ISO 8601 format)",
            "format": "date-time"
        },
        "limit": {
            "type": "integer",
            "description": "Maximum number of results",
            "minimum": 1,
            "maximum": 1000,
            "default": 100
        },
        "offset": {
            "type": "integer",
            "description": "Pagination offset",
            "minimum": 0,
            "default": 0
        }
    },
)
async def admin_audit_logs(request: Request) -> Any:
    """Query audit logs (admin only)."""
    user_id, _ir, has_admin = await introspect_and_check_admin(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if not has_admin:
        return JSONResponse(
            content={"error": "forbidden", "error_description": "admin scope required"},
            status_code=403,
        )
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "admin_audit_logs"):
            # Parse query parameters
            user_id_filter = request.query_params.get("user_id")
            event_type = request.query_params.get("event_type")
            start_date_str = request.query_params.get("start_date")
            end_date_str = request.query_params.get("end_date")
            limit = int(request.query_params.get("limit", 100))
            offset = int(request.query_params.get("offset", 0))
            # Validate limit
            if limit > 1000:
                limit = 1000
            if limit < 1:
                limit = 100
            # Parse dates
            start_date = None
            if start_date_str:
                try:
                    start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
                except Exception:
                    return JSONResponse(
                        content={"error": "invalid_request", "error_description": "Invalid start_date format. Use ISO 8601."},
                        status_code=400,
                    )
            end_date = None
            if end_date_str:
                try:
                    end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
                except Exception:
                    return JSONResponse(
                        content={"error": "invalid_request", "error_description": "Invalid end_date format. Use ISO 8601."},
                        status_code=400,
                    )
            manager = get_audit_log_manager(auth)
            result = await manager.query_logs(
                user_id=user_id_filter,
                event_type=event_type,
                start_date=start_date,
                end_date=end_date,
                limit=limit,
                offset=offset,
            )
            return result
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# Admin User Management Endpoints
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# POST /admin/impersonate/{user_id}
# -----------------------------------------------------------------------------
@XWAction(
    operationId="admin_impersonate",
    summary="Generate Impersonation Token (Admin)",
    method="POST",
    description="""
    Generate an impersonation token for a user (admin only).
    Impersonation tokens are short-lived and marked with an 'impersonated' claim
    to indicate they were generated by an admin for impersonation purposes.
    Security: Requires admin scope.
    """,
    tags=ADMIN_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "Impersonation token generated"},
        401: {"description": "Authentication required"},
        403: {"description": "Admin scope required"},
        404: {"description": "User not found"},
    },
    examples={
        "impersonation_token": {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "Bearer",
            "expires_in": 3600,
            "impersonated": True,
            "impersonated_by": "admin_user_id"
        }
    },
    rate_limit="10/hour",
    audit=True,
    in_types={
        "user_id": {
            "type": "string",
            "description": "User identifier to impersonate",
            "minLength": 1,
            "maxLength": 256
        },
        "expires_in": {
            "type": "integer",
            "description": "Token expiration in seconds (default: 3600, max: 86400)",
            "minimum": 60,
            "maximum": 86400,
            "default": 3600
        },
        "scopes": {
            "type": "array",
            "description": "Scopes for the impersonation token",
            "items": {"type": "string"},
            "default": ["openid", "profile", "email"]
        }
    },
)
async def admin_impersonate(user_id: str, request: Request) -> Any:
    """Generate impersonation token for a user."""
    admin_user_id, _ir, has_admin = await introspect_and_check_admin(request)
    if not admin_user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if not has_admin:
        return JSONResponse(
            content={"error": "forbidden", "error_description": "admin scope required"},
            status_code=403,
        )
    auth = get_auth(request)
    body_data = await request.json() if hasattr(request, 'json') else {}
    try:
        async with track_critical_handler(request, "admin_impersonate"):
            # Verify target user exists
            user_lifecycle = get_user_lifecycle(auth)
            target_user = await user_lifecycle.get_user(user_id)
            if not target_user:
                return JSONResponse(
                    content={"error": "not_found", "error_description": "User not found"},
                    status_code=404,
                )
            # Get scopes and expiration
            scopes = body_data.get("scopes", ["openid", "profile", "email"])
            expires_in = min(body_data.get("expires_in", 3600), 86400)  # Max 24 hours
            # Generate impersonation token with special claims
            token_manager = auth._token_manager
            if token_manager._jwt_manager:
                # Generate JWT with impersonation claims
                additional_claims = {
                    "impersonated": True,
                    "impersonated_by": admin_user_id,
                    "original_sub": user_id,
                }
                impersonation_token = token_manager._jwt_manager.generate_token(
                    user_id=user_id,
                    client_id="admin_impersonation",
                    scopes=scopes,
                    expires_in=expires_in,
                    additional_claims=additional_claims,
                )
            else:
                # Fallback to standard token generation
                impersonation_token = await token_manager.generate_access_token(
                    user_id=user_id,
                    client_id="admin_impersonation",
                    scopes=scopes,
                )
            return {
                "access_token": impersonation_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "impersonated": True,
                "impersonated_by": admin_user_id,
            }
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /admin/users/{user_id}
# -----------------------------------------------------------------------------
@XWAction(
    operationId="admin_users_get",
    summary="Get User Details (Admin)",
    method="GET",
    description="""
    Get detailed user information by ID (admin only).
    Security: Requires admin scope.
    """,
    tags=ADMIN_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "User details"},
        401: {"description": "Authentication required"},
        403: {"description": "Admin scope required"},
        404: {"description": "User not found"},
    },
    rate_limit="100/hour",
    audit=True,
    in_types={
        "user_id": {
            "type": "string",
            "description": "User identifier",
            "minLength": 1,
            "maxLength": 256
        }
    },
)
async def admin_users_get(user_id: str, request: Request) -> Any:
    """Get user details (admin only)."""
    admin_user_id, _ir, has_admin = await introspect_and_check_admin(request)
    if not admin_user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if not has_admin:
        return JSONResponse(
            content={"error": "forbidden", "error_description": "admin scope required"},
            status_code=403,
        )
    auth = get_auth(request)
    user_lifecycle = get_user_lifecycle(auth)
    try:
        async with track_critical_handler(request, "admin_users_get"):
            user = await user_lifecycle.get_user(user_id)
            if not user:
                return JSONResponse(
                    content={"error": "not_found", "error_description": "User not found"},
                    status_code=404,
                )
            # Get user roles
            from exonware.xwauth.identity.authorization.rbac import RBACAuthorizer
            rbac = RBACAuthorizer(auth)
            roles = await rbac.get_user_roles(user_id)
            return {
                "user_id": user.id,
                "email": user.email,
                "status": user.status.value if hasattr(user.status, 'value') else str(user.status),
                "roles": roles,
                "attributes": user.attributes,
                "created_at": user.created_at.isoformat() if hasattr(user.created_at, 'isoformat') else str(user.created_at),
                "updated_at": user.updated_at.isoformat() if hasattr(user.updated_at, 'isoformat') else str(user.updated_at),
            }
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# PUT /admin/users/{user_id}
# -----------------------------------------------------------------------------
@XWAction(
    operationId="admin_users_update",
    summary="Update User (Admin)",
    method="PUT",
    description="""
    Update user information (admin only).
    Security: Requires admin scope.
    """,
    tags=ADMIN_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "User updated"},
        400: {"description": "Invalid request"},
        401: {"description": "Authentication required"},
        403: {"description": "Admin scope required"},
        404: {"description": "User not found"},
    },
    rate_limit="50/hour",
    audit=True,
    in_types={
        "user_id": {
            "type": "string",
            "description": "User identifier",
            "minLength": 1,
            "maxLength": 256
        },
        "email": {
            "type": "string",
            "description": "User email",
            "format": "email",
            "maxLength": 256
        },
        "status": {
            "type": "string",
            "description": "User status",
            "enum": ["active", "inactive", "suspended", "deleted"]
        },
        "attributes": {
            "type": "object",
            "description": "User attributes to update"
        }
    },
)
async def admin_users_update(user_id: str, request: Request) -> Any:
    """Update user (admin only)."""
    admin_user_id, _ir, has_admin = await introspect_and_check_admin(request)
    if not admin_user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if not has_admin:
        return JSONResponse(
            content={"error": "forbidden", "error_description": "admin scope required"},
            status_code=403,
        )
    auth = get_auth(request)
    body_data = await request.json() if hasattr(request, 'json') else {}
    try:
        async with track_critical_handler(request, "admin_users_update"):
            user_lifecycle = get_user_lifecycle(auth)
            # Verify user exists
            user = await user_lifecycle.get_user(user_id)
            if not user:
                return JSONResponse(
                    content={"error": "not_found", "error_description": "User not found"},
                    status_code=404,
                )
            # Build updates
            updates = {}
            if "email" in body_data:
                updates["email"] = body_data["email"]
            if "status" in body_data:
                from exonware.xwauth.identity.defs import UserStatus
                try:
                    updates["status"] = UserStatus(body_data["status"])
                except ValueError:
                    return JSONResponse(
                        content={"error": "invalid_request", "error_description": f"Invalid status: {body_data['status']}"},
                        status_code=400,
                    )
            if "attributes" in body_data:
                # Merge attributes
                current_attrs = user.attributes.copy() if hasattr(user, 'attributes') else {}
                current_attrs.update(body_data["attributes"])
                updates["attributes"] = current_attrs
            # Update user
            updated_user = await user_lifecycle.update_user(user_id, updates)
            return {
                "user_id": updated_user.id,
                "email": updated_user.email,
                "status": updated_user.status.value if hasattr(updated_user.status, 'value') else str(updated_user.status),
                "attributes": updated_user.attributes,
            }
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# DELETE /admin/users/{user_id}
# -----------------------------------------------------------------------------
@XWAction(
    operationId="admin_users_delete",
    summary="Delete User (Admin)",
    method="DELETE",
    description="""
    Delete a user (admin only).
    Security: Requires admin scope.
    """,
    tags=ADMIN_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        204: {"description": "User deleted"},
        401: {"description": "Authentication required"},
        403: {"description": "Admin scope required"},
        404: {"description": "User not found"},
    },
    rate_limit="10/hour",
    audit=True,
    in_types={
        "user_id": {
            "type": "string",
            "description": "User identifier",
            "minLength": 1,
            "maxLength": 256
        }
    },
)
async def admin_users_delete(user_id: str, request: Request) -> Any:
    """Delete user (admin only)."""
    admin_user_id, _ir, has_admin = await introspect_and_check_admin(request)
    if not admin_user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if not has_admin:
        return JSONResponse(
            content={"error": "forbidden", "error_description": "admin scope required"},
            status_code=403,
        )
    auth = get_auth(request)
    user_lifecycle = get_user_lifecycle(auth)
    try:
        async with track_critical_handler(request, "admin_users_delete"):
            # Verify user exists
            user = await user_lifecycle.get_user(user_id)
            if not user:
                return JSONResponse(
                    content={"error": "not_found", "error_description": "User not found"},
                    status_code=404,
                )
            # Delete user
            await user_lifecycle.delete_user(user_id)
            return Response(status_code=204)
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# POST /admin/users/{user_id}/roles
# -----------------------------------------------------------------------------
@XWAction(
    operationId="admin_users_assign_role",
    summary="Assign Role to User (Admin)",
    method="POST",
    description="""
    Assign a role to a user (admin only).
    Security: Requires admin scope.
    """,
    tags=ADMIN_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "Role assigned"},
        400: {"description": "Invalid request"},
        401: {"description": "Authentication required"},
        403: {"description": "Admin scope required"},
        404: {"description": "User not found"},
    },
    rate_limit="50/hour",
    audit=True,
    in_types={
        "user_id": {
            "type": "string",
            "description": "User identifier",
            "minLength": 1,
            "maxLength": 256
        },
        "role": {
            "type": "string",
            "description": "Role name to assign",
            "minLength": 1,
            "maxLength": 128
        }
    },
)
async def admin_users_assign_role(user_id: str, request: Request) -> Any:
    """Assign role to user (admin only)."""
    admin_user_id, _ir, has_admin = await introspect_and_check_admin(request)
    if not admin_user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if not has_admin:
        return JSONResponse(
            content={"error": "forbidden", "error_description": "admin scope required"},
            status_code=403,
        )
    auth = get_auth(request)
    body_data = await request.json() if hasattr(request, 'json') else {}
    try:
        async with track_critical_handler(request, "admin_users_assign_role"):
            user_lifecycle = get_user_lifecycle(auth)
            # Verify user exists
            user = await user_lifecycle.get_user(user_id)
            if not user:
                return JSONResponse(
                    content={"error": "not_found", "error_description": "User not found"},
                    status_code=404,
                )
            role = body_data.get("role")
            if not role:
                return JSONResponse(
                    content={"error": "invalid_request", "error_description": "role is required"},
                    status_code=400,
                )
            # Get current roles
            from exonware.xwauth.identity.authorization.rbac import RBACAuthorizer
            rbac = RBACAuthorizer(auth)
            current_roles = await rbac.get_user_roles(user_id)
            # Add role if not already present
            if role not in current_roles:
                current_roles.append(role)
                await user_lifecycle.update_user(user_id, {
                    "attributes": {
                        **user.attributes,
                        "roles": current_roles,
                    }
                })
            return {
                "user_id": user_id,
                "role": role,
                "roles": current_roles,
            }
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# DELETE /admin/users/{user_id}/roles/{role}
# -----------------------------------------------------------------------------
@XWAction(
    operationId="admin_users_remove_role",
    summary="Remove Role from User (Admin)",
    method="DELETE",
    description="""
    Remove a role from a user (admin only).
    Security: Requires admin scope.
    """,
    tags=ADMIN_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "Role removed"},
        401: {"description": "Authentication required"},
        403: {"description": "Admin scope required"},
        404: {"description": "User or role not found"},
    },
    rate_limit="50/hour",
    audit=True,
    in_types={
        "user_id": {
            "type": "string",
            "description": "User identifier",
            "minLength": 1,
            "maxLength": 256
        },
        "role": {
            "type": "string",
            "description": "Role name to remove",
            "minLength": 1,
            "maxLength": 128
        }
    },
)
async def admin_users_remove_role(user_id: str, role: str, request: Request) -> Any:
    """Remove role from user (admin only)."""
    admin_user_id, _ir, has_admin = await introspect_and_check_admin(request)
    if not admin_user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if not has_admin:
        return JSONResponse(
            content={"error": "forbidden", "error_description": "admin scope required"},
            status_code=403,
        )
    auth = get_auth(request)
    user_lifecycle = get_user_lifecycle(auth)
    try:
        async with track_critical_handler(request, "admin_users_remove_role"):
            # Verify user exists
            user = await user_lifecycle.get_user(user_id)
            if not user:
                return JSONResponse(
                    content={"error": "not_found", "error_description": "User not found"},
                    status_code=404,
                )
            # Get current roles
            from exonware.xwauth.identity.authorization.rbac import RBACAuthorizer
            rbac = RBACAuthorizer(auth)
            current_roles = await rbac.get_user_roles(user_id)
            # Remove role if present
            if role not in current_roles:
                return JSONResponse(
                    content={"error": "not_found", "error_description": f"User does not have role: {role}"},
                    status_code=404,
                )
            current_roles.remove(role)
            await user_lifecycle.update_user(user_id, {
                "attributes": {
                    **user.attributes,
                    "roles": current_roles,
                }
            })
            return {
                "user_id": user_id,
                "role": role,
                "roles": current_roles,
            }
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /admin/users
# -----------------------------------------------------------------------------
@XWAction(
    operationId="admin_users_list",
    summary="List Users (Admin)",
    method="GET",
    description="List all users (admin only).",
    tags=ADMIN_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={},  # Exclude Request parameter from schema (FastAPI dependency, not user input)
)
async def admin_list_users(request: Request) -> Any:
    user_id, _ir, has_admin = await introspect_and_check_admin(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if not has_admin:
        return JSONResponse(
            content={"error": "forbidden", "error_description": "admin scope required"},
            status_code=403,
        )
    auth = get_auth(request)
    user_lifecycle = get_user_lifecycle(auth)
    try:
        async with track_critical_handler(request, "admin_users_list"):
            users = await user_lifecycle.list_users()
            return {
                "users": [
                    {
                        "user_id": user.id,
                        "email": user.email,
                        "created_at": user.created_at.isoformat() if hasattr(user.created_at, "isoformat") else str(user.created_at),
                    }
                    for user in users
                ]
            }
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
