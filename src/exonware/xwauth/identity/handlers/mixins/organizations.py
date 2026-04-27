# exonware/xwauth/handlers/mixins/organizations.py
"""Organizations: CRUD, members, invite, users_me_organizations."""

from __future__ import annotations
from typing import Any, Optional
from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
from exonware.xwauth.identity.ops_hooks import track_critical_handler
from exonware.xwsystem.security.tenancy import tenancy_violation_for_path_org

from .._common import (
    ORG_TAGS,
    USER_TAGS,
    get_auth,
    get_bearer_user_and_introspection,
    get_current_user_id,
    get_organization_lifecycle,
    get_organization_manager,
    json_response_for_token_org_path_mismatch,
)


def _org_token_path_alignment_or_response(introspection: dict | None, path_org_id: str) -> JSONResponse | None:
    """403 when JWT/introspection org_id disagrees with URL org (IDOR hardening for org-bound tokens)."""
    if tenancy_violation_for_path_org(introspection, path_org_id):
        return JSONResponse(
            content=json_response_for_token_org_path_mismatch(),
            status_code=403,
        )
    return None
# -----------------------------------------------------------------------------
# GET /organizations
# -----------------------------------------------------------------------------
@XWAction(
    operationId="organizations_list",
    summary="List User's Organizations",
    method="GET",
    description="""
    List all organizations the current authenticated user belongs to.
    Returns organizations with their metadata, roles, and membership information.
    Security: Requires Bearer token authentication.
    """,
    tags=ORG_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "List of organizations"},
        401: {"description": "Authentication required"},
    },
    rate_limit="100/hour",
    audit=True,
    in_types={},  # Exclude Request parameter from schema - Request is injected by FastAPI
)
async def organizations_list(request: Request) -> Any:
    """List all organizations for current user."""
    user_id = await get_current_user_id(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "organizations_list"):
            lifecycle = get_organization_lifecycle(auth)
            orgs = await lifecycle.list_user_organizations(user_id)
            # Get user's role in each organization
            manager = get_organization_manager(auth)
            result = []
            for org in orgs:
                role = await manager.get_member_role(org.id, user_id)
                org_dict = org.to_dict()
                org_dict["role"] = role
                result.append(org_dict)
            return {"organizations": result}
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# POST /organizations
# -----------------------------------------------------------------------------
@XWAction(
    operationId="organizations_create",
    summary="Create Organization",
    method="POST",
    description="""
    Create a new organization.
    The creator automatically becomes the owner of the organization.
    Security: Requires Bearer token authentication.
    """,
    tags=ORG_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        201: {"description": "Organization created"},
        400: {"description": "Invalid request"},
        401: {"description": "Authentication required"},
    },
    rate_limit="10/hour",
    audit=True,
    in_types={
        "name": {
            "type": "string",
            "description": "Organization name",
            "minLength": 1,
            "maxLength": 256
        },
        "slug": {
            "type": "string",
            "description": "URL-friendly organization identifier (auto-generated if not provided)",
            "minLength": 1,
            "maxLength": 100,
            "pattern": "^[a-z0-9-]+$"
        },
        "description": {
            "type": "string",
            "description": "Organization description",
            "maxLength": 2048
        },
        "metadata": {
            "type": "object",
            "description": "Organization metadata"
        }
    },
)
async def organizations_create(request: Request) -> Any:
    """Create a new organization."""
    user_id = await get_current_user_id(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    auth = get_auth(request)
    body_data = await request.json() if hasattr(request, 'json') else {}
    try:
        async with track_critical_handler(request, "organizations_create"):
            lifecycle = get_organization_lifecycle(auth)
            org = await lifecycle.create_organization(
                name=body_data.get("name"),
                slug=body_data.get("slug"),
                description=body_data.get("description"),
                metadata=body_data.get("metadata"),
                owner_id=user_id,
            )
            return JSONResponse(
                content=org.to_dict(),
                status_code=201,
            )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /organizations/{org_id}
# -----------------------------------------------------------------------------
@XWAction(
    operationId="organizations_get",
    summary="Get Organization Details",
    method="GET",
    description="""
    Get organization details by ID.
    Security: Requires Bearer token authentication.
    User must be a member of the organization.
    """,
    tags=ORG_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "Organization details"},
        401: {"description": "Authentication required"},
        403: {"description": "Not a member of this organization"},
        404: {"description": "Organization not found"},
    },
    rate_limit="100/hour",
    audit=True,
    in_types={
        "org_id": {
            "type": "string",
            "description": "Organization identifier",
            "minLength": 1,
            "maxLength": 256
        }
    },
)
async def organizations_get(org_id: str, request: Request) -> Any:
    """Get organization details."""
    user_id, introspection = await get_bearer_user_and_introspection(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if mis := _org_token_path_alignment_or_response(introspection, org_id):
        return mis
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "organizations_get"):
            lifecycle = get_organization_lifecycle(auth)
            org = await lifecycle.get_organization(org_id)
            if not org:
                return JSONResponse(
                    content={"error": "not_found", "error_description": "Organization not found"},
                    status_code=404,
                )
            # Check if user is a member
            manager = get_organization_manager(auth)
            role = await manager.get_member_role(org_id, user_id)
            if not role:
                return JSONResponse(
                    content={"error": "forbidden", "error_description": "Not a member of this organization"},
                    status_code=403,
                )
            org_dict = org.to_dict()
            org_dict["role"] = role
            return org_dict
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# PUT /organizations/{org_id}
# -----------------------------------------------------------------------------
@XWAction(
    operationId="organizations_update",
    summary="Update Organization",
    method="PUT",
    description="""
    Update organization details.
    Requires admin or owner role in the organization.
    Security: Requires Bearer token authentication.
    """,
    tags=ORG_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "Organization updated"},
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Organization not found"},
    },
    rate_limit="50/hour",
    audit=True,
    in_types={
        "org_id": {
            "type": "string",
            "description": "Organization identifier",
            "minLength": 1,
            "maxLength": 256
        },
        "name": {
            "type": "string",
            "description": "Organization name",
            "minLength": 1,
            "maxLength": 256
        },
        "slug": {
            "type": "string",
            "description": "URL-friendly organization identifier",
            "minLength": 1,
            "maxLength": 100,
            "pattern": "^[a-z0-9-]+$"
        },
        "description": {
            "type": "string",
            "description": "Organization description",
            "maxLength": 2048
        },
        "metadata": {
            "type": "object",
            "description": "Organization metadata"
        }
    },
)
async def organizations_update(org_id: str, request: Request) -> Any:
    """Update organization."""
    user_id, introspection = await get_bearer_user_and_introspection(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if mis := _org_token_path_alignment_or_response(introspection, org_id):
        return mis
    auth = get_auth(request)
    body_data = await request.json() if hasattr(request, 'json') else {}
    try:
        async with track_critical_handler(request, "organizations_update"):
            # Check permissions
            manager = get_organization_manager(auth)
            role = await manager.get_member_role(org_id, user_id)
            if not role or role not in ["owner", "admin"]:
                return JSONResponse(
                    content={"error": "forbidden", "error_description": "Insufficient permissions"},
                    status_code=403,
                )
            lifecycle = get_organization_lifecycle(auth)
            updates = {}
            if "name" in body_data:
                updates["name"] = body_data["name"]
            if "slug" in body_data:
                updates["slug"] = body_data["slug"]
            if "description" in body_data:
                updates["description"] = body_data["description"]
            if "metadata" in body_data:
                updates["metadata"] = body_data["metadata"]
            org = await lifecycle.update_organization(org_id, updates)
            return org.to_dict()
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /users/me/organizations
# -----------------------------------------------------------------------------
@XWAction(
    operationId="users_me_organizations",
    summary="List Current User's Organizations",
    method="GET",
    description="""
    List all organizations the current authenticated user belongs to.
    Alias for GET /organizations for convenience.
    Security: Requires Bearer token authentication.
    """,
    tags=USER_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "List of organizations"},
        401: {"description": "Authentication required"},
    },
    rate_limit="100/hour",
    audit=True,
    in_types={},  # Exclude Request parameter from schema - Request is injected by FastAPI
)
async def users_me_organizations(request: Request) -> Any:
    """List current user's organizations (alias for GET /organizations)."""
    return await organizations_list(request)
# -----------------------------------------------------------------------------
# POST /organizations/{org_id}/invitations
# -----------------------------------------------------------------------------
@XWAction(
    operationId="organizations_invite",
    summary="Invite Member to Organization",
    method="POST",
    description="""
    Invite a member to an organization by email.
    Requires admin or owner role in the organization.
    Security: Requires Bearer token authentication.
    """,
    tags=ORG_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        201: {"description": "Invitation created"},
        400: {"description": "Invalid request"},
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Organization not found"},
    },
    rate_limit="50/hour",
    audit=True,
    in_types={
        "org_id": {
            "type": "string",
            "description": "Organization identifier",
            "minLength": 1,
            "maxLength": 256
        },
        "email": {
            "type": "string",
            "description": "Email address of invitee",
            "format": "email",
            "minLength": 1,
            "maxLength": 256
        },
        "role": {
            "type": "string",
            "description": "Role to assign (default: 'member')",
            "enum": ["owner", "admin", "member"],
            "default": "member"
        }
    },
)
async def organizations_invite(org_id: str, request: Request) -> Any:
    """Invite a member to an organization."""
    user_id, introspection = await get_bearer_user_and_introspection(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if mis := _org_token_path_alignment_or_response(introspection, org_id):
        return mis
    auth = get_auth(request)
    body_data = await request.json() if hasattr(request, 'json') else {}
    try:
        async with track_critical_handler(request, "organizations_invite"):
            # Check permissions
            manager = get_organization_manager(auth)
            role = await manager.get_member_role(org_id, user_id)
            if not role or role not in ["owner", "admin"]:
                return JSONResponse(
                    content={"error": "forbidden", "error_description": "Insufficient permissions"},
                    status_code=403,
                )
            invitation = await manager.invite_member(
                org_id=org_id,
                email=body_data.get("email"),
                role=body_data.get("role", "member"),
                inviter_id=user_id,
            )
            return JSONResponse(
                content=invitation,
                status_code=201,
            )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /organizations/{org_id}/members
# -----------------------------------------------------------------------------
@XWAction(
    operationId="organizations_members_list",
    summary="List Organization Members",
    method="GET",
    description="""
    List all members of an organization.
    Requires member role or higher in the organization.
    Security: Requires Bearer token authentication.
    """,
    tags=ORG_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "List of members"},
        401: {"description": "Authentication required"},
        403: {"description": "Not a member of this organization"},
        404: {"description": "Organization not found"},
    },
    rate_limit="100/hour",
    audit=True,
    in_types={
        "org_id": {
            "type": "string",
            "description": "Organization identifier",
            "minLength": 1,
            "maxLength": 256
        }
    },
)
async def organizations_members_list(org_id: str, request: Request) -> Any:
    """List all members of an organization."""
    user_id, introspection = await get_bearer_user_and_introspection(request)
    if not user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if mis := _org_token_path_alignment_or_response(introspection, org_id):
        return mis
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "organizations_members_list"):
            # Check if user is a member
            manager = get_organization_manager(auth)
            role = await manager.get_member_role(org_id, user_id)
            if not role:
                return JSONResponse(
                    content={"error": "forbidden", "error_description": "Not a member of this organization"},
                    status_code=403,
                )
            members = await manager.list_members(org_id)
            return {"members": members}
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# PATCH /organizations/{org_id}/members/{user_id}/role
# -----------------------------------------------------------------------------
@XWAction(
    operationId="organizations_members_update_role",
    summary="Update Member Role",
    method="PATCH",
    description="""
    Update a member's role in an organization.
    Requires admin or owner role in the organization.
    Security: Requires Bearer token authentication.
    """,
    tags=ORG_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "Role updated"},
        400: {"description": "Invalid request"},
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Organization or member not found"},
    },
    rate_limit="50/hour",
    audit=True,
    in_types={
        "org_id": {
            "type": "string",
            "description": "Organization identifier",
            "minLength": 1,
            "maxLength": 256
        },
        "user_id": {
            "type": "string",
            "description": "User identifier",
            "minLength": 1,
            "maxLength": 256
        },
        "role": {
            "type": "string",
            "description": "New role",
            "enum": ["owner", "admin", "member"],
            "minLength": 1
        }
    },
)
async def organizations_members_update_role(org_id: str, user_id: str, request: Request) -> Any:
    """Update a member's role."""
    current_user_id, introspection = await get_bearer_user_and_introspection(request)
    if not current_user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if mis := _org_token_path_alignment_or_response(introspection, org_id):
        return mis
    auth = get_auth(request)
    body_data = await request.json() if hasattr(request, 'json') else {}
    try:
        async with track_critical_handler(request, "organizations_members_update_role"):
            # Check permissions
            manager = get_organization_manager(auth)
            current_role = await manager.get_member_role(org_id, current_user_id)
            if not current_role or current_role not in ["owner", "admin"]:
                return JSONResponse(
                    content={"error": "forbidden", "error_description": "Insufficient permissions"},
                    status_code=403,
                )
            role = body_data.get("role")
            if not role:
                return JSONResponse(
                    content={"error": "invalid_request", "error_description": "Role is required"},
                    status_code=400,
                )
            result = await manager.update_member_role(
                org_id, user_id, role, actor_user_id=current_user_id
            )
            return result
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# DELETE /organizations/{org_id}/members/{user_id}
# -----------------------------------------------------------------------------
@XWAction(
    operationId="organizations_members_remove",
    summary="Remove Member from Organization",
    method="DELETE",
    description="""
    Remove a member from an organization.
    Requires admin or owner role in the organization.
    Cannot remove the last owner.
    Security: Requires Bearer token authentication.
    """,
    tags=ORG_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        204: {"description": "Member removed"},
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Organization or member not found"},
    },
    rate_limit="50/hour",
    audit=True,
    in_types={
        "org_id": {
            "type": "string",
            "description": "Organization identifier",
            "minLength": 1,
            "maxLength": 256
        },
        "user_id": {
            "type": "string",
            "description": "User identifier",
            "minLength": 1,
            "maxLength": 256
        }
    },
)
async def organizations_members_remove(org_id: str, user_id: str, request: Request) -> Any:
    """Remove a member from an organization."""
    current_user_id, introspection = await get_bearer_user_and_introspection(request)
    if not current_user_id:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required"},
            status_code=401,
        )
    if mis := _org_token_path_alignment_or_response(introspection, org_id):
        return mis
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "organizations_members_remove"):
            # Check permissions
            manager = get_organization_manager(auth)
            current_role = await manager.get_member_role(org_id, current_user_id)
            if not current_role or current_role not in ["owner", "admin"]:
                return JSONResponse(
                    content={"error": "forbidden", "error_description": "Insufficient permissions"},
                    status_code=403,
                )
            await manager.remove_member(org_id, user_id)
            return Response(status_code=204)
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
