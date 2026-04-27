"""SCIM and policy explain endpoints."""

from __future__ import annotations

from dataclasses import asdict
from uuid import uuid4
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwsystem.security.contracts import AuthContext

from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
from exonware.xwauth.identity.ops_hooks import track_critical_handler
from .._common import (
    AUTHZ_TAGS,
    SCIM_TAGS,
    get_auth,
    get_bearer_token,
    get_scim_group_service,
    get_scim_user_service,
)
from ...scim import ScimPatchOperation


async def _resolve_auth_context_or_none(request: Request) -> AuthContext | None:
    token = get_bearer_token(request)
    if not token:
        return None
    auth = get_auth(request)
    return await auth.resolve_auth_context(token)


def _scim_unauthorized() -> JSONResponse:
    return JSONResponse(
        content={"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "status": "401", "detail": "Authentication required"},
        status_code=401,
    )

def _scim_error(status: int, detail: str) -> JSONResponse:
    return JSONResponse(
        content={"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "status": str(status), "detail": detail},
        status_code=status,
    )

def _etag_headers_from_resource(resource: Any) -> dict[str, str]:
    meta = getattr(resource, "meta", None)
    version = getattr(meta, "version", None) if meta is not None else None
    if isinstance(version, str) and version.strip():
        return {"ETag": version}
    return {}

def _scim_org_query_matches_token(request: Request, context: AuthContext) -> bool:
    """Optional org_id query param must match token org when the token is org-bound (tenant-safe SCIM)."""
    org_q = (request.query_params.get("org_id") or "").strip()
    if not org_q:
        return True
    token_org = context.org_id
    if token_org is None or not str(token_org).strip():
        return True
    return str(token_org).strip() == org_q


def _matches_if_match(if_match_header: str | None, current_etag: str | None) -> bool:
    if if_match_header is None or not if_match_header.strip():
        return True
    if current_etag is None:
        return False
    if_match = if_match_header.strip()
    return if_match == "*" or if_match == current_etag


def _extract_scim_query_paging(request: Request) -> tuple[str | None, int, int]:
    filter_expression = request.query_params.get("filter")
    try:
        start_index = int(request.query_params.get("startIndex", 1))
    except Exception:
        start_index = 1
    try:
        count = int(request.query_params.get("count", 100))
    except Exception:
        count = 100
    return filter_expression, start_index, count


@XWAction(
    operationId="policy_explain",
    summary="Explain Authorization Decision",
    method="POST",
    description="Return an explainable authorization decision trace for resource/action.",
    tags=AUTHZ_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={200: {"description": "Decision and trace"}, 401: {"description": "Authentication required"}},
)
async def policy_explain(request: Request) -> Any:
    auth = get_auth(request)
    context = await _resolve_auth_context_or_none(request)
    body_data = await request.json() if hasattr(request, "json") else {}
    if context is None:
        raw_context = body_data.get("context")
        if isinstance(raw_context, dict):
            claims_map = dict(raw_context.get("claims") or {})
            org_fallback = raw_context.get("org_id") or raw_context.get("organization_id")
            proj_fallback = raw_context.get("project_id") or raw_context.get("application_id")
            context = AuthContext(
                subject_id=str(raw_context.get("subject_id") or raw_context.get("sub") or raw_context.get("user_id") or "anonymous"),
                tenant_id=raw_context.get("tenant_id"),
                org_id=org_fallback or claims_map.get("org_id") or claims_map.get("organization_id"),
                project_id=proj_fallback or claims_map.get("project_id") or claims_map.get("application_id"),
                scopes=list(raw_context.get("scopes") or []),
                roles=list(raw_context.get("roles") or []),
                claims=claims_map,
            )
    if context is None:
        return JSONResponse(
            content={"error": "unauthorized", "error_description": "Authentication required or context payload"},
            status_code=401,
        )
    resource = str(body_data.get("resource") or "").strip()
    action = str(body_data.get("action") or "").strip()
    if not resource or not action:
        return JSONResponse(
            content={"error": "invalid_request", "error_description": "resource and action are required"},
            status_code=400,
        )
    try:
        async with track_critical_handler(request, "policy_explain"):
            decision = auth.policy_decision_service.explain(
                context,
                resource=resource,
                action=action,
                org_id=body_data.get("org_id"),
                project_id=body_data.get("project_id"),
            )
            return {"allowed": decision.allowed, "trace": asdict(decision.trace)}
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


@XWAction(
    operationId="scim_service_provider_config",
    summary="SCIM Service Provider Config",
    method="GET",
    description="Return SCIM service provider capabilities.",
    tags=SCIM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={200: {"description": "SCIM provider config"}, 401: {"description": "Authentication required"}},
)
async def scim_service_provider_config(request: Request) -> Any:
    if await _resolve_auth_context_or_none(request) is None:
        return _scim_unauthorized()
    async with track_critical_handler(request, "scim_service_provider_config"):
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": True},
            "sort": {"supported": False},
            "etag": {"supported": True},
            "authenticationSchemes": [
                {
                    "name": "OAuth Bearer Token",
                    "description": "Authentication scheme using OAuth Bearer Token.",
                    "type": "oauthbearertoken",
                    "primary": True,
                }
            ],
        }


@XWAction(
    operationId="scim_resource_types",
    summary="SCIM ResourceTypes (RFC 7644 §4)",
    method="GET",
    description="Return the list of SCIM resource types supported by this service provider.",
    tags=SCIM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={200: {"description": "SCIM resource types list"}, 401: {"description": "Authentication required"}},
)
async def scim_resource_types(request: Request) -> Any:
    if await _resolve_auth_context_or_none(request) is None:
        return _scim_unauthorized()
    async with track_critical_handler(request, "scim_resource_types"):
        base = str(request.base_url).rstrip("/")
        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 2,
            "itemsPerPage": 2,
            "startIndex": 1,
            "Resources": [
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                    "id": "User",
                    "name": "User",
                    "endpoint": "/Users",
                    "description": "User Account",
                    "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
                    "meta": {"resourceType": "ResourceType", "location": f"{base}/v1/scim/v2/ResourceTypes/User"},
                },
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                    "id": "Group",
                    "name": "Group",
                    "endpoint": "/Groups",
                    "description": "Group",
                    "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
                    "meta": {"resourceType": "ResourceType", "location": f"{base}/v1/scim/v2/ResourceTypes/Group"},
                },
            ],
        }


@XWAction(
    operationId="scim_bulk",
    summary="SCIM Bulk (RFC 7644 §3.7)",
    method="POST",
    description=(
        "Execute multiple SCIM Users/Groups operations in one request. Dispatches "
        "each operation in the BulkRequest to the matching Users/Groups handler and "
        "collects per-operation results into a BulkResponse. Stops early if the "
        "``failOnErrors`` ceiling is reached."
    ),
    tags=SCIM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={200: {"description": "BulkResponse"}, 400: {"description": "Malformed BulkRequest"}, 401: {"description": "Authentication required"}},
)
async def scim_bulk(request: Request) -> Any:
    if await _resolve_auth_context_or_none(request) is None:
        return _scim_unauthorized()
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            content={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": "400",
                "scimType": "invalidSyntax",
                "detail": "Request body is not valid JSON",
            },
            status_code=400,
        )
    operations = body.get("Operations") if isinstance(body, dict) else None
    if not isinstance(operations, list):
        return JSONResponse(
            content={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": "400",
                "scimType": "invalidValue",
                "detail": "BulkRequest must include an 'Operations' array",
            },
            status_code=400,
        )
    fail_on_errors = body.get("failOnErrors") if isinstance(body, dict) else None
    try:
        fail_on_errors = int(fail_on_errors) if fail_on_errors is not None else None
    except (TypeError, ValueError):
        fail_on_errors = None

    results: list[dict[str, Any]] = []
    error_count = 0

    async with track_critical_handler(request, "scim_bulk"):
        for op in operations:
            method = (op.get("method") or "").upper() if isinstance(op, dict) else ""
            path = op.get("path") if isinstance(op, dict) else None
            bulk_id = op.get("bulkId") if isinstance(op, dict) else None
            data = op.get("data") if isinstance(op, dict) else None
            status_code, resource_location, err_detail = await _dispatch_bulk_operation(
                request, method, path, data
            )
            entry: dict[str, Any] = {
                "method": method,
                "status": str(status_code),
            }
            if bulk_id:
                entry["bulkId"] = bulk_id
            if resource_location:
                entry["location"] = resource_location
            if status_code >= 400:
                error_count += 1
                entry["response"] = {
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": str(status_code),
                    "detail": err_detail or "operation failed",
                }
                if fail_on_errors is not None and error_count >= fail_on_errors:
                    results.append(entry)
                    break
            results.append(entry)

    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],
        "Operations": results,
    }


async def _dispatch_bulk_operation(
    request: Request,
    method: str,
    path: Any,
    data: Any,
) -> tuple[int, str | None, str | None]:
    """
    Route one BulkRequest op to the matching Users/Groups handler.
    Returns (status, location, error_detail).
    """
    if not isinstance(path, str) or not path.startswith("/"):
        return 400, None, "path must start with '/' (relative SCIM path)"
    segments = [s for s in path.strip("/").split("/") if s]
    if not segments:
        return 400, None, "empty SCIM path"
    resource_type = segments[0]
    resource_id = segments[1] if len(segments) >= 2 else None
    base = str(request.base_url).rstrip("/")

    try:
        svc = (
            _scim_users_service(request) if resource_type == "Users"
            else _scim_groups_service(request) if resource_type == "Groups"
            else None
        )
        if svc is None:
            return 400, None, f"Unsupported resource type in Bulk op: {resource_type}"
        loc_base = f"{base}/v1/scim/v2/{resource_type}"
        attrs = dict(data) if isinstance(data, dict) else {}
        external_id = attrs.pop("externalId", None) or attrs.pop("external_id", None)

        if method == "POST" and resource_id is None:
            # Client can provide its own id, otherwise mint one.
            new_id = attrs.pop("id", None) or str(uuid4())
            # ScimService.create is sync and returns a ScimResource-like object.
            result = svc.create(new_id, attrs, external_id=external_id)
            rid = getattr(result, "id", None) or (result.get("id") if isinstance(result, dict) else new_id)
            return 201, f"{loc_base}/{rid}" if rid else None, None
        if method in ("PUT", "PATCH") and resource_id:
            fn = getattr(svc, "replace", None) if method == "PUT" else getattr(svc, "patch", None)
            if callable(fn):
                fn(resource_id, attrs)
                return 200, f"{loc_base}/{resource_id}", None
            return 501, None, f"Bulk {method} not implemented on this SCIM service"
        if method == "DELETE" and resource_id:
            fn = getattr(svc, "delete", None)
            if callable(fn):
                fn(resource_id)
                return 204, None, None
            return 501, None, "Bulk DELETE not implemented on this SCIM service"
        return 400, None, f"Unsupported Bulk operation: {method} {path}"
    except Exception as e:  # noqa: BLE001
        return 500, None, str(e)


def _scim_users_service(request: Request) -> Any:
    return getattr(request.app.state, "scim_users_service", None) or (
        getattr(get_auth(request), "_scim_users", None) if get_auth(request) else None
    )


def _scim_groups_service(request: Request) -> Any:
    return getattr(request.app.state, "scim_groups_service", None) or (
        getattr(get_auth(request), "_scim_groups", None) if get_auth(request) else None
    )


@XWAction(
    operationId="scim_search",
    summary="SCIM query via search (RFC 7644 §3.4.3)",
    method="POST",
    description=(
        "POST-based SCIM search. Accepts a SearchRequest body with filter + paging, runs "
        "it against both Users and Groups, and returns a combined ListResponse. Lets "
        "clients send long filters or sensitive attributes that would be awkward in a "
        "GET query string."
    ),
    tags=SCIM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={200: {"description": "SCIM ListResponse"}, 400: {"description": "Malformed SearchRequest"}, 401: {"description": "Authentication required"}},
)
async def scim_search(request: Request) -> Any:
    if await _resolve_auth_context_or_none(request) is None:
        return _scim_unauthorized()
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            content={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": "400",
                "scimType": "invalidSyntax",
                "detail": "Request body is not valid JSON",
            },
            status_code=400,
        )
    if not isinstance(body, dict):
        body = {}
    # RFC 7644 §3.4.3 SearchRequest fields.
    filt = body.get("filter")
    attributes = body.get("attributes") or []
    excluded = body.get("excludedAttributes") or []
    sort_by = body.get("sortBy")
    sort_order = body.get("sortOrder", "ascending")
    start_index = body.get("startIndex", 1)
    count = body.get("count", 100)
    try:
        start_index = max(1, int(start_index))
        count = max(0, int(count))
    except (TypeError, ValueError):
        start_index, count = 1, 100

    async with track_critical_handler(request, "scim_search"):
        # Root .search spans both resource types — fan out, concat, truncate.
        users_svc = _scim_users_service(request)
        groups_svc = _scim_groups_service(request)
        resources: list[dict[str, Any]] = []
        for svc in (users_svc, groups_svc):
            if svc is None:
                continue
            try:
                # ScimService exposes ``list_response(filter_expression, start_index, count)``
                # as a sync method returning the ListResponse dict already.
                listing = svc.list_response(
                    filter_expression=filt,
                    start_index=1,
                    count=count + start_index,  # over-fetch so we can paginate below
                )
            except Exception:
                continue
            if isinstance(listing, dict):
                got = listing.get("Resources") or []
                resources.extend(got if isinstance(got, list) else [])
        total = len(resources)
        page = resources[start_index - 1 : start_index - 1 + count]
        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": total,
            "itemsPerPage": len(page),
            "startIndex": start_index,
            "Resources": page,
        }


@XWAction(
    operationId="scim_me_get",
    summary="SCIM Me — current user as SCIM User",
    method="GET",
    description="Return the authenticated caller's record in SCIM User shape. Shortcut for ``GET /Users/{self}``.",
    tags=SCIM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={200: {"description": "SCIM User representation"}, 401: {"description": "Authentication required"}},
)
async def scim_me(request: Request) -> Any:
    ctx = await _resolve_auth_context_or_none(request)
    if ctx is None:
        return _scim_unauthorized()
    async with track_critical_handler(request, "scim_me"):
        user_id = getattr(ctx, "user_id", None) or getattr(ctx, "sub", None)
        if not user_id:
            return _scim_unauthorized()
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": user_id,
            "meta": {
                "resourceType": "User",
                "location": f"{str(request.base_url).rstrip('/')}/v1/scim/v2/Users/{user_id}",
            },
        }


@XWAction(
    operationId="scim_schemas_list",
    summary="SCIM Schemas",
    method="GET",
    description="Return the list of SCIM resource schemas supported by this service provider (RFC 7643).",
    tags=SCIM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "SCIM schemas list"},
        401: {"description": "Authentication required"},
    },
)
async def scim_schemas(request: Request) -> Any:
    if await _resolve_auth_context_or_none(request) is None:
        return _scim_unauthorized()
    async with track_critical_handler(request, "scim_schemas"):
        # Return the three core SCIM schemas this service supports. Integrators
        # that extend with custom attributes can override this handler to add
        # their extension schemas.
        user_schema = {
            "id": "urn:ietf:params:scim:schemas:core:2.0:User",
            "name": "User",
            "description": "User Account",
            "attributes": [
                {"name": "userName", "type": "string", "required": True, "uniqueness": "server"},
                {"name": "displayName", "type": "string"},
                {"name": "emails", "type": "complex", "multiValued": True},
                {"name": "active", "type": "boolean"},
            ],
        }
        group_schema = {
            "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
            "name": "Group",
            "description": "Group",
            "attributes": [
                {"name": "displayName", "type": "string", "required": True},
                {"name": "members", "type": "complex", "multiValued": True},
            ],
        }
        spc_schema = {
            "id": "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
            "name": "ServiceProviderConfig",
            "description": "Schema for representing the service provider's configuration",
        }
        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 3,
            "itemsPerPage": 3,
            "startIndex": 1,
            "Resources": [user_schema, group_schema, spc_schema],
        }


@XWAction(operationId="scim_users_list", summary="List SCIM Users", method="GET", tags=SCIM_TAGS, engine="fastapi", profile=ActionProfile.ENDPOINT)
async def scim_users_list(request: Request) -> Any:
    ctx = await _resolve_auth_context_or_none(request)
    if ctx is None:
        return _scim_unauthorized()
    if not _scim_org_query_matches_token(request, ctx):
        return _scim_error(403, "org_id query does not match token organization context")
    auth = get_auth(request)
    service = get_scim_user_service(auth)
    try:
        async with track_critical_handler(request, "scim_users_list"):
            filter_expression, start_index, count = _extract_scim_query_paging(request)
            return service.list_response(filter_expression=filter_expression, start_index=start_index, count=count)
    except ValueError as exc:
        return _scim_error(400, str(exc))
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


@XWAction(operationId="scim_users_create", summary="Create SCIM User", method="POST", tags=SCIM_TAGS, engine="fastapi", profile=ActionProfile.ENDPOINT)
async def scim_users_create(request: Request) -> Any:
    ctx = await _resolve_auth_context_or_none(request)
    if ctx is None:
        return _scim_unauthorized()
    if not _scim_org_query_matches_token(request, ctx):
        return _scim_error(403, "org_id query does not match token organization context")
    auth = get_auth(request)
    service = get_scim_user_service(auth)
    body_data = await request.json() if hasattr(request, "json") else {}
    resource_id = str(body_data.get("id") or uuid4())
    attributes = {k: v for k, v in body_data.items() if k not in {"schemas", "id", "externalId", "meta"}}
    try:
        async with track_critical_handler(request, "scim_users_create"):
            created = service.create(resource_id=resource_id, attributes=attributes, external_id=body_data.get("externalId"))
            return JSONResponse(content=created.to_dict(), status_code=201, headers=_etag_headers_from_resource(created))
    except ValueError as exc:
        return JSONResponse(
            content={"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "status": "409", "detail": str(exc)},
            status_code=409,
        )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


@XWAction(operationId="scim_users_get", summary="Get SCIM User", method="GET", tags=SCIM_TAGS, engine="fastapi", profile=ActionProfile.ENDPOINT)
async def scim_users_get(resource_id: str, request: Request) -> Any:
    ctx = await _resolve_auth_context_or_none(request)
    if ctx is None:
        return _scim_unauthorized()
    if not _scim_org_query_matches_token(request, ctx):
        return _scim_error(403, "org_id query does not match token organization context")
    auth = get_auth(request)
    service = get_scim_user_service(auth)
    async with track_critical_handler(request, "scim_users_get"):
        found = service.get(resource_id)
        if found is None:
            return _scim_error(404, "Resource not found")
        return JSONResponse(content=found.to_dict(), headers=_etag_headers_from_resource(found))


@XWAction(operationId="scim_users_patch", summary="Patch SCIM User", method="PATCH", tags=SCIM_TAGS, engine="fastapi", profile=ActionProfile.ENDPOINT)
async def scim_users_patch(resource_id: str, request: Request) -> Any:
    ctx = await _resolve_auth_context_or_none(request)
    if ctx is None:
        return _scim_unauthorized()
    if not _scim_org_query_matches_token(request, ctx):
        return _scim_error(403, "org_id query does not match token organization context")
    auth = get_auth(request)
    service = get_scim_user_service(auth)
    existing = service.get(resource_id)
    if existing is None:
        return _scim_error(404, "Resource not found")
    current_etag = getattr(getattr(existing, "meta", None), "version", None)
    if_match = request.headers.get("if-match")
    if not _matches_if_match(if_match, current_etag):
        return _scim_error(412, "If-Match precondition failed")

    body_data = await request.json() if hasattr(request, "json") else {}
    schemas = body_data.get("schemas")
    if schemas is not None:
        required_schema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
        if not isinstance(schemas, list) or required_schema not in schemas:
            return _scim_error(400, "SCIM PATCH requires PatchOp schema")
    raw_operations = body_data.get("Operations") or []
    operations: list[ScimPatchOperation] = []
    if not isinstance(raw_operations, list):
        return _scim_error(400, "Operations must be an array")
    for operation in raw_operations:
        if not isinstance(operation, dict):
            return _scim_error(400, "Each operation must be an object")
        operations.append(
            ScimPatchOperation(
                op=str(operation.get("op") or ""),
                path=operation.get("path"),
                value=operation.get("value"),
            )
        )
    try:
        async with track_critical_handler(request, "scim_users_patch"):
            updated = service.patch(resource_id=resource_id, operations=operations)
            return JSONResponse(content=updated.to_dict(), headers=_etag_headers_from_resource(updated))
    except KeyError:
        return _scim_error(404, "Resource not found")
    except ValueError as exc:
        return _scim_error(400, str(exc))
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


@XWAction(operationId="scim_users_delete", summary="Delete SCIM User", method="DELETE", tags=SCIM_TAGS, engine="fastapi", profile=ActionProfile.ENDPOINT)
async def scim_users_delete(resource_id: str, request: Request) -> Any:
    ctx = await _resolve_auth_context_or_none(request)
    if ctx is None:
        return _scim_unauthorized()
    if not _scim_org_query_matches_token(request, ctx):
        return _scim_error(403, "org_id query does not match token organization context")
    auth = get_auth(request)
    service = get_scim_user_service(auth)
    existing = service.get(resource_id)
    if existing is None:
        return _scim_error(404, "Resource not found")
    current_etag = getattr(getattr(existing, "meta", None), "version", None)
    if_match = request.headers.get("if-match")
    if not _matches_if_match(if_match, current_etag):
        return _scim_error(412, "If-Match precondition failed")
    async with track_critical_handler(request, "scim_users_delete"):
        if not service.delete(resource_id):
            return _scim_error(404, "Resource not found")
        return Response(status_code=204)


@XWAction(operationId="scim_groups_list", summary="List SCIM Groups", method="GET", tags=SCIM_TAGS, engine="fastapi", profile=ActionProfile.ENDPOINT)
async def scim_groups_list(request: Request) -> Any:
    ctx = await _resolve_auth_context_or_none(request)
    if ctx is None:
        return _scim_unauthorized()
    if not _scim_org_query_matches_token(request, ctx):
        return _scim_error(403, "org_id query does not match token organization context")
    auth = get_auth(request)
    service = get_scim_group_service(auth)
    try:
        async with track_critical_handler(request, "scim_groups_list"):
            filter_expression, start_index, count = _extract_scim_query_paging(request)
            return service.list_response(filter_expression=filter_expression, start_index=start_index, count=count)
    except ValueError as exc:
        return _scim_error(400, str(exc))
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


@XWAction(operationId="scim_groups_create", summary="Create SCIM Group", method="POST", tags=SCIM_TAGS, engine="fastapi", profile=ActionProfile.ENDPOINT)
async def scim_groups_create(request: Request) -> Any:
    ctx = await _resolve_auth_context_or_none(request)
    if ctx is None:
        return _scim_unauthorized()
    if not _scim_org_query_matches_token(request, ctx):
        return _scim_error(403, "org_id query does not match token organization context")
    auth = get_auth(request)
    service = get_scim_group_service(auth)
    body_data = await request.json() if hasattr(request, "json") else {}
    resource_id = str(body_data.get("id") or uuid4())
    attributes = {k: v for k, v in body_data.items() if k not in {"schemas", "id", "externalId", "meta"}}
    try:
        async with track_critical_handler(request, "scim_groups_create"):
            created = service.create(resource_id=resource_id, attributes=attributes, external_id=body_data.get("externalId"))
            return JSONResponse(content=created.to_dict(), status_code=201, headers=_etag_headers_from_resource(created))
    except ValueError as exc:
        return _scim_error(409, str(exc))
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


@XWAction(operationId="scim_groups_get", summary="Get SCIM Group", method="GET", tags=SCIM_TAGS, engine="fastapi", profile=ActionProfile.ENDPOINT)
async def scim_groups_get(resource_id: str, request: Request) -> Any:
    ctx = await _resolve_auth_context_or_none(request)
    if ctx is None:
        return _scim_unauthorized()
    if not _scim_org_query_matches_token(request, ctx):
        return _scim_error(403, "org_id query does not match token organization context")
    auth = get_auth(request)
    service = get_scim_group_service(auth)
    async with track_critical_handler(request, "scim_groups_get"):
        found = service.get(resource_id)
        if found is None:
            return _scim_error(404, "Resource not found")
        return JSONResponse(content=found.to_dict(), headers=_etag_headers_from_resource(found))


@XWAction(operationId="scim_groups_patch", summary="Patch SCIM Group", method="PATCH", tags=SCIM_TAGS, engine="fastapi", profile=ActionProfile.ENDPOINT)
async def scim_groups_patch(resource_id: str, request: Request) -> Any:
    ctx = await _resolve_auth_context_or_none(request)
    if ctx is None:
        return _scim_unauthorized()
    if not _scim_org_query_matches_token(request, ctx):
        return _scim_error(403, "org_id query does not match token organization context")
    auth = get_auth(request)
    service = get_scim_group_service(auth)
    existing = service.get(resource_id)
    if existing is None:
        return _scim_error(404, "Resource not found")
    current_etag = getattr(getattr(existing, "meta", None), "version", None)
    if_match = request.headers.get("if-match")
    if not _matches_if_match(if_match, current_etag):
        return _scim_error(412, "If-Match precondition failed")

    body_data = await request.json() if hasattr(request, "json") else {}
    raw_operations = body_data.get("Operations") or []
    if not isinstance(raw_operations, list):
        return _scim_error(400, "Operations must be an array")
    operations = [
        ScimPatchOperation(op=str(operation.get("op") or ""), path=operation.get("path"), value=operation.get("value"))
        for operation in raw_operations
        if isinstance(operation, dict)
    ]
    if len(operations) != len(raw_operations):
        return _scim_error(400, "Each operation must be an object")
    try:
        async with track_critical_handler(request, "scim_groups_patch"):
            updated = service.patch(resource_id=resource_id, operations=operations)
            return JSONResponse(content=updated.to_dict(), headers=_etag_headers_from_resource(updated))
    except ValueError as exc:
        return _scim_error(400, str(exc))


@XWAction(operationId="scim_groups_delete", summary="Delete SCIM Group", method="DELETE", tags=SCIM_TAGS, engine="fastapi", profile=ActionProfile.ENDPOINT)
async def scim_groups_delete(resource_id: str, request: Request) -> Any:
    ctx = await _resolve_auth_context_or_none(request)
    if ctx is None:
        return _scim_unauthorized()
    if not _scim_org_query_matches_token(request, ctx):
        return _scim_error(403, "org_id query does not match token organization context")
    auth = get_auth(request)
    service = get_scim_group_service(auth)
    existing = service.get(resource_id)
    if existing is None:
        return _scim_error(404, "Resource not found")
    current_etag = getattr(getattr(existing, "meta", None), "version", None)
    if_match = request.headers.get("if-match")
    if not _matches_if_match(if_match, current_etag):
        return _scim_error(412, "If-Match precondition failed")
    async with track_critical_handler(request, "scim_groups_delete"):
        if not service.delete(resource_id):
            return _scim_error(404, "Resource not found")
        return Response(status_code=204)
