# exonware/xwauth/handlers/mixins/system.py
"""System: health, metrics, oauth_protected_resource."""

from __future__ import annotations
import asyncio
import time
from typing import Any, Optional
from datetime import datetime, timezone
from fastapi import Request, Depends, Header
from fastapi.responses import JSONResponse, RedirectResponse, Response
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwsystem.monitoring.error_recovery import retry_with_backoff
from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
from .._common import (
    SYSTEM_TAGS,
    get_auth,
    get_user_lifecycle,
)
@XWAction(
    operationId="health",
    summary="Health Check",
    method="GET",
    description="""
    Health check endpoint for monitoring and load balancers.
    Returns service health status. Always returns 200 if service is running.
    No authentication required.
    """,
    tags=SYSTEM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    readonly=True,
    responses={200: {"description": "Service is healthy"}},
    examples={"response": {"status": "healthy", "service": "xwauth"}},
    in_types={},
)
async def health(request: Request) -> Any:
    return {"status": "healthy", "service": "xwauth"}
# -----------------------------------------------------------------------------
# GET /metrics
# -----------------------------------------------------------------------------
@XWAction(
    operationId="metrics",
    summary="Metrics",
    method="GET",
    description="Prometheus metrics endpoint.",
    tags=SYSTEM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={},  # Exclude Request parameter from schema (FastAPI dependency, not user input)
)
async def metrics(request: Request) -> Any:
    """Return basic Prometheus metrics."""
    auth = get_auth(request)
    runtime = getattr(request.app.state, "xwauth_ops_runtime", None)
    runtime_scorecard = runtime.scorecard() if runtime else {}
    totals = runtime_scorecard.get("totals", {}) if isinstance(runtime_scorecard, dict) else {}
    total_requests = int(totals.get("requests", 0))
    total_errors = int(totals.get("errors", 0))
    # Basic metrics
    metrics_lines = [
        "# HELP xwauth_requests_total Total number of requests",
        "# TYPE xwauth_requests_total counter",
        f"xwauth_requests_total {total_requests}",
        "",
        "# HELP xwauth_errors_total Total number of errors",
        "# TYPE xwauth_errors_total counter",
        f"xwauth_errors_total {total_errors}",
        "",
        "# HELP xwauth_users_total Total number of users",
        "# TYPE xwauth_users_total gauge",
    ]
    storage_ok = False
    storage_started = time.perf_counter()
    try:
        user_lifecycle = get_user_lifecycle(auth)
        users = await _list_users_with_resilience(user_lifecycle)
        metrics_lines.append(f"xwauth_users_total {len(users)}")
        storage_ok = True
    except Exception:
        metrics_lines.append("xwauth_users_total 0")
    storage_ms = (time.perf_counter() - storage_started) * 1000.0
    if runtime:
        runtime.record_dependency("storage", storage_ok, storage_ms)
    metrics_lines.extend([
        "",
        "# HELP xwauth_health Health status (1=healthy, 0=unhealthy)",
        "# TYPE xwauth_health gauge",
        "xwauth_health 1",
    ])
    ops_tier = getattr(request.app.state, "xwauth_ops_tier", "")
    if ops_tier:
        metrics_lines.extend(
            [
                "",
                "# HELP xwauth_ops_tier_info Current ops tier profile",
                "# TYPE xwauth_ops_tier_info gauge",
                f'xwauth_ops_tier_info{{tier="{ops_tier}"}} 1',
            ]
        )
    route_families = runtime_scorecard.get("route_families", {}) if isinstance(runtime_scorecard, dict) else {}
    for family, data in route_families.items():
        req = int(data.get("requests", 0))
        err = int(data.get("errors", 0))
        burn_rate = float(data.get("burn_rate", 0.0))
        metrics_lines.extend(
            [
                f'xwauth_requests_by_family_total{{route_family="{family}"}} {req}',
                f'xwauth_errors_by_family_total{{route_family="{family}"}} {err}',
                f'xwauth_burn_rate_by_family{{route_family="{family}"}} {burn_rate}',
            ]
        )
    if runtime:
        deps = runtime.scorecard().get("dependencies", {})
        if deps:
            metrics_lines.extend(
                [
                    "",
                    "# HELP xwauth_dependency_requests_total Outbound dependency calls (e.g. user store)",
                    "# TYPE xwauth_dependency_requests_total counter",
                ]
            )
            for dep_name, dep in deps.items():
                req = int(dep.get("requests", 0))
                metrics_lines.append(
                    f'xwauth_dependency_requests_total{{dependency="{dep_name}"}} {req}'
                )
            metrics_lines.extend(
                [
                    "",
                    "# HELP xwauth_dependency_errors_total Outbound dependency failures",
                    "# TYPE xwauth_dependency_errors_total counter",
                ]
            )
            for dep_name, dep in deps.items():
                err = int(dep.get("errors", 0))
                metrics_lines.append(
                    f'xwauth_dependency_errors_total{{dependency="{dep_name}"}} {err}'
                )
            metrics_lines.extend(
                [
                    "",
                    "# HELP xwauth_dependency_avg_latency_ms Rolling average dependency latency (ms)",
                    "# TYPE xwauth_dependency_avg_latency_ms gauge",
                ]
            )
            for dep_name, dep in deps.items():
                avg = float(dep.get("avg_latency_ms", 0.0))
                metrics_lines.append(
                    f'xwauth_dependency_avg_latency_ms{{dependency="{dep_name}"}} {avg}'
                )
    if runtime:
        ch = runtime.scorecard().get("critical_handlers", {})
        if ch:
            metrics_lines.extend(
                [
                    "",
                    "# HELP xwauth_critical_handler_requests_total Core handler invocations (auth_core)",
                    "# TYPE xwauth_critical_handler_requests_total counter",
                ]
            )
            for op_id, data in ch.items():
                metrics_lines.append(
                    f'xwauth_critical_handler_requests_total{{operation="{op_id}"}} {int(data.get("requests", 0))}'
                )
            metrics_lines.extend(
                [
                    "",
                    "# HELP xwauth_critical_handler_errors_total Core handler failures",
                    "# TYPE xwauth_critical_handler_errors_total counter",
                ]
            )
            for op_id, data in ch.items():
                metrics_lines.append(
                    f'xwauth_critical_handler_errors_total{{operation="{op_id}"}} {int(data.get("errors", 0))}'
                )
            metrics_lines.extend(
                [
                    "",
                    "# HELP xwauth_critical_handler_avg_latency_ms Rolling average handler latency (ms)",
                    "# TYPE xwauth_critical_handler_avg_latency_ms gauge",
                ]
            )
            for op_id, data in ch.items():
                metrics_lines.append(
                    f'xwauth_critical_handler_avg_latency_ms{{operation="{op_id}"}} {float(data.get("avg_latency_ms", 0.0))}'
                )
    return Response(content="\n".join(metrics_lines), media_type="text/plain")


@retry_with_backoff(max_retries=2, base_delay=0.05, max_delay=0.25)
async def _list_users_with_resilience(user_lifecycle: Any) -> Any:
    return await asyncio.wait_for(user_lifecycle.list_users(), timeout=1.5)
# -----------------------------------------------------------------------------
# GET /.well-known/oauth-protected-resource
# -----------------------------------------------------------------------------
@XWAction(
    operationId="oauth_protected_resource",
    summary="OAuth Protected Resource Metadata (RFC 9728)",
    method="GET",
    description="""
    Get OAuth 2.0 Protected Resource Metadata (RFC 9728).
    This endpoint provides metadata about the protected resource (API), including:
    - Resource identifier
    - Authorization servers that can issue tokens for this resource
    - Supported scopes
    - Bearer token presentation methods
    - JWKS URI for resource public keys
    This enables clients and authorization servers to discover how to interact
    with the protected resource.
    """,
    tags=SYSTEM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Protected resource metadata"},
    },
    rate_limit="100/hour",
)
async def oauth_protected_resource(request: Request) -> Any:
    """Get OAuth 2.0 Protected Resource Metadata (RFC 9728)."""
    from exonware.xwauth.identity.oauth_http.discovery import oauth_protected_resource_metadata
    auth = get_auth(request)
    # Get issuer from app state (set by xwauth-api server)
    issuer = getattr(request.app.state, 'xwauth_issuer', None)
    if not issuer:
        # Fallback: construct from request URL
        issuer = str(request.base_url).rstrip("/")
    # Get resource URI (typically the API base URL)
    resource = issuer
    # Get authorization servers (typically the same as issuer for self-hosted)
    authorization_servers = [issuer]
    # Get supported scopes from config
    scopes_supported = getattr(auth.config, 'default_scopes', ['openid', 'profile', 'email'])
    # Build metadata
    metadata = oauth_protected_resource_metadata(
        resource=resource,
        authorization_servers=authorization_servers,
        issuer=issuer,
        scopes_supported=scopes_supported,
        bearer_methods_supported=["header"],  # Standard bearer token in Authorization header
    )
    return metadata


@XWAction(
    operationId="oauth_oidc_conformance_evidence",
    summary="OAuth/OIDC Conformance Evidence",
    method="GET",
    description="Return machine-readable OAuth/OIDC conformance evidence and artifact links.",
    tags=SYSTEM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    readonly=True,
)
async def oauth_oidc_conformance_evidence(request: Request) -> Any:
    """Conformance evidence endpoint for quality gates and CI artifacts."""
    issuer = getattr(request.app.state, "xwauth_issuer", None) or str(request.base_url).rstrip("/")
    app = request.app
    path_set = {getattr(route, "path", "") for route in getattr(app, "routes", [])}

    required_paths = [
        "/v1/oauth2/authorize",
        "/v1/oauth2/token",
        "/v1/oauth2/introspect",
        "/v1/oauth2/revoke",
        "/v1/oauth2/jwks",
        "/v1/oidc/userinfo",
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ]
    present = [path for path in required_paths if path in path_set]
    missing = [path for path in required_paths if path not in path_set]
    coverage = int((len(present) / len(required_paths)) * 100) if required_paths else 100
    route_registry = getattr(app.state, "xwauth_route_family_registry", {}) or {}
    route_families = sorted(set(route_registry.values()))
    required_families = {
        "oauth_authorize",
        "oauth_token",
        "oauth_introspect",
        "oauth_revoke",
        "sessions",
        "scim",
        "saml",
        "mfa",
        "passkeys",
    }
    family_missing = sorted(required_families - set(route_families))
    family_coverage = (
        int((len(required_families) - len(family_missing)) / len(required_families) * 100)
        if required_families
        else 100
    )
    ops_profile = getattr(app.state, "xwauth_ops_profile", {}) or {}

    return {
        "profile": "oauth-oidc-conformance-evidence",
        "issuer": issuer,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "quality_gates": {
            "required_endpoint_coverage_percent": coverage,
            "required_endpoint_coverage_pass": coverage == 100,
            "missing_required_paths": missing,
            "route_family_coverage_percent": family_coverage,
            "route_family_coverage_pass": family_coverage == 100,
            "missing_required_route_families": family_missing,
        },
        "artifacts": {
            "openapi": f"{issuer}/openapi.json",
            "oauth_metadata": f"{issuer}/.well-known/oauth-authorization-server",
            "oidc_metadata": f"{issuer}/.well-known/openid-configuration",
            "protected_resource_metadata": f"{issuer}/.well-known/oauth-protected-resource",
        },
        "ops_profile": {
            "schema_version": ops_profile.get("schema_version"),
            "tier": ops_profile.get("tier"),
            "deployment_overlay": ops_profile.get("deployment_overlay"),
        },
        "required_paths": required_paths,
        "present_paths": present,
        "route_families": route_families,
    }


@XWAction(
    operationId="ops_scorecard",
    summary="Ops Scorecard",
    method="GET",
    description="Return runtime ops scorecard, burn-rate status, and release gate decision.",
    tags=SYSTEM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    readonly=True,
)
async def ops_scorecard(request: Request) -> Any:
    runtime = getattr(request.app.state, "xwauth_ops_runtime", None)
    if runtime is None:
        return {
            "profile": "ops-scorecard",
            "available": False,
            "reason": "ops_runtime_not_initialized",
        }
    return {
        "profile": "ops-scorecard",
        "available": True,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scorecard": runtime.scorecard(),
        "signed_artifact": runtime.signed_scorecard_artifact(),
    }


@XWAction(
    operationId="ops_release_gate",
    summary="Ops Release Gate",
    method="GET",
    description="Return release gate decision derived from burn-rate and protection status.",
    tags=SYSTEM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    readonly=True,
)
async def ops_release_gate(request: Request) -> Any:
    runtime = getattr(request.app.state, "xwauth_ops_runtime", None)
    if runtime is None:
        return {"available": False, "pass": False, "reason": "ops_runtime_not_initialized"}
    gate = runtime.release_gate()
    return {
        "available": True,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "release_gate": gate,
    }


@XWAction(
    operationId="ops_runbooks",
    summary="Ops Runbooks and Gameday",
    method="GET",
    description="Return operational runbooks and gameday scenario inventory.",
    tags=SYSTEM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    readonly=True,
)
async def ops_runbooks(request: Request) -> Any:
    runtime = getattr(request.app.state, "xwauth_ops_runtime", None)
    if runtime is None:
        return {"available": False, "runbooks": [], "gameday": {}}
    return {
        "available": True,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "runbooks": runtime.runbooks(),
        "gameday": runtime.gameday(),
    }


@XWAction(
    operationId="ops_deployment_overlays",
    summary="Ops Deployment Overlays",
    method="GET",
    description="Return deployment overlay contracts for k8s/vm/saas and selected runtime overlay.",
    tags=SYSTEM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    readonly=True,
)
async def ops_deployment_overlays(request: Request) -> Any:
    runtime = getattr(request.app.state, "xwauth_ops_runtime", None)
    if runtime is None:
        return {"available": False, "overlay": {}}
    return {
        "available": True,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "overlay": runtime.deployment_overlay_pack(),
    }


@XWAction(
    operationId="ops_anomalies",
    summary="Ops Anomalies",
    method="GET",
    description="Return runtime security and reliability anomaly signals.",
    tags=SYSTEM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    readonly=True,
)
async def ops_anomalies(request: Request) -> Any:
    runtime = getattr(request.app.state, "xwauth_ops_runtime", None)
    if runtime is None:
        return {"available": False, "anomalies": {"count": 0, "items": []}}
    return {
        "available": True,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "anomalies": runtime.anomalies(),
    }


@XWAction(
    operationId="ops_sli_catalog",
    summary="Ops SLI Catalog",
    method="GET",
    description="Return endpoint-to-SLI mapping from the registered route catalog (criticality, route family, instrumentation flags).",
    tags=SYSTEM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    readonly=True,
)
async def ops_sli_catalog(request: Request) -> Any:
    try:
        from exonware.xwauth_api.sli_catalog import build_sli_catalog
    except ImportError:
        return {
            "available": False,
            "reason": "xwauth_api_not_installed",
            "catalog": {},
        }
    catalog = build_sli_catalog()
    return {
        "available": True,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        **catalog,
    }


@XWAction(
    operationId="ops_forensics",
    summary="Ops Forensics Timeline",
    method="GET",
    description="Return recent anomaly timeline and protection state for incident reconstruction.",
    tags=SYSTEM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    readonly=True,
)
async def ops_forensics(request: Request) -> Any:
    runtime = getattr(request.app.state, "xwauth_ops_runtime", None)
    if runtime is None:
        return {"available": False, "forensics": {"items": [], "protection": {}}}
    return {
        "available": True,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "forensics": runtime.forensics_timeline(),
    }


@XWAction(
    operationId="ops_safe_delivery",
    summary="Ops Safe Delivery Signal",
    method="GET",
    description="Return canary state, release gate, and automated rollback recommendation from profile.",
    tags=SYSTEM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    readonly=True,
)
async def ops_safe_delivery(request: Request) -> Any:
    runtime = getattr(request.app.state, "xwauth_ops_runtime", None)
    if runtime is None:
        return {"available": False, "safe_delivery": {}}
    return {
        "available": True,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "safe_delivery": runtime.safe_delivery_signal(),
    }


@XWAction(
    operationId="ops_benchmark",
    summary="Ops Benchmark Snapshot",
    method="GET",
    description="Return benchmark-style operational snapshot suitable for weekly scorecard evidence.",
    tags=SYSTEM_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    readonly=True,
)
async def ops_benchmark(request: Request) -> Any:
    runtime = getattr(request.app.state, "xwauth_ops_runtime", None)
    if runtime is None:
        return {"available": False, "benchmark": {}}
    return {
        "available": True,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "benchmark": runtime.benchmark_snapshot(),
    }
