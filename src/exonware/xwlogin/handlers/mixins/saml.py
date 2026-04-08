# exonware/xwlogin/handlers/mixins/saml.py
"""SAML SSO HTTP surface: metadata, ACS, discovery (uses connector helpers from xwauth)."""

from __future__ import annotations

from typing import Any

from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwlogin.handlers.connector_http import (
    SSO_TAGS,
    get_auth,
    get_saml_manager,
    get_user_lifecycle,
    oauth_error_to_http,
    track_critical_handler,
)
from exonware.xwapi.http import JSONResponse, RedirectResponse, Request, Response

# -----------------------------------------------------------------------------
# GET /auth/sso/saml/metadata
# -----------------------------------------------------------------------------
@XWAction(
    operationId="saml_metadata",
    summary="Export SAML Metadata",
    method="GET",
    description="""
    Export SAML 2.0 Service Provider metadata XML.
    This endpoint returns the SAML metadata that can be shared with Identity Providers
    for SSO configuration.
    Security: Public endpoint (metadata is not sensitive).
    """,
    tags=SSO_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "SAML metadata XML", "content": {"application/xml": {}}},
    },
    rate_limit="100/hour",
    in_types={
        "entity_id": {
            "type": "string",
            "description": "Service Provider entity ID",
            "minLength": 1,
            "maxLength": 512,
        },
        "acs_url": {
            "type": "string",
            "description": "Assertion Consumer Service URL",
            "format": "uri",
            "minLength": 1,
            "maxLength": 512,
        },
        "slo_url": {
            "type": "string",
            "description": "Single Logout Service URL (optional)",
            "format": "uri",
            "maxLength": 512,
        },
        "certificate": {
            "type": "string",
            "description": "X.509 certificate for signing (optional)",
            "maxLength": 4096,
        },
    },
)
async def saml_metadata(request: Request) -> Any:
    """Export SAML metadata."""
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "saml_metadata"):
            entity_id = request.query_params.get("entity_id") or getattr(
                auth.config, "saml_entity_id", "https://xwauth.example.com"
            )
            acs_url = request.query_params.get("acs_url") or str(request.url).replace(
                "/metadata", "/acs"
            )
            slo_url = request.query_params.get("slo_url")
            certificate = request.query_params.get("certificate")
            manager = get_saml_manager(auth)
            metadata_xml = manager.generate_metadata(
                entity_id=entity_id,
                acs_url=acs_url,
                slo_url=slo_url,
                certificate=certificate,
            )
            return Response(
                content=metadata_xml,
                media_type="application/xml",
                headers={
                    "Content-Disposition": 'attachment; filename="saml-metadata.xml"'
                },
            )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


# -----------------------------------------------------------------------------
# POST /auth/sso/saml/acs
# -----------------------------------------------------------------------------
@XWAction(
    operationId="saml_acs",
    summary="SAML Assertion Consumer Service",
    method="POST",
    description="""
    Process SAML assertion from Identity Provider.
    This is the ACS (Assertion Consumer Service) endpoint that receives SAML
    responses from Identity Providers after authentication.
    Security: Public endpoint (called by IdP).
    """,
    tags=SSO_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Authentication successful"},
        302: {"description": "Redirect to relay_state URL"},
        400: {"description": "Invalid SAML response"},
    },
    rate_limit="100/hour",
    in_types={
        "SAMLResponse": {
            "type": "string",
            "description": "Base64-encoded SAML response",
            "minLength": 1,
        },
        "RelayState": {
            "type": "string",
            "description": "Relay state parameter (optional)",
            "maxLength": 512,
        },
    },
)
async def saml_acs(request: Request) -> Any:
    """Process SAML assertion."""
    auth = get_auth(request)
    form_data = await request.form() if hasattr(request, "form") else {}
    try:
        async with track_critical_handler(request, "saml_acs"):
            saml_response = form_data.get("SAMLResponse") or (
                await request.json() if hasattr(request, "json") else {}
            ).get("SAMLResponse")
            relay_state = form_data.get("RelayState") or (
                await request.json() if hasattr(request, "json") else {}
            ).get("RelayState")
            if not saml_response:
                return JSONResponse(
                    content={
                        "error": "invalid_request",
                        "error_description": "SAMLResponse is required",
                    },
                    status_code=400,
                )
            manager = get_saml_manager(auth)
            result = await manager.process_acs(saml_response, relay_state)
            user_lifecycle = get_user_lifecycle(auth)
            email = result.get("email")
            user_id = result.get("user_id")
            if email:
                user = await user_lifecycle.get_user_by_email(email)
                if not user:
                    user = await user_lifecycle.create_user(
                        email=email,
                        attributes={
                            "saml_id": user_id,
                            **result.get("attributes", {}),
                        },
                    )
                user_pk = str(getattr(user, "id", user))
                token_data = await auth.issue_federated_user_tokens(
                    user_id=user_pk,
                    auth_method="saml",
                )
                if relay_state:
                    from urllib.parse import urlencode

                    frag = urlencode(
                        {
                            "access_token": token_data.get("access_token") or "",
                            "token_type": token_data.get("token_type") or "Bearer",
                            "expires_in": str(token_data.get("expires_in") or ""),
                        }
                    )
                    base = relay_state
                    sep = "#" if "#" not in base else "&"
                    return RedirectResponse(url=f"{base}{sep}{frag}", status_code=302)
                return {
                    "user_id": user.id,
                    "email": email,
                    "access_token": token_data.get("access_token"),
                    "refresh_token": token_data.get("refresh_token"),
                    "expires_in": token_data.get("expires_in"),
                    "token_type": token_data.get("token_type"),
                    "session_id": token_data.get("session_id"),
                    "message": "SAML authentication successful",
                }
            return JSONResponse(
                content={
                    "error": "invalid_saml",
                    "error_description": "No email found in SAML assertion",
                },
                status_code=400,
            )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


# -----------------------------------------------------------------------------
# GET /auth/sso/discovery
# -----------------------------------------------------------------------------
@XWAction(
    operationId="sso_discovery",
    summary="SSO Provider Discovery",
    method="GET",
    description="""
    Auto-detect SSO provider by email domain.
    Returns SSO configuration for a given email domain, enabling automatic
    SSO provider selection based on user's email address.
    Security: Public endpoint.
    """,
    tags=SSO_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "SSO provider configuration"},
        404: {"description": "No SSO provider found for domain"},
    },
    rate_limit="100/hour",
    in_types={
        "email": {
            "type": "string",
            "description": "Email address to discover SSO provider for",
            "format": "email",
            "minLength": 1,
            "maxLength": 256,
        }
    },
)
async def sso_discovery(request: Request) -> Any:
    """Discover SSO provider by email domain."""
    auth = get_auth(request)
    email = request.query_params.get("email")
    if not email:
        return JSONResponse(
            content={
                "error": "invalid_request",
                "error_description": "email parameter is required",
            },
            status_code=400,
        )
    try:
        async with track_critical_handler(request, "sso_discovery"):
            manager = get_saml_manager(auth)
            org_id = (request.query_params.get("org_id") or "").strip() or None
            sso_config = await manager.discover_sso_provider(email, org_id=org_id)
            if not sso_config:
                return JSONResponse(
                    content={
                        "error": "not_found",
                        "error_description": "No SSO provider found for this domain",
                    },
                    status_code=404,
                )
            out: dict[str, Any] = {
                "email": email,
                "domain": email.split("@")[1] if "@" in email else None,
                "sso_provider": sso_config.get("provider_type", "saml"),
                "idp_url": sso_config.get("idp_url"),
                "entity_id": sso_config.get("entity_id"),
            }
            if org_id:
                out["org_id"] = org_id
            if sso_config.get("org_id"):
                out["resolved_org_id"] = sso_config.get("org_id")
            return out
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
