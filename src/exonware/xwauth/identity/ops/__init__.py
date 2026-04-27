#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/__init__.py
Operational helpers (deliverability, runbooks) — no SMTP implementation here.
"""

from __future__ import annotations

from .abuse_resistance import (
    ABUSE_RESISTANCE_OPS_SCHEMA_VERSION,
    abuse_resistance_checklist,
    exponential_backoff_delay_ms,
)
from .admin_api_openapi_parity import (
    ADMIN_API_OPENAPI_PARITY_SCHEMA_VERSION,
    admin_api_openapi_parity_checklist,
)
from .airgap_deployment import AIRGAP_OPS_SCHEMA_VERSION, airgap_deployment_checklist
from .b2b_delegated_admin import (
    B2B_DELEGATED_ADMIN_OPS_SCHEMA_VERSION,
    b2b_delegated_admin_checklist,
)
from .compliance_pack import (
    COMPLIANCE_PACK_SCHEMA_VERSION,
    compliance_evidence_template,
    compliance_pack_checklist,
)
from .data_residency import DATA_RESIDENCY_OPS_SCHEMA_VERSION, data_residency_checklist
from .email_magic_link_ops import (
    EMAIL_MAGIC_LINK_OPS_SCHEMA_VERSION,
    magic_link_email_ops_checklist,
    recommended_magic_link_ttl_seconds_bounds,
)
from .extension_model_readiness import (
    EXTENSION_MODEL_READINESS_SCHEMA_VERSION,
    extension_model_readiness_checklist,
)
from .infra_as_code_tenants import (
    INFRA_AS_CODE_TENANTS_SCHEMA_VERSION,
    infra_as_code_tenants_checklist,
)
from .kubernetes_operator_readiness import (
    K8S_OPERATOR_READINESS_SCHEMA_VERSION,
    kubernetes_operator_readiness_checklist,
)
from .login_ui_accessibility import (
    LOGIN_UI_A11Y_SCHEMA_VERSION,
    login_ui_accessibility_checklist,
)
from .multi_region_auth import MULTI_REGION_AUTH_OPS_SCHEMA_VERSION, multi_region_auth_checklist
from .oidc_self_cert_readiness import (
    OIDC_SELF_CERT_READINESS_SCHEMA_VERSION,
    oidc_self_cert_readiness_checklist,
)
from .pen_test_engagement import (
    PENTEST_ENGAGEMENT_SCHEMA_VERSION,
    pen_test_engagement_checklist,
)
from .session_device_reference_ui import (
    SESSION_DEVICE_REFERENCE_UI_SCHEMA_VERSION,
    session_device_reference_ui_checklist,
)
from .tco_evidence import (
    TCO_EVIDENCE_SCHEMA_VERSION,
    tco_benchmark_publish_checklist,
    validate_microbench_output,
)
from .research_program import (
    RESEARCH_PROGRAM_SCHEMA_VERSION,
    fuzzing_recommendations,
    interop_bounty_policy,
)

__all__ = [
    "ABUSE_RESISTANCE_OPS_SCHEMA_VERSION",
    "abuse_resistance_checklist",
    "exponential_backoff_delay_ms",
    "ADMIN_API_OPENAPI_PARITY_SCHEMA_VERSION",
    "admin_api_openapi_parity_checklist",
    "AIRGAP_OPS_SCHEMA_VERSION",
    "airgap_deployment_checklist",
    "B2B_DELEGATED_ADMIN_OPS_SCHEMA_VERSION",
    "b2b_delegated_admin_checklist",
    "COMPLIANCE_PACK_SCHEMA_VERSION",
    "compliance_pack_checklist",
    "compliance_evidence_template",
    "DATA_RESIDENCY_OPS_SCHEMA_VERSION",
    "data_residency_checklist",
    "MULTI_REGION_AUTH_OPS_SCHEMA_VERSION",
    "multi_region_auth_checklist",
    "OIDC_SELF_CERT_READINESS_SCHEMA_VERSION",
    "oidc_self_cert_readiness_checklist",
    "PENTEST_ENGAGEMENT_SCHEMA_VERSION",
    "pen_test_engagement_checklist",
    "SESSION_DEVICE_REFERENCE_UI_SCHEMA_VERSION",
    "session_device_reference_ui_checklist",
    "EMAIL_MAGIC_LINK_OPS_SCHEMA_VERSION",
    "magic_link_email_ops_checklist",
    "recommended_magic_link_ttl_seconds_bounds",
    "EXTENSION_MODEL_READINESS_SCHEMA_VERSION",
    "extension_model_readiness_checklist",
    "INFRA_AS_CODE_TENANTS_SCHEMA_VERSION",
    "infra_as_code_tenants_checklist",
    "K8S_OPERATOR_READINESS_SCHEMA_VERSION",
    "kubernetes_operator_readiness_checklist",
    "LOGIN_UI_A11Y_SCHEMA_VERSION",
    "login_ui_accessibility_checklist",
    "TCO_EVIDENCE_SCHEMA_VERSION",
    "tco_benchmark_publish_checklist",
    "validate_microbench_output",
    "RESEARCH_PROGRAM_SCHEMA_VERSION",
    "interop_bounty_policy",
    "fuzzing_recommendations",
]
