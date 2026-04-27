#!/usr/bin/env python3
"""
#exonware/xwauth.identity/tests/1.unit/security_tests/test_policy_decision_org_boundary.py
PolicyDecisionService org/project boundary behavior (documented contract).
"""

from __future__ import annotations

import pytest

from exonware.xwsystem.security.contracts import AuthContext

from exonware.xwauth.identity.policy_decision import PolicyDecisionService


@pytest.mark.xwauth_identity_unit
def test_explain_denies_when_org_id_mismatches_org_claim() -> None:
    svc = PolicyDecisionService()
    ctx = AuthContext(
        subject_id="user-1",
        scopes=["documents:read"],
        claims={"org_id": "org-a"},
    )
    decision = svc.explain(ctx, resource="documents", action="read", org_id="org-b")
    assert decision.allowed is False
    assert any("org scope mismatch" in r for r in decision.trace.reasons)


@pytest.mark.xwauth_identity_unit
def test_explain_org_id_does_not_restrict_when_token_has_no_org_claims() -> None:
    """
    When ``org_id`` is passed to explain() but the token carries no org claims,
    org scoping is skipped (allowed_orgs is empty). Callers that require
    per-tenant isolation must enforce org claims at token issue or in API
    middleware — not rely on this helper alone.
    """
    svc = PolicyDecisionService()
    ctx = AuthContext(
        subject_id="user-1",
        scopes=["documents:read"],
        claims={},
    )
    decision = svc.explain(ctx, resource="documents", action="read", org_id="tenant-x")
    assert decision.allowed is True


@pytest.mark.xwauth_identity_unit
def test_explain_project_mismatch_when_project_claim_present() -> None:
    svc = PolicyDecisionService()
    ctx = AuthContext(
        subject_id="user-1",
        scopes=["documents:read"],
        claims={"project_id": "p-1"},
    )
    decision = svc.explain(
        ctx, resource="documents", action="read", project_id="p-2"
    )
    assert decision.allowed is False
