#!/usr/bin/env python3
"""
Centralized authorization policy decision helpers for xwauth.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4
from exonware.xwsystem.security.contracts import AuthContext


@dataclass(slots=True)
class PolicyDecisionTrace:
    """Explainable policy trace for audit and operator tooling."""

    decision_id: str
    resource: str
    action: str
    required_scopes: list[str]
    effective_scopes: list[str]
    matched_scopes: list[str]
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PolicyDecision:
    """Structured authorization decision with trace."""

    allowed: bool
    trace: PolicyDecisionTrace


class PolicyDecisionService:
    """
    Minimal RBAC+scope decision service.
    This centralizes runtime authorization checks so API/storage layers can delegate.
    """

    @staticmethod
    def _effective_scopes(context: AuthContext) -> set[str]:
        scopes = {str(scope).strip() for scope in (context.scopes or []) if str(scope).strip()}
        roles = {str(role).strip() for role in (context.roles or []) if str(role).strip()}
        scopes.update({role for role in roles if ":" in role})
        if "admin" in roles:
            scopes.add("*")
        return scopes

    @staticmethod
    def _required_scopes(resource: str, action: str) -> list[str]:
        required = [
            f"{resource}:{action}",
            f"{resource}:*",
            "*",
        ]
        # Backward-compatible legacy scope shape.
        if resource != "storage":
            required.append(f"storage:{action}")
        return required

    @staticmethod
    def _claim_list(claim_value: Any) -> set[str]:
        if claim_value is None:
            return set()
        if isinstance(claim_value, (list, tuple, set)):
            return {str(item) for item in claim_value}
        return {str(claim_value)}

    def explain(
        self,
        context: AuthContext,
        resource: str,
        action: str,
        *,
        org_id: str | None = None,
        project_id: str | None = None,
    ) -> PolicyDecision:
        effective_scopes = self._effective_scopes(context)
        required_scopes = self._required_scopes(resource, action)
        matched_scopes = [scope for scope in required_scopes if scope in effective_scopes]
        reasons: list[str] = []

        if matched_scopes:
            reasons.append(f"matched scopes: {', '.join(matched_scopes)}")
        else:
            reasons.append("no required scope matched")

        allowed = bool(matched_scopes)
        claims = context.claims or {}

        if org_id is not None:
            allowed_orgs = self._claim_list(claims.get("org_ids")) | self._claim_list(claims.get("org_id"))
            if allowed_orgs and org_id not in allowed_orgs:
                allowed = False
                reasons.append(f"org scope mismatch for org_id={org_id}")

        if project_id is not None:
            allowed_projects = self._claim_list(claims.get("project_ids")) | self._claim_list(claims.get("project_id"))
            if allowed_projects and project_id not in allowed_projects:
                allowed = False
                reasons.append(f"project scope mismatch for project_id={project_id}")

        trace = PolicyDecisionTrace(
            decision_id=str(uuid4()),
            resource=resource,
            action=action,
            required_scopes=required_scopes,
            effective_scopes=sorted(effective_scopes),
            matched_scopes=matched_scopes,
            reasons=reasons,
        )
        return PolicyDecision(allowed=allowed, trace=trace)

    async def evaluate(self, context: AuthContext, resource: str, action: str) -> bool:
        """
        Evaluate authorization decision for a resource/action pair.
        """
        return self.explain(context, resource, action).allowed
