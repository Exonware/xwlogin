#!/usr/bin/env python3
"""
Declarative claim / attribute mapping (mapping DSL v1).

Rules are JSON-serializable dicts:

    {"target": "email", "from": ["email", "mail", "userPrincipalName"]}
    {"target": "subject_id", "from": ["sub", "id"], "required": true}

*target* names align with FederatedIdentity fields: subject_id, email, tenant_id, roles (list).
Additional targets are stored on the output claims dict under the target key.
"""

from __future__ import annotations

from typing import Any


def _get_path(data: dict[str, Any], path: str) -> Any:
    if not path:
        return None
    if "." not in path:
        return data.get(path)
    cur: Any = data
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def apply_claim_mapping_v1(
    claims: dict[str, Any],
    rules: list[dict[str, Any]] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Apply mapping rules to a flat-ish claims dict (nested paths supported in *from*).

    Returns:
        (mapped_claims, trace) where trace describes each rule resolution for audit/support.
    """
    if not rules:
        return dict(claims), {"version": 1, "rules_applied": 0, "steps": []}

    out = dict(claims)
    steps: list[dict[str, Any]] = []

    for idx, rule in enumerate(rules):
        target = str(rule.get("target") or "").strip()
        if not target:
            steps.append({"index": idx, "skipped": True, "reason": "missing_target"})
            continue
        sources = rule.get("from")
        if isinstance(sources, str):
            candidates = [sources]
        elif isinstance(sources, list):
            candidates = [str(s) for s in sources]
        else:
            steps.append({"index": idx, "target": target, "skipped": True, "reason": "invalid_from"})
            continue
        required = bool(rule.get("required", False))
        selected: Any = None
        selected_from: str | None = None
        for cand in candidates:
            val = _get_path(out, cand)
            if val is not None and val != "":
                selected = val
                selected_from = cand
                break
        step_trace: dict[str, Any] = {
            "index": idx,
            "target": target,
            "candidates": list(candidates),
            "selected_from": selected_from,
            "required": required,
        }
        if selected is None:
            step_trace["resolved"] = False
            if required:
                step_trace["error"] = "required_claim_missing"
            steps.append(step_trace)
            continue
        if target == "roles" and not isinstance(selected, list):
            selected = [selected] if selected is not None else []
        out[target] = selected
        step_trace["resolved"] = True
        steps.append(step_trace)

    trace = {"version": 1, "rules_applied": len(rules), "steps": steps}
    return out, trace
