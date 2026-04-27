#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/kubernetes_operator_readiness.py
Readiness checklist for a **Kubernetes operator** beyond Helm (REF_25 #4).

Pairs with golden-path Compose/Helm; operator adds day-2 lifecycle hooks.
"""

from __future__ import annotations

from typing import Any

K8S_OPERATOR_READINESS_SCHEMA_VERSION = 1


def kubernetes_operator_readiness_checklist() -> dict[str, Any]:
    """Expectations for upgrades, health, and key-rotation hooks when shipping an operator."""
    return {
        "schema_version": K8S_OPERATOR_READINESS_SCHEMA_VERSION,
        "kind": "kubernetes_operator_readiness",
        "sections": [
            {
                "id": "value_over_helm",
                "title": "Value beyond static Helm",
                "items": [
                    "Document what the **operator automates** that Helm alone cannot (e.g. coordinated upgrades, CR-driven reconfigure, key rotation jobs).",
                    "Keep **Helm charts** viable for users who do not want an operator.",
                ],
            },
            {
                "id": "crd_and_api",
                "title": "CRD / API surface",
                "items": [
                    "Version **CRDs** (v1alpha1 → v1beta1) with conversion or migration notes.",
                    "Validate spec with **CEL** or admission webhooks where Kubernetes version allows.",
                ],
            },
            {
                "id": "rollout_and_health",
                "title": "Rollout and health",
                "items": [
                    "Integrate **readiness/liveness** probes with AS health (JWKS readiness, storage connectivity).",
                    "Use **PodDisruptionBudgets** and sensible `maxUnavailable` for rolling updates.",
                ],
            },
            {
                "id": "key_rotation",
                "title": "Signing key rotation",
                "items": [
                    "Operator or **CronJob** triggers key generation, JWKS publication, and phased cutover.",
                    "Surface rotation **status** in CR status fields and metrics for SRE dashboards.",
                ],
            },
            {
                "id": "observability",
                "title": "Observability",
                "items": [
                    "Emit **metrics** consistent with REF_60+ contracts where applicable.",
                    "Structured logs with **correlation ids** across operator reconcile loops and workload pods.",
                ],
            },
        ],
    }
