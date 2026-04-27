# exonware/xwauth.identity/src/exonware/xwauth.identity/security/mfa_policy.py
"""Central MFA / WebAuthn policy hooks (profiles A/B/C)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class MfaSecurityProfile(str, Enum):
    """Security posture for MFA and passkeys (aligned with protocol profiles)."""

    A = "A"
    B = "B"
    C = "C"


@dataclass(frozen=True)
class MfaPolicyContext:
    tenant_id: str | None = None
    user_id: str | None = None
    route: str | None = None
    scopes: tuple[str, ...] = ()


def attestation_for_profile(profile: str | MfaSecurityProfile) -> str:
    p = profile.value if isinstance(profile, MfaSecurityProfile) else str(profile).upper()
    if p == "C":
        return "direct"
    if p == "B":
        return "indirect"
    return "none"


def require_backup_codes(profile: str | MfaSecurityProfile) -> bool:
    p = profile.value if isinstance(profile, MfaSecurityProfile) else str(profile).upper()
    return p in ("B", "C")


def step_up_required_aal2(
    *,
    policy_profile: str,
    sensitive: bool,
    current_aal: str | None,
) -> bool:
    """Return True when policy demands AAL2 for a sensitive action."""
    if not sensitive:
        return False
    p = (policy_profile or "A").upper()
    if p not in ("A", "B", "C"):
        p = "A"
    if current_aal == "aal2":
        return False
    return True


def merge_amr_claims(existing: list[str] | None, *methods: str) -> list[str]:
    merged: list[str] = []
    for src in existing or []:
        if src and src not in merged:
            merged.append(str(src))
    for m in methods:
        if m and m not in merged:
            merged.append(m)
    return merged
