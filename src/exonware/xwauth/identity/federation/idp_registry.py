#!/usr/bin/env python3
"""
Tenant-scoped IdP registry, dry-run validation, and lightweight health signals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.saml import SamlMetadataTrustSnapshot, SAMLManager


@dataclass(slots=True)
class TenantIdpRecord:
    """Registered IdP for a tenant (OIDC, SAML metadata URL, LDAP ref, etc.)."""

    tenant_id: str
    idp_key: str
    protocol: str
    org_id: str | None = None
    entity_id: str | None = None
    metadata_url: str | None = None
    metadata_xml: str | None = None
    pinned_cert_fingerprints_sha256: list[str] = field(default_factory=list)
    domains: tuple[str, ...] = ()
    extra: dict[str, Any] = field(default_factory=dict)


def idp_isolation_namespace(record: TenantIdpRecord) -> str:
    if record.org_id and str(record.org_id).strip():
        return f"org:{str(record.org_id).strip()}"
    return f"tenant:{(record.tenant_id or '').strip()}"


def idp_record_to_discovery_response(record: TenantIdpRecord) -> dict[str, Any]:
    """Shape returned by SAMLManager.discover_sso_provider / HTTP discovery."""
    extra = record.extra or {}
    idp_url = record.metadata_url or extra.get("idp_sso_url") or extra.get("idp_url")
    return {
        "provider_type": record.protocol or "saml",
        "idp_url": idp_url,
        "entity_id": record.entity_id,
        "idp_key": record.idp_key,
        "tenant_id": record.tenant_id,
        "org_id": record.org_id,
    }


@dataclass(slots=True)
class IdpHealthSnapshot:
    """Interop / operator health signal (cert expiry, trust state)."""

    tenant_id: str
    idp_key: str
    trust_state: str
    metadata_valid_until: str | None
    signing_cert_count: int
    warnings: list[str] = field(default_factory=list)
    org_id: str | None = None


class TenantScopedIdpRegistry:
    """
    In-memory registry with optional persistence hooks via auth.storage.

    Isolation key is ``org:{org_id}`` when ``TenantIdpRecord.org_id`` is set, else ``tenant:{tenant_id}``.
    Domain discovery returns an IdP only when the caller supplies the matching org or tenant scope,
    preventing cross-tenant email-domain leaks.

    Storage keys (when persist=True): ``idp_registry:{namespace}:{idp_key}`` as JSON-compatible dicts.
    """

    def __init__(self, auth: Any, *, persist: bool = False) -> None:
        self._auth = auth
        self._persist = persist
        self._by_key: dict[tuple[str, str], TenantIdpRecord] = {}
        self._domain_index: dict[str, tuple[str, str]] = {}

    def register(self, record: TenantIdpRecord) -> None:
        ns = idp_isolation_namespace(record)
        key = (ns, record.idp_key)
        self._by_key[key] = record
        for domain in record.domains:
            d = domain.lower().strip()
            if d:
                self._domain_index[d] = key
        if self._persist:
            self._persist_record(record)

    def get_in_namespace(self, isolation_namespace: str, idp_key: str) -> TenantIdpRecord | None:
        return self._by_key.get((isolation_namespace, idp_key))

    def get(self, tenant_id: str, idp_key: str) -> TenantIdpRecord | None:
        return self.get_in_namespace(f"tenant:{(tenant_id or '').strip()}", idp_key)

    def get_for_org(self, org_id: str, idp_key: str) -> TenantIdpRecord | None:
        return self.get_in_namespace(f"org:{(org_id or '').strip()}", idp_key)

    def resolve_domain(self, tenant_id: str, email_domain: str) -> TenantIdpRecord | None:
        want = f"tenant:{(tenant_id or '').strip()}"
        key = self._domain_index.get(email_domain.lower().strip())
        if not key or key[0] != want:
            return None
        return self._by_key.get(key)

    def resolve_domain_for_org(self, org_id: str, email_domain: str) -> TenantIdpRecord | None:
        want = f"org:{(org_id or '').strip()}"
        key = self._domain_index.get(email_domain.lower().strip())
        if not key or key[0] != want:
            return None
        return self._by_key.get(key)

    def validate_metadata_dry_run(self, metadata_xml: str, *, source_url: str | None = None) -> SamlMetadataTrustSnapshot:
        """Parse SAML metadata; raises XWAuthError on invalid XML."""
        manager = SAMLManager(self._auth)
        return manager.parse_idp_metadata_xml(metadata_xml, source_url=source_url)

    def health_snapshot(
        self,
        tenant_id: str,
        idp_key: str,
        *,
        metadata_xml: str | None = None,
        source_url: str | None = None,
    ) -> IdpHealthSnapshot:
        return self._health_snapshot_ns(f"tenant:{(tenant_id or '').strip()}", idp_key, tenant_id, None, metadata_xml, source_url)

    def health_snapshot_for_org(
        self,
        org_id: str,
        idp_key: str,
        *,
        metadata_xml: str | None = None,
        source_url: str | None = None,
    ) -> IdpHealthSnapshot:
        return self._health_snapshot_ns(f"org:{(org_id or '').strip()}", idp_key, "", org_id, metadata_xml, source_url)

    def _health_snapshot_ns(
        self,
        ns: str,
        idp_key: str,
        tenant_id: str,
        org_id: str | None,
        metadata_xml: str | None,
        source_url: str | None,
    ) -> IdpHealthSnapshot:
        rec = self.get_in_namespace(ns, idp_key)
        if not rec:
            return IdpHealthSnapshot(
                tenant_id=tenant_id,
                org_id=org_id,
                idp_key=idp_key,
                trust_state="unknown",
                metadata_valid_until=None,
                signing_cert_count=0,
                warnings=["idp_not_registered"],
            )
        xml = metadata_xml or rec.metadata_xml
        warnings: list[str] = []
        if not xml:
            return IdpHealthSnapshot(
                tenant_id=rec.tenant_id,
                org_id=rec.org_id,
                idp_key=idp_key,
                trust_state="unverified",
                metadata_valid_until=None,
                signing_cert_count=0,
                warnings=["metadata_not_loaded"],
            )
        manager = SAMLManager(self._auth)
        snap = manager.parse_idp_metadata_xml(xml, source_url=source_url or rec.metadata_url)
        trusted = manager.verify_metadata_trust(snap, rec.pinned_cert_fingerprints_sha256 or None)
        if snap.valid_until:
            warnings.append("check_metadata_valid_until_calendar")
        if not trusted and rec.pinned_cert_fingerprints_sha256:
            warnings.append("metadata_cert_not_in_pin_set")
        return IdpHealthSnapshot(
            tenant_id=rec.tenant_id,
            org_id=rec.org_id,
            idp_key=idp_key,
            trust_state=snap.trust_state,
            metadata_valid_until=snap.valid_until,
            signing_cert_count=len(snap.signing_cert_fingerprints_sha256),
            warnings=warnings,
        )

    def _persist_record(self, record: TenantIdpRecord) -> None:
        storage = self._auth.storage
        ns = idp_isolation_namespace(record)
        key = f"idp_registry:{ns}:{record.idp_key}"
        payload = {
            "tenant_id": record.tenant_id,
            "org_id": record.org_id,
            "idp_key": record.idp_key,
            "protocol": record.protocol,
            "entity_id": record.entity_id,
            "metadata_url": record.metadata_url,
            "metadata_xml": record.metadata_xml,
            "pinned_cert_fingerprints_sha256": list(record.pinned_cert_fingerprints_sha256),
            "domains": list(record.domains),
            "extra": dict(record.extra),
        }
        try:
            if hasattr(storage, "create"):
                storage.create(key, payload)
            elif hasattr(storage, "write"):
                storage.write(key, payload)
        except Exception:
            pass
