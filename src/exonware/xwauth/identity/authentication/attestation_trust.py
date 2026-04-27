# exonware/xwauth.identity/authentication/attestation_trust.py
"""
WebAuthn attestation trust roots (enterprise CA bundles), aligned with py_webauthn
``pem_root_certs_bytes_by_fmt`` (Keycloak-style operator-supplied trust, not FIDO MDS download).
"""

from __future__ import annotations

from typing import Any


def build_pem_root_certs_bytes_by_fmt(pem_certificates: list[str]) -> dict[Any, list[bytes]] | None:
    """
    Map trusted attestation CA PEM blobs to all ``AttestationFormat`` values except ``NONE``.

    Operators typically load one org CA bundle and apply it to packed/TPM/Apple/Android formats.
    """
    if not pem_certificates:
        return None
    roots: list[bytes] = []
    for p in pem_certificates:
        s = (p or "").strip()
        if s:
            roots.append(s.encode("utf-8"))
    if not roots:
        return None
    try:
        from webauthn.helpers.structs import AttestationFormat
    except ImportError:
        return None
    out: dict[Any, list[bytes]] = {}
    for fmt in AttestationFormat:
        if fmt == AttestationFormat.NONE:
            continue
        out[fmt] = roots
    return out
