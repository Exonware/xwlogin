#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/saml.py
SAML SSO Manager
SAML 2.0 Single Sign-On implementation with metadata generation and ACS handling.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from __future__ import annotations
import base64
import os
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any
from urllib.parse import urlencode
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.errors import XWAuthError
logger = get_logger(__name__)

_DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
# ElementTree ``.//`` matches descendants only, not the context node (signed Assertion-as-root payloads).
_SAML_ASSERTION_TAG = f"{{{_SAML_ASSERTION_NS}}}Assertion"


def _find_saml_assertion_element(xml_root: ET.Element) -> ET.Element | None:
    if xml_root.tag == _SAML_ASSERTION_TAG:
        return xml_root
    return xml_root.find(f".//{_SAML_ASSERTION_TAG}")


@dataclass(slots=True)
class SamlMetadataTrustSnapshot:
    """SAML metadata trust snapshot used for trust-rotation workflows."""

    entity_id: str
    signing_cert_fingerprints_sha256: list[str]
    valid_until: str | None
    source_url: str | None
    fetched_at: str
    trust_state: str = "unverified"


class SAMLManager:
    """
    SAML SSO manager.
    Handles SAML metadata generation, ACS endpoint processing, and SSO discovery.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize SAML manager.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._config = auth.config
        self._storage = auth.storage
        self._seen_response_ids: set[str] = set()
        self._seen_assertion_ids: set[str] = set()
        logger.debug("SAMLManager initialized")

    @staticmethod
    def _utc_now_iso() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _extract_cert_fingerprint(cert_text: str) -> str:
        compact = "".join((cert_text or "").split())
        if not compact:
            return ""
        try:
            decoded = base64.b64decode(compact, validate=True)
        except Exception:
            decoded = compact.encode("utf-8")
        return sha256(decoded).hexdigest()

    @staticmethod
    def _strict_validation_enabled(config: Any) -> bool:
        value = getattr(config, "saml_strict_validation", False)
        return bool(value)

    def _clock_skew(self) -> timedelta:
        sec = int(getattr(self._config, "saml_clock_skew_seconds", 120) or 0)
        return timedelta(seconds=max(0, sec))

    @staticmethod
    def _parse_saml_time(value: str) -> datetime:
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        return datetime.fromisoformat(normalized).astimezone(timezone.utc)

    def _check_and_record_replay(self, response_id: str | None, assertion_id: str | None) -> None:
        if response_id:
            if response_id in self._seen_response_ids:
                raise XWAuthError(
                    "SAML strict validation failed: replayed response id",
                    error_code="saml_strict_validation_failed",
                )
            self._seen_response_ids.add(response_id)
        if assertion_id:
            if assertion_id in self._seen_assertion_ids:
                raise XWAuthError(
                    "SAML strict validation failed: replayed assertion id",
                    error_code="saml_strict_validation_failed",
                )
            self._seen_assertion_ids.add(assertion_id)
        # Keep replay cache bounded.
        if len(self._seen_response_ids) > 10000:
            self._seen_response_ids.clear()
        if len(self._seen_assertion_ids) > 10000:
            self._seen_assertion_ids.clear()

    @staticmethod
    def _saml_trust_verification_enabled(config: Any) -> bool:
        pe = getattr(config, "saml_idp_signing_certificates_pem", None) or []
        pins = getattr(config, "saml_idp_certificate_pins_sha256", None) or []
        return bool(pe) or bool(pins)

    @staticmethod
    def _extract_x509_der_from_signature_lxml(element: Any) -> bytes | None:
        """First embedded X509Certificate DER under XML-DSig (lxml element)."""
        for cert_node in element.findall(f".//{{{_DS_NS}}}X509Certificate"):
            if not cert_node.text:
                continue
            raw = "".join(cert_node.text.split())
            try:
                return base64.b64decode(raw, validate=True)
            except Exception:
                continue
        return None

    def _verify_xml_signatures(self, decoded_response: bytes, config: Any) -> None:
        """
        Verify XML-DSig on SAML Response or Assertion when IdP trust material is configured.
        Requires optional dependency ``signxml`` (``pip install 'exonware-xwauth[saml]'``).
        """
        try:
            from lxml import etree
            from signxml import XMLVerifier
        except ImportError as exc:
            raise XWAuthError(
                "SAML XML signature verification requires signxml "
                "(pip install 'exonware-xwauth[saml]').",
                error_code="saml_signxml_required",
            ) from exc

        try:
            root = etree.fromstring(decoded_response)
        except etree.XMLSyntaxError as exc:
            raise XWAuthError(
                f"Invalid SAML response XML: {exc}",
                error_code="invalid_saml_xml",
            ) from exc

        assertion_el = root.find(f".//{{{_SAML_ASSERTION_NS}}}Assertion")
        ds_sig = f"{{{_DS_NS}}}Signature"
        signed_el = None
        for el in (assertion_el, root):
            if el is None:
                continue
            if el.find(f".//{ds_sig}") is not None:
                signed_el = el
                break
        if signed_el is None:
            raise XWAuthError(
                "SAML trust validation requires an XML digital signature on the assertion or response",
                error_code="saml_signature_missing",
            )

        pe_list = [
            p.strip()
            for p in (getattr(config, "saml_idp_signing_certificates_pem", None) or [])
            if isinstance(p, str) and p.strip()
        ]
        pins_raw = getattr(config, "saml_idp_certificate_pins_sha256", None) or []
        pins = {
            p.strip().lower().replace(":", "")
            for p in pins_raw
            if isinstance(p, str) and p.strip()
        }
        ca = getattr(config, "saml_idp_ca_bundle_pem", None)
        ca_kw: dict[str, Any] = {}
        if isinstance(ca, str) and ca.strip():
            ca_kw["ca_pem_file"] = ca.encode("utf-8")

        verifier = XMLVerifier()
        last_error: Exception | None = None

        for pem in pe_list:
            try:
                verifier.verify(signed_el, x509_cert=pem, **ca_kw)
                return
            except Exception as e:
                last_error = e

        der = self._extract_x509_der_from_signature_lxml(signed_el)
        if der is not None and pins:
            fp = sha256(der).hexdigest()
            if fp.lower() not in pins:
                raise XWAuthError(
                    "SAML signing certificate is not pinned (SHA-256 fingerprint mismatch)",
                    error_code="saml_cert_pin_mismatch",
                )
            try:
                from cryptography import x509 as cx509

                cert_obj = cx509.load_der_x509_certificate(der)
                verifier.verify(signed_el, x509_cert=cert_obj, **ca_kw)
                return
            except Exception as e:
                last_error = e

        if pins and der is None:
            raise XWAuthError(
                "SAML signature is missing X509Certificate in KeyInfo (required for certificate pinning)",
                error_code="saml_signature_missing_keyinfo_cert",
            )

        msg = "SAML XML signature verification failed"
        if last_error is not None:
            msg = f"{msg}: {last_error}"
        raise XWAuthError(msg, error_code="saml_signature_invalid")

    def parse_idp_metadata_xml(self, metadata_xml: str, source_url: str | None = None) -> SamlMetadataTrustSnapshot:
        """Parse IdP metadata into a trust snapshot for rotation workflows."""
        try:
            root = ET.fromstring(metadata_xml)
        except ET.ParseError as exc:
            raise XWAuthError(
                f"Invalid SAML metadata XML: {exc}",
                error_code="invalid_saml_metadata_xml",
            ) from exc

        entity_id = root.get("entityID") or ""
        valid_until = root.get("validUntil")
        cert_nodes = root.findall(".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
        fingerprints = []
        for cert_node in cert_nodes:
            if cert_node.text:
                fingerprint = self._extract_cert_fingerprint(cert_node.text)
                if fingerprint:
                    fingerprints.append(fingerprint)
        return SamlMetadataTrustSnapshot(
            entity_id=entity_id,
            signing_cert_fingerprints_sha256=sorted(set(fingerprints)),
            valid_until=valid_until,
            source_url=source_url,
            fetched_at=self._utc_now_iso(),
        )

    def verify_metadata_trust(
        self,
        snapshot: SamlMetadataTrustSnapshot,
        pinned_fingerprints_sha256: list[str] | None,
    ) -> bool:
        """Verify metadata snapshot against pinned fingerprints."""
        if not pinned_fingerprints_sha256:
            snapshot.trust_state = "unverified"
            return True
        pinned = {item.strip().lower() for item in pinned_fingerprints_sha256 if item and item.strip()}
        seen = {item.strip().lower() for item in snapshot.signing_cert_fingerprints_sha256 if item and item.strip()}
        trusted = bool(seen.intersection(pinned))
        snapshot.trust_state = "validated" if trusted else "rejected"
        return trusted

    def _extract_assertion_trace(self, xml_response: ET.Element, assertion: ET.Element) -> dict[str, Any]:
        namespace = {
            "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        }
        audiences = [
            node.text
            for node in assertion.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Audience", namespace)
            if node.text
        ]
        return {
            "response_id": xml_response.get("ID"),
            "in_response_to": xml_response.get("InResponseTo"),
            "assertion_id": assertion.get("ID"),
            "audiences": audiences,
        }

    def _enforce_strict_validation(self, xml_response: ET.Element, assertion: ET.Element) -> None:
        namespace = {
            "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        }
        status_code = xml_response.find(".//{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode", namespace)
        if status_code is None or status_code.get("Value") != "urn:oasis:names:tc:SAML:2.0:status:Success":
            raise XWAuthError("SAML strict validation failed: non-success StatusCode", error_code="saml_strict_validation_failed")

        response_id = xml_response.get("ID")
        assertion_id = assertion.get("ID")
        if not response_id:
            raise XWAuthError("SAML strict validation failed: missing Response ID", error_code="saml_strict_validation_failed")
        if not assertion_id:
            raise XWAuthError("SAML strict validation failed: missing Assertion ID", error_code="saml_strict_validation_failed")

        subject_confirmation_data = assertion.find(
            ".//{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData",
            namespace,
        )
        if subject_confirmation_data is None:
            raise XWAuthError("SAML strict validation failed: missing SubjectConfirmationData", error_code="saml_strict_validation_failed")
        if not subject_confirmation_data.get("Recipient"):
            raise XWAuthError("SAML strict validation failed: missing Recipient", error_code="saml_strict_validation_failed")
        not_on_or_after = subject_confirmation_data.get("NotOnOrAfter")
        if not not_on_or_after:
            raise XWAuthError("SAML strict validation failed: missing NotOnOrAfter", error_code="saml_strict_validation_failed")
        try:
            expiry = self._parse_saml_time(not_on_or_after)
        except Exception as exc:
            raise XWAuthError(
                "SAML strict validation failed: invalid NotOnOrAfter format",
                error_code="saml_strict_validation_failed",
            ) from exc
        skew = self._clock_skew()
        now = datetime.now(timezone.utc)
        if expiry + skew < now:
            raise XWAuthError(
                "SAML strict validation failed: assertion expired",
                error_code="saml_strict_validation_failed",
            )

        conditions = assertion.find(
            ".//{urn:oasis:names:tc:SAML:2.0:assertion}Conditions",
            namespace,
        )
        if conditions is not None:
            cond_noa = conditions.get("NotOnOrAfter")
            if cond_noa:
                try:
                    cexp = self._parse_saml_time(cond_noa)
                except Exception as exc:
                    raise XWAuthError(
                        "SAML strict validation failed: invalid Conditions NotOnOrAfter",
                        error_code="saml_strict_validation_failed",
                    ) from exc
                if cexp + skew < now:
                    raise XWAuthError(
                        "SAML strict validation failed: conditions expired",
                        error_code="saml_strict_validation_failed",
                    )
            cond_nb = conditions.get("NotBefore")
            if cond_nb:
                try:
                    cstart = self._parse_saml_time(cond_nb)
                except Exception as exc:
                    raise XWAuthError(
                        "SAML strict validation failed: invalid Conditions NotBefore",
                        error_code="saml_strict_validation_failed",
                    ) from exc
                if cstart - skew > now:
                    raise XWAuthError(
                        "SAML strict validation failed: assertion not yet valid",
                        error_code="saml_strict_validation_failed",
                    )

        response_in_response_to = xml_response.get("InResponseTo")
        subject_in_response_to = subject_confirmation_data.get("InResponseTo")
        if not response_in_response_to:
            raise XWAuthError("SAML strict validation failed: missing Response InResponseTo", error_code="saml_strict_validation_failed")
        if not subject_in_response_to:
            raise XWAuthError("SAML strict validation failed: missing SubjectConfirmationData InResponseTo", error_code="saml_strict_validation_failed")
        if response_in_response_to != subject_in_response_to:
            raise XWAuthError(
                "SAML strict validation failed: InResponseTo mismatch",
                error_code="saml_strict_validation_failed",
            )

        audience_nodes = assertion.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Audience", namespace)
        if not audience_nodes or not any(node.text for node in audience_nodes):
            raise XWAuthError("SAML strict validation failed: missing AudienceRestriction", error_code="saml_strict_validation_failed")

        expected_audiences = list(getattr(self._config, "saml_expected_audiences", None) or [])
        if not expected_audiences:
            ent = getattr(self._config, "saml_entity_id", None)
            if ent:
                expected_audiences = [str(ent)]
        if expected_audiences:
            aud_values = [str(n.text).strip() for n in audience_nodes if n.text and str(n.text).strip()]
            if not any(aud in aud_values for aud in expected_audiences):
                raise XWAuthError(
                    "SAML strict validation failed: audience mismatch",
                    error_code="saml_strict_validation_failed",
                )

        self._check_and_record_replay(response_id=response_id, assertion_id=assertion_id)

    def generate_metadata(
        self,
        entity_id: str,
        acs_url: str,
        slo_url: str | None = None,
        certificate: str | None = None,
    ) -> str:
        """
        Generate SAML 2.0 Service Provider metadata XML.
        Args:
            entity_id: Service Provider entity ID
            acs_url: Assertion Consumer Service URL
            slo_url: Single Logout Service URL (optional)
            certificate: X.509 certificate for signing (optional)
        Returns:
            SAML metadata XML string
        """
        # Build metadata XML
        root = ET.Element(
            "{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor",
            attrib={
                "entityID": entity_id,
                "xmlns": "urn:oasis:names:tc:SAML:2.0:metadata",
                "xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
            }
        )
        # SPSSODescriptor
        sp_descriptor = ET.SubElement(
            root,
            "{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor",
            attrib={
                "protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
                "WantAssertionsSigned": "true",
            }
        )
        # KeyDescriptor (if certificate provided)
        if certificate:
            key_descriptor = ET.SubElement(
                sp_descriptor,
                "{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor",
                attrib={"use": "signing"}
            )
            key_info = ET.SubElement(
                key_descriptor,
                "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
            )
            x509_data = ET.SubElement(
                key_info,
                "{http://www.w3.org/2000/09/xmldsig#}X509Data"
            )
            x509_cert = ET.SubElement(
                x509_data,
                "{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
            )
            x509_cert.text = certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "").strip()
        # AssertionConsumerService
        acs = ET.SubElement(
            sp_descriptor,
            "{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService",
            attrib={
                "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "Location": acs_url,
                "index": "0",
            }
        )
        # SingleLogoutService (if provided)
        if slo_url:
            slo = ET.SubElement(
                sp_descriptor,
                "{urn:oasis:names:tc:SAML:2.0:metadata}SingleLogoutService",
                attrib={
                    "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                    "Location": slo_url,
                }
            )
        # Convert to XML string
        ET.indent(root, space="  ")
        xml_str = ET.tostring(root, encoding='unicode', xml_declaration=True)
        return xml_str

    async def process_acs(
        self,
        saml_response: str,
        relay_state: str | None = None,
    ) -> dict[str, Any]:
        """
        Process SAML Assertion Consumer Service response.
        Args:
            saml_response: Base64-encoded SAML response
            relay_state: Relay state parameter (optional)
        Returns:
            Dictionary with user information and authentication result
        Raises:
            XWAuthError: If SAML response is invalid
        """
        try:
            # Decode SAML response
            decoded_response = base64.b64decode(saml_response)
            xml_response = ET.fromstring(decoded_response)
            namespace = {
                'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
                'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
            }
            assertion = _find_saml_assertion_element(xml_response)
            if assertion is None:
                raise XWAuthError(
                    "Invalid SAML response: No assertion found",
                    error_code="invalid_saml_response"
                )
            if self._saml_trust_verification_enabled(self._config):
                self._verify_xml_signatures(decoded_response, self._config)
            if self._strict_validation_enabled(self._config):
                self._enforce_strict_validation(xml_response, assertion)
            # Extract subject (user identifier)
            subject = assertion.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Subject', namespace)
            if subject is None:
                raise XWAuthError(
                    "Invalid SAML response: No subject found",
                    error_code="invalid_saml_response"
                )
            name_id = subject.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}NameID', namespace)
            if name_id is None:
                raise XWAuthError(
                    "Invalid SAML response: No NameID found",
                    error_code="invalid_saml_response"
                )
            user_id = name_id.text
            # Extract attributes
            attribute_statement = assertion.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement', namespace)
            attributes = {}
            if attribute_statement:
                for attr in attribute_statement.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute', namespace):
                    attr_name = attr.get('Name')
                    attr_values = attr.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue', namespace)
                    if attr_values:
                        attributes[attr_name] = attr_values[0].text if len(attr_values) == 1 else [v.text for v in attr_values]
            # Extract email (common attribute)
            email = attributes.get('email') or attributes.get('Email') or attributes.get('mail') or attributes.get('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress')
            if isinstance(email, list):
                email = email[0] if email else None
            logger.debug(f"Processed SAML assertion for user: {user_id}")
            return {
                "user_id": user_id,
                "email": email,
                "attributes": attributes,
                "relay_state": relay_state,
                "assertion_trace": self._extract_assertion_trace(xml_response, assertion),
            }
        except ET.ParseError as e:
            raise XWAuthError(
                f"Invalid SAML response XML: {e}",
                error_code="invalid_saml_xml"
            )
        except XWAuthError:
            raise
        except Exception as e:
            raise XWAuthError(
                f"Error processing SAML response: {e}",
                error_code="saml_processing_error"
            )

    async def discover_sso_provider(self, email: str, *, org_id: str | None = None) -> dict[str, Any] | None:
        """
        Discover SSO provider by email domain.
        When ``org_id`` is set, only the org-scoped IdP registry is consulted first; by default
        legacy global ``sso_domain:`` storage is not used unless
        ``XWAUTH_SSO_DISCOVERY_ORG_LEGACY_FALLBACK`` is truthy (avoids cross-org domain leaks).

        Args:
            email: User email address
            org_id: Optional B2B organization id to scope federation discovery
        Returns:
            SSO provider configuration or None if not found
        """
        if not email or '@' not in email:
            return None
        domain = email.split('@')[1].lower()
        reg = getattr(self._auth, "tenant_idp_registry", None)
        org = (org_id or "").strip()
        if org and reg is not None:
            rec = reg.resolve_domain_for_org(org, domain)
            if rec is not None:
                from ..federation.idp_registry import idp_record_to_discovery_response
                return idp_record_to_discovery_response(rec)
            if os.environ.get("XWAUTH_SSO_DISCOVERY_ORG_LEGACY_FALLBACK", "").strip().lower() not in {
                "1",
                "true",
                "yes",
                "on",
            }:
                return None
        # Check storage for domain-based SSO configuration
        # In production, this would query a database of domain-to-SSO-provider mappings
        sso_key = f"sso_domain:{domain}"
        if hasattr(self._storage, 'read'):
            sso_config = await self._storage.read(sso_key)
            if sso_config:
                return sso_config
        else:
            # Fallback to in-memory storage
            if hasattr(self._storage, '_sso_domains'):
                sso_config = self._storage._sso_domains.get(domain)
                if sso_config:
                    return sso_config
        return None

    def rotate_metadata_trust(
        self,
        provider_key: str,
        metadata_xml: str,
        *,
        source_url: str | None = None,
        pinned_fingerprints_sha256: list[str] | None = None,
    ) -> SamlMetadataTrustSnapshot:
        """Build and verify a metadata trust snapshot for rotation workflows."""
        snapshot = self.parse_idp_metadata_xml(metadata_xml, source_url=source_url)
        self.verify_metadata_trust(snapshot, pinned_fingerprints_sha256)
        if hasattr(self._storage, "create"):
            try:
                trust_key = f"saml:metadata:trust:{provider_key}"
                # Best-effort persistence; storage implementations differ by project.
                self._storage.create(trust_key, asdict(snapshot))
            except Exception:
                logger.debug("SAML trust snapshot persistence unavailable", exc_info=True)
        return snapshot

    def generate_authn_request(
        self,
        idp_url: str,
        sp_entity_id: str,
        acs_url: str,
        relay_state: str | None = None,
    ) -> str:
        """
        Generate SAML AuthnRequest URL.
        Args:
            idp_url: Identity Provider URL
            sp_entity_id: Service Provider entity ID
            acs_url: Assertion Consumer Service URL
            relay_state: Relay state parameter (optional)
        Returns:
            SAML AuthnRequest URL
        """
        # Build AuthnRequest XML (simplified)
        # In production, use proper SAML library
        authn_request = f"""<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_{self._generate_id()}"
    Version="2.0"
    IssueInstant="{datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}"
    Destination="{idp_url}"
    AssertionConsumerServiceURL="{acs_url}">
    <saml:Issuer>{sp_entity_id}</saml:Issuer>
</samlp:AuthnRequest>"""
        # Encode and build URL
        encoded_request = base64.b64encode(authn_request.encode()).decode()
        params = {
            'SAMLRequest': encoded_request,
        }
        if relay_state:
            params['RelayState'] = relay_state
        return f"{idp_url}?{urlencode(params)}"

    def _generate_id(self) -> str:
        """Generate unique ID for SAML request."""
        import secrets
        random_bytes = secrets.token_bytes(16)
        return base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
