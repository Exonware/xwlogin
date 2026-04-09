#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/ldap.py
LDAP Provider
LDAP (Lightweight Directory Access Protocol) authentication provider.
Note: LDAP is not OAuth 2.0, but is included for enterprise authentication.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import CoreABaseProvider, IProvider, ProviderType, XWProviderError
from dataclasses import dataclass, field
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class LDAPProvider(CoreABaseProvider, IProvider):
    """
    LDAP authentication provider.
    Note: LDAP is not OAuth 2.0. This is a direct authentication provider
    that authenticates against an LDAP directory server.
    """

    def __init__(
        self,
        server: str,
        base_dn: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
        use_ssl: bool = True,
        port: int | None = None,
        user_dn_template: str = "uid={username},{base_dn}",
        search_filter_template: str = "(uid={username})",
        mapping_contract: "LDAPMappingContract | None" = None,
        jit_provisioning: bool = True,
        directory_sync_enabled: bool = False,
        **kwargs
    ):
        """
        Initialize LDAP provider.
        Args:
            server: LDAP server hostname or IP
            base_dn: Base distinguished name (e.g., 'dc=example,dc=com')
            bind_dn: Bind DN for authentication (optional)
            bind_password: Bind password (optional)
            use_ssl: Use SSL/TLS (default: True)
            port: LDAP port (default: 389 for LDAP, 636 for LDAPS)
            **kwargs: Additional configuration
        """
        super().__init__(**kwargs)
        self.server = server
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.use_ssl = use_ssl
        self.port = port or (636 if use_ssl else 389)
        self.user_dn_template = user_dn_template
        self.search_filter_template = search_filter_template
        self.mapping_contract = mapping_contract or LDAPMappingContract.default()
        self.jit_provisioning = bool(jit_provisioning)
        self.directory_sync_enabled = bool(directory_sync_enabled)
        logger.warning(
            "LDAP is not OAuth 2.0. This provider uses direct LDAP authentication. "
            "For OAuth 2.0 with Active Directory, use ActiveDirectoryProvider or ADFSProvider."
        )

    @staticmethod
    def _entry_as_dict(entry: Any) -> dict[str, Any]:
        attrs = getattr(entry, "entry_attributes_as_dict", None)
        if isinstance(attrs, dict):
            return attrs
        if isinstance(entry, dict):
            return entry
        return {}

    @staticmethod
    def _first_value(value: Any, fallback: str | None = None) -> str | None:
        if isinstance(value, list):
            if not value:
                return fallback
            return str(value[0]) if value[0] is not None else fallback
        if value is None:
            return fallback
        return str(value)

    def _extract_groups(self, attrs: dict[str, Any]) -> list[str]:
        groups: list[str] = []
        for attribute_name in self.mapping_contract.group_attributes:
            raw = attrs.get(attribute_name)
            if raw is None:
                continue
            if isinstance(raw, list):
                groups.extend(str(item) for item in raw if item is not None)
            else:
                groups.append(str(raw))
        deduped: list[str] = []
        for group in groups:
            if group not in deduped:
                deduped.append(group)
        return deduped

    def _extract_roles(self, groups: list[str]) -> list[str]:
        if not self.mapping_contract.group_to_roles:
            return []
        roles: list[str] = []
        role_map = self.mapping_contract.group_role_mapping
        for group in groups:
            mapped = role_map.get(group)
            if mapped and mapped not in roles:
                roles.append(mapped)
        return roles

    def _map_ldap_entry_to_user_info(self, entry: Any, username: str) -> dict[str, Any]:
        attrs = self._entry_as_dict(entry)
        contract = self.mapping_contract

        username_value = self._first_value(attrs.get(contract.username_attribute), fallback=username) or username
        email_value = self._first_value(attrs.get(contract.email_attribute), fallback="")
        display_name_value = self._first_value(attrs.get(contract.display_name_attribute), fallback="")
        given_name_value = self._first_value(attrs.get(contract.given_name_attribute), fallback="")
        family_name_value = self._first_value(attrs.get(contract.family_name_attribute), fallback="")

        groups = self._extract_groups(attrs)
        roles = self._extract_roles(groups)

        return {
            "id": username_value,
            "username": username_value,
            "email": email_value,
            "name": display_name_value,
            "given_name": given_name_value,
            "family_name": family_name_value,
            "groups": groups,
            "roles": roles,
            "mapping_trace": {
                "username_attribute": contract.username_attribute,
                "email_attribute": contract.email_attribute,
                "display_name_attribute": contract.display_name_attribute,
                "group_attributes": list(contract.group_attributes),
                "group_to_roles": contract.group_to_roles,
                "jit_provisioning": self.jit_provisioning,
                "directory_sync_enabled": self.directory_sync_enabled,
            },
        }
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "ldap"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.LDAP

    async def authenticate(self, credentials: dict[str, Any]) -> dict[str, Any]:
        """
        Authenticate user against LDAP server.
        Args:
            credentials: Dictionary with 'username' and 'password'
        Returns:
            Authentication result with user information
        Raises:
            XWProviderError: If authentication fails
        """
        try:
            import ldap3
        except ImportError:
            raise XWProviderError(
                "ldap3 library required for LDAP authentication. "
                "Install it with: pip install ldap3",
                error_code="ldap3_not_available"
            )
        username = credentials.get('username')
        password = credentials.get('password')
        if not username or not password:
            raise XWProviderError(
                "Username and password required for LDAP authentication",
                error_code="missing_credentials"
            )
        # Build LDAP server URL
        protocol = 'ldaps' if self.use_ssl else 'ldap'
        server_url = f"{protocol}://{self.server}:{self.port}"
        # Create server and connection
        server = ldap3.Server(server_url, get_info=ldap3.ALL)
        # Build user DN
        user_dn = self.user_dn_template.format(username=username, base_dn=self.base_dn)
        try:
            conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
            # Search for user details
            conn.search(
                search_base=self.base_dn,
                search_filter=self.search_filter_template.format(username=username, base_dn=self.base_dn),
                search_scope=ldap3.SUBTREE,
                attributes=self.mapping_contract.ldap_attributes_for_fetch(),
            )
            if conn.entries:
                entry = conn.entries[0]
                user_info = self._map_ldap_entry_to_user_info(entry, username=username)
                conn.unbind()
                return user_info
            else:
                conn.unbind()
                raise XWProviderError(
                    "User not found in LDAP directory",
                    error_code="user_not_found"
                )
        except ldap3.core.exceptions.LDAPBindError as e:
            raise XWProviderError(
                f"LDAP authentication failed: {e}",
                error_code="ldap_auth_failed",
                cause=e
            )
        except Exception as e:
            raise XWProviderError(
                f"LDAP error: {e}",
                error_code="ldap_error",
                cause=e
            )


@dataclass(slots=True)
class LDAPMappingContract:
    """Mapping contract for LDAP/AD field normalization and group-role extraction."""

    username_attribute: str = "uid"
    email_attribute: str = "mail"
    display_name_attribute: str = "cn"
    given_name_attribute: str = "givenName"
    family_name_attribute: str = "sn"
    group_attributes: tuple[str, ...] = ("memberOf",)
    group_role_mapping: dict[str, str] = field(default_factory=dict)
    group_to_roles: bool = False

    @classmethod
    def default(cls) -> "LDAPMappingContract":
        return cls()

    def ldap_attributes_for_fetch(self) -> list[str]:
        ordered: list[str] = []
        for attr in (
            self.username_attribute,
            self.email_attribute,
            self.display_name_attribute,
            self.given_name_attribute,
            self.family_name_attribute,
            *self.group_attributes,
        ):
            if attr and attr not in ordered:
                ordered.append(attr)
        return ordered
