#!/usr/bin/env python3
"""
Unit tests for LDAP provider mapping contracts.
"""

from __future__ import annotations

import pytest

from exonware.xwauth.connect.providers.ldap import LDAPMappingContract, LDAPProvider


@pytest.mark.xwlogin_unit
def test_ldap_mapping_contract_includes_group_attributes() -> None:
    contract = LDAPMappingContract(
        group_attributes=("memberOf", "groups"),
        group_to_roles=True,
        group_role_mapping={"cn=admins,ou=groups,dc=example,dc=com": "admin"},
    )
    attrs = contract.ldap_attributes_for_fetch()
    assert "uid" in attrs
    assert "mail" in attrs
    assert "memberOf" in attrs
    assert "groups" in attrs


@pytest.mark.xwlogin_unit
def test_ldap_provider_maps_groups_and_roles() -> None:
    contract = LDAPMappingContract(
        group_attributes=("memberOf",),
        group_to_roles=True,
        group_role_mapping={"cn=admins,ou=groups,dc=example,dc=com": "admin"},
    )
    provider = LDAPProvider(
        server="ldap.example.com",
        base_dn="dc=example,dc=com",
        client_id="ldap-client",
        client_secret="ldap-secret",
        mapping_contract=contract,
    )
    entry = {
        "uid": ["alice"],
        "mail": ["alice@example.com"],
        "cn": ["Alice Example"],
        "givenName": ["Alice"],
        "sn": ["Example"],
        "memberOf": ["cn=admins,ou=groups,dc=example,dc=com"],
    }
    user_info = provider._map_ldap_entry_to_user_info(entry, username="alice")
    assert user_info["id"] == "alice"
    assert user_info["email"] == "alice@example.com"
    assert user_info["groups"] == ["cn=admins,ou=groups,dc=example,dc=com"]
    assert user_info["roles"] == ["admin"]
    assert user_info["mapping_trace"]["group_to_roles"] is True

