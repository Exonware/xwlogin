#!/usr/bin/env python3
"""
Unit tests for EntitySessionManager.
Verify that create_session finds entities by name and stores session on the entity dict.
Used to debug "Entity 'RU-KARIZMA' not found, cannot create session" and status "No session created".
"""

from __future__ import annotations

import pytest
from exonware.xwlogin.clients.entity_session_manager import EntitySessionManager


@pytest.mark.xwlogin_unit
class TestEntitySessionManager:
    """Test EntitySessionManager session creation (authentication flow)."""

    def test_create_session_finds_entity_by_name(self):
        """Entity name in entities dict -> create_session(name) returns session and stores it."""
        entities = {
            "RU-KARIZMA": {
                "name": "RU-KARIZMA",
                "company_id": 940,
                "session": None,
            }
        }
        manager = EntitySessionManager(entities)
        session = manager.create_session("RU-KARIZMA")
        assert session is not None
        assert entities["RU-KARIZMA"]["session"] is session
        assert manager.get_entity_session("RU-KARIZMA") is session

    def test_create_session_entity_not_found_returns_none(self):
        """Entity name not in entities -> create_session returns None."""
        entities = {"OTHER": {"name": "OTHER", "session": None}}
        manager = EntitySessionManager(entities)
        session = manager.create_session("RU-KARIZMA")
        assert session is None
        assert entities["OTHER"]["session"] is None

    def test_create_session_same_structure_as_lmam_json(self):
        """Use same structure as lmam.data.agency.json so load -> setter -> session_start_all would work."""
        # Mimic loaded.get('agencies', {}) from JSON
        agencies = {
            "RU-KARIZMA": {
                "company_id": 940,
                "contract": "EEU_CONT",
                "name": "RU-KARIZMA",
                "oauth_token_pl": {"client_id": "x", "username": "KARIZMA1219"},
                "session": None,
            }
        }
        manager = EntitySessionManager(agencies)
        session = manager.create_session("RU-KARIZMA")
        assert session is not None
        assert agencies["RU-KARIZMA"]["session"] is session
