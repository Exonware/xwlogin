#!/usr/bin/env python3
"""
#exonware/xwauth/tests/1.unit/clients_tests/conftest.py
OAuth Client Tests Fixtures
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.0
Generation Date: 25-Jan-2026
"""

from __future__ import annotations
import pytest
@pytest.fixture

def oauth2_client_config():
    """OAuth 2.0 client configuration."""
    return {
        "client_id": "test_client_id",
        "client_secret": "test_client_secret",
        "redirect_uri": "https://client.example.com/callback",
        "authorization_url": "https://auth.example.com/oauth/authorize",
        "token_url": "https://auth.example.com/oauth/token",
    }
