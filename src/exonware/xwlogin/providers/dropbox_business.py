#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/dropbox_business.py
Dropbox Business OAuth Provider
Uses the same authorize/token URLs as consumer Dropbox; team features rely on scopes
configured on the Dropbox Business app (e.g. team_data.member, team_info.read).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ProviderType
from typing import Any
from exonware.xwsystem import get_logger
from .dropbox import DropboxProvider
logger = get_logger(__name__)


class DropboxBusinessProvider(DropboxProvider):
    """Dropbox Business OAuth 2.0 (team-aware scopes on the same OAuth endpoints)."""

    def _get_authorization_params(self) -> dict[str, Any]:
        params = super()._get_authorization_params()
        params.setdefault("token_access_type", "offline")
        return params

    @property
    def provider_name(self) -> str:
        return "dropbox_business"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.DROPBOX_BUSINESS
