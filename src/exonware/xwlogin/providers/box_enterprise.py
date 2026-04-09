#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/box_enterprise.py
Box Enterprise OAuth Provider
Same OAuth 2.0 endpoints as consumer Box; use enterprise app scopes (e.g. root_readwrite).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ProviderType
from exonware.xwsystem import get_logger
from .box import BoxProvider
logger = get_logger(__name__)


class BoxEnterpriseProvider(BoxProvider):
    """Box OAuth 2.0 for enterprise apps (shared endpoints; enterprise features via app scopes)."""

    @property
    def provider_name(self) -> str:
        return "box_enterprise"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.BOX_ENTERPRISE
