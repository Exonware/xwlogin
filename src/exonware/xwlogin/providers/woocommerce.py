#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/woocommerce.py
WooCommerce / WordPress merchant identity Provider
WooCommerce.com and many Woo merchants use WordPress.com OAuth for app identity.
Self-hosted stores use plugins or REST keys; this provider matches WordPress.com OAuth.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ProviderType
from exonware.xwsystem import get_logger
from .wordpress import WordPressProvider
logger = get_logger(__name__)


class WooCommerceProvider(WordPressProvider):
    """WordPress.com OAuth 2.0 scoped for WooCommerce / Automattic integrations."""

    @property
    def provider_name(self) -> str:
        return "woocommerce"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.WOOCOMMERCE
