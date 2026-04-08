#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/youtube.py
YouTube OAuth Provider
Uses the same Google OAuth endpoints; request YouTube Data API scopes (e.g.
https://www.googleapis.com/auth/youtube.readonly) when calling get_authorization_url.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ProviderType
from exonware.xwsystem import get_logger
from .google import GoogleProvider
logger = get_logger(__name__)


class YouTubeProvider(GoogleProvider):
    """Google OAuth 2.0 with registry id `youtube` for YouTube-specific scope bundles."""

    @property
    def provider_name(self) -> str:
        return "youtube"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.YOUTUBE
