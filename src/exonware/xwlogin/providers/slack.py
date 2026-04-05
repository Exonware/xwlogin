#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/slack.py
Slack OAuth Provider
Slack OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class SlackProvider(ABaseProvider):
    """Slack OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://slack.com/oauth/v2/authorize"
    TOKEN_URL = "https://slack.com/api/oauth.v2.access"
    USERINFO_URL = "https://slack.com/api/users.identity"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Slack provider.
        Args:
            client_id: Slack OAuth client ID
            client_secret: Slack OAuth client secret
            **kwargs: Additional configuration
        """
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=self.USERINFO_URL,
            **kwargs
        )
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "slack"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.SLACK

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """
        Exchange authorization code for access token.
        Slack OAuth v2 returns a different response structure.
        Args:
            code: Authorization code
            redirect_uri: Redirect URI
        Returns:
            Token response dictionary (normalized to standard OAuth format)
        """
        # Call parent to get Slack's response
        slack_response = await super().exchange_code_for_token(code, redirect_uri)
        # Slack returns: { ok: true, access_token: "...", authed_user: {...}, team: {...} }
        # Normalize to standard OAuth format
        if not slack_response.get("ok"):
            raise Exception(f"Slack token exchange failed: {slack_response.get('error', 'Unknown error')}")
        # Extract access token (Slack provides it at top level and in authed_user)
        access_token = slack_response.get("access_token") or slack_response.get("authed_user", {}).get("access_token")
        return {
            "access_token": access_token,
            "token_type": slack_response.get("token_type", "bearer"),
            "scope": slack_response.get("scope", ""),
            # Store full response for get_user_info
            "_slack_response": slack_response,
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Slack.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # Slack users.identity endpoint returns: { ok: true, user: {...}, team: {...} }
        user_info = await super().get_user_info(access_token)
        # Slack API returns nested structure: { ok: true, user: {...}, team: {...} }
        if not user_info.get("ok"):
            raise Exception(f"Slack API error: {user_info.get('error', 'Unknown error')}")
        slack_user = user_info.get("user", {})
        team = user_info.get("team", {})
        # Normalize Slack user info format
        return {
            'id': str(slack_user.get('id')),
            'email': slack_user.get('email'),
            'name': slack_user.get('name'),
            'real_name': slack_user.get('real_name'),
            'display_name': slack_user.get('real_name') or slack_user.get('name'),
            'avatar_url': slack_user.get('image_512') or slack_user.get('image_192'),
            'team_id': team.get('id'),
            'team_name': team.get('name'),
        }
