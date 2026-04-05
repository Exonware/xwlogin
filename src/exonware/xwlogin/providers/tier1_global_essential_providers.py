#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/tier1_global_essential_providers.py
Tier-1 globally essential IdPs: thin registry aliases, Microsoft SKUs, Meta branding,
and Apple ecosystem entries that are not browser OAuth2 code flows.

Most names in the "Global 20" already have first-class modules (Google, Apple SIWA,
Microsoft, GitHub, Slack, etc.). This file fills naming/segmentation gaps only.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 08-Apr-2026
"""

from __future__ import annotations
from exonware.xwlogin.provider_connector import ProviderType
from .enterprise_tier2_oidc import AzureAdB2CPolicyProvider
from .facebook import FacebookProvider
from .microsoft import MicrosoftProvider
from .tier2_enterprise_iam_stubs import _EnterpriseIamStub
from .twitter import TwitterProvider


class Microsoft365Provider(MicrosoftProvider):
    """Microsoft 365 / personal Microsoft account — same v2.0 endpoints as :class:`MicrosoftProvider`; distinct registry key."""

    @property
    def provider_name(self) -> str:
        return "microsoft_365"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.MICROSOFT_365


class XProvider(TwitterProvider):
    """X (Twitter API v2 OAuth2) — same endpoints as :class:`TwitterProvider`; ``provider_name`` \"x\" for UI/analytics."""

    @property
    def provider_name(self) -> str:
        return "x"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.TWITTER


class MetaOAuthProvider(FacebookProvider):
    """Meta (Facebook Login) — same Graph OAuth as :class:`FacebookProvider`; ``provider_type`` is :attr:`ProviderType.META`."""

    @property
    def provider_name(self) -> str:
        return "meta"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.META


class MicrosoftEntraExternalIdProvider(AzureAdB2CPolicyProvider):
    """Microsoft Entra External ID — customer identity; same B2C-style URLs as :class:`AzureAdB2CPolicyProvider`."""

    @property
    def provider_name(self) -> str:
        return "microsoft_entra_external_id"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.MICROSOFT_ENTRA_EXTERNAL_ID


class AppleBusinessManagerStub(_EnterpriseIamStub):
    """Apple Business Manager / Apple School Manager — device and app licensing; not a generic OAuth2 authorize URL for apps."""

    _hint = "Use Apple Business Manager APIs and MDM; workforce SSO often uses Sign in with Apple, SAML, or Federated Authentication."

    @property
    def provider_name(self) -> str:
        return "apple_business_manager"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.APPLE_BUSINESS_MANAGER


class AppleIcloudWebStub(_EnterpriseIamStub):
    """Apple Account / iCloud web sign-in — Apple ID flows; web and native use Apple ID or Sign in with Apple, not a separate public OAuth host."""

    _hint = "For third-party apps use :class:`~exonware.xwlogin.providers.apple.AppleProvider` (Sign in with Apple) or Apple ID web flows per Apple docs."

    @property
    def provider_name(self) -> str:
        return "apple_icloud_web"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.APPLE_ICLOUD_WEB


class AppleGameCenterStub(_EnterpriseIamStub):
    """Apple Game Center — GameKit multiplayer identity; native SDK, not a browser OAuth2 authorization code flow."""

    _hint = "Use GameKit / GKLocalPlayer on Apple platforms; no standard OAuth2 authorize URL for backend code exchange."

    @property
    def provider_name(self) -> str:
        return "apple_game_center"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.APPLE_GAME_CENTER
