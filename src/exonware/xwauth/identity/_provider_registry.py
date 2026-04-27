#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/providers/registry.py
Provider Registry
Provider registry using xwsystem registry patterns.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

import re
from exonware.xwsystem import get_logger
from exonware.xwsystem.patterns.registry import GenericRegistry
from exonware.xwauth.identity.defs import ProviderType
from exonware.xwauth.identity.errors import XWProviderError, XWProviderNotFoundError
from exonware.xwauth.identity.contracts import IProvider
logger = get_logger(__name__)


class ProviderRegistry:
    """
    Provider registry for managing OAuth providers.
    Uses xwsystem GenericRegistry pattern for provider registration.
    """

    def __init__(self):
        """Initialize provider registry."""
        self._registry = GenericRegistry[IProvider]()
        self._name_pattern = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
        logger.debug("ProviderRegistry initialized")

    def register(self, provider: IProvider) -> None:
        """
        Register provider.
        Args:
            provider: Provider instance
        """
        provider_name = str(provider.provider_name or "").strip()
        if not provider_name:
            raise XWProviderError(
                "Provider name is required",
                error_code="invalid_provider_name",
            )
        if not self._name_pattern.match(provider_name):
            raise XWProviderError(
                f"Invalid provider name: {provider_name}",
                error_code="invalid_provider_name",
                suggestions=["Use lowercase letters, numbers, '_' or '-', length 2-64"],
            )
        if not hasattr(provider, "exchange_code_for_token") or not hasattr(provider, "get_user_info"):
            raise XWProviderError(
                "Provider does not satisfy OAuth provider contract",
                error_code="invalid_provider_contract",
            )
        self._registry.register(provider_name, provider)
        logger.debug(f"Registered provider: {provider_name}")

    def get(self, provider_name: str) -> IProvider:
        """
        Get provider by name.
        Args:
            provider_name: Provider name
        Returns:
            Provider instance
        Raises:
            XWProviderNotFoundError: If provider not found
        """
        provider = self._registry.get(provider_name)
        if provider is None:
            raise XWProviderNotFoundError(
                f"Provider not found: {provider_name}",
                error_code="provider_not_found",
                suggestions=[f"Register provider '{provider_name}' before use"]
            )
        return provider

    def list_providers(self) -> list[str]:
        """
        List all registered provider names.
        Returns:
            List of provider names
        """
        return self._registry.list_names()

    def has(self, provider_name: str) -> bool:
        """
        Check if provider is registered.
        Args:
            provider_name: Provider name
        Returns:
            True if registered, False otherwise
        """
        return self._registry.exists(provider_name)
