#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/base.py
XWAuth Abstract Base Classes
This module defines abstract base classes (A-prefix) that extend interfaces from contracts.py.
Following GUIDE_DEV.md: All abstract classes start with 'A' and extend 'I' interfaces.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional
from exonware.xwsystem import get_logger
from .contracts import (
    IProvider,
    ITokenManager,
    ISessionManager,
    IAuthenticator,
    IAuthorizer,
    IConfig,
)
from .errors import XWAuthError

if TYPE_CHECKING:
    from .storage.interface import IStorageProvider  # noqa: F401

logger = get_logger(__name__)
# ==============================================================================
# BASE AUTH CLASS
# ==============================================================================


class ABaseAuth(ABC):
    """
    Abstract base class for authentication implementations.
    Provides common functionality for all authentication implementations.
    """

    def __init__(self, storage: Optional[IStorageProvider] = None):
        """
        Initialize base auth.
        Args:
            storage: Optional storage provider
        """
        self._storage = storage
        logger.debug("ABaseAuth initialized")
# ==============================================================================
# PROVIDER BASE CLASSES
# ==============================================================================


class ABaseProvider(IProvider, ABC):
    """
    Abstract base class for OAuth providers.
    Extends IProvider interface. Provides common functionality
    for all provider implementations.
    """

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize provider.
        Args:
            client_id: OAuth client ID
            client_secret: OAuth client secret
            **kwargs: Provider-specific configuration
        """
        self._client_id = client_id
        self._client_secret = client_secret
        self._config = kwargs
        logger.debug(f"ABaseProvider initialized: {self.provider_name}")
    @property
    @abstractmethod

    def provider_name(self) -> str:
        """Get provider name."""
        pass
    @property
    @abstractmethod

    def provider_type(self) -> str:
        """Get provider type."""
        pass
# ==============================================================================
# TOKEN MANAGER BASE CLASSES
# ==============================================================================


class ABaseTokenManager(ITokenManager, ABC):
    """
    Abstract base class for token managers.
    Extends ITokenManager interface. Provides common functionality
    for all token manager implementations.
    """

    def __init__(self, storage: Optional[IStorageProvider] = None, **config):
        """
        Initialize token manager.
        Args:
            storage: Optional storage provider for token persistence
            **config: Token manager configuration
        """
        self._storage = storage
        self._config = config
        logger.debug("ABaseTokenManager initialized")
# ==============================================================================
# SESSION MANAGER BASE CLASSES
# ==============================================================================


class ABaseSessionManager(ISessionManager, ABC):
    """
    Abstract base class for session managers.
    Extends ISessionManager interface. Provides common functionality
    for all session manager implementations.
    """

    def __init__(self, storage: Optional[IStorageProvider] = None, **config):
        """
        Initialize session manager.
        Args:
            storage: Storage provider for session persistence
            **config: Session manager configuration
        """
        self._storage = storage
        self._config = config
        logger.debug("ABaseSessionManager initialized")
# ==============================================================================
# AUTHENTICATOR BASE CLASSES
# ==============================================================================


class ABaseAuthenticator(IAuthenticator, ABC):
    """
    Abstract base class for authenticators.
    Extends IAuthenticator interface. Provides common functionality
    for all authenticator implementations.
    """

    def __init__(self, storage: Optional[IStorageProvider] = None, **config):
        """
        Initialize authenticator.
        Args:
            storage: Storage provider for user data
            **config: Authenticator configuration
        """
        self._storage = storage
        self._config = config
        logger.debug("ABaseAuthenticator initialized")
# ==============================================================================
# AUTHORIZER BASE CLASSES
# ==============================================================================


class ABaseAuthorizer(IAuthorizer, ABC):
    """
    Abstract base class for authorizers.
    Extends IAuthorizer interface. Provides common functionality
    for all authorizer implementations.
    """

    def __init__(self, storage: Optional[IStorageProvider] = None, **config):
        """
        Initialize authorizer.
        Args:
            storage: Storage provider for roles/permissions
            **config: Authorizer configuration
        """
        self._storage = storage
        self._config = config
        logger.debug("ABaseAuthorizer initialized")
# ==============================================================================
# CONFIGURATION BASE CLASSES
# ==============================================================================


class ABaseConfig(IConfig, ABC):
    """
    Abstract base class for configuration.
    Extends IConfig interface. Provides common functionality
    for all configuration implementations.
    """

    def __init__(self, **defaults):
        """
        Initialize configuration.
        Args:
            **defaults: Default configuration values
        """
        self._config: dict[str, Any] = defaults.copy()
        logger.debug("ABaseConfig initialized")

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        self._config[key] = value

    def has(self, key: str) -> bool:
        """Check if configuration key exists."""
        return key in self._config
