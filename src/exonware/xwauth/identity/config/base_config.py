#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/config/base_config.py
Base Configuration (Fallback)
Fallback base configuration class if xwsystem is not available.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from abc import ABC, abstractmethod
from typing import Any, Optional


class AConfigBase(ABC):
    """Abstract base class for configuration management (fallback)."""

    def __init__(self, config_type: str = "dict"):
        """
        Initialize configuration base.
        Args:
            config_type: Configuration type
        """
        self.config_type = config_type
        self._config: dict[str, Any] = {}
        self._defaults: dict[str, Any] = {}
    @abstractmethod

    def load(self, source: str | dict[str, Any]) -> None:
        """Load configuration from source."""
        pass
    @abstractmethod

    def save(self, destination: str) -> None:
        """Save configuration to destination."""
        pass
    @abstractmethod

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        pass
    @abstractmethod

    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        pass
    @abstractmethod

    def delete(self, key: str) -> bool:
        """Delete configuration key."""
        pass
    @abstractmethod

    def has(self, key: str) -> bool:
        """Check if configuration key exists."""
        pass
    @abstractmethod

    def keys(self) -> list[str]:
        """Get all configuration keys."""
        pass
    @abstractmethod

    def values(self) -> list[Any]:
        """Get all configuration values."""
        pass
    @abstractmethod

    def items(self) -> list[tuple[str, Any]]:
        """Get all configuration items."""
        pass
