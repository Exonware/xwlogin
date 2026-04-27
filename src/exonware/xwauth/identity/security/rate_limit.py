#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/security/rate_limit.py
Rate Limiting
Rate limiting implementation for API protection.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Optional
from datetime import datetime, timedelta
from collections import defaultdict
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.errors import XWAuthError
logger = get_logger(__name__)


class RateLimiter:
    """
    Rate limiter implementation.
    Simple in-memory rate limiter (can be extended with Redis for distributed systems).
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000
    ):
        """
        Initialize rate limiter.
        Args:
            requests_per_minute: Maximum requests per minute
            requests_per_hour: Maximum requests per hour
        """
        self._requests_per_minute = requests_per_minute
        self._requests_per_hour = requests_per_hour
        self._minute_requests: dict[str, list[datetime]] = defaultdict(list)
        self._hour_requests: dict[str, list[datetime]] = defaultdict(list)
        logger.debug("RateLimiter initialized")

    def check_rate_limit(self, identifier: str) -> bool:
        """
        Check if identifier is within rate limits.
        Args:
            identifier: Client identifier (IP, user ID, etc.)
        Returns:
            True if within limits, False if rate limited
        """
        now = datetime.now()
        # Clean old entries
        self._cleanup_old_entries(identifier, now)
        # Check minute limit
        minute_count = len(self._minute_requests[identifier])
        if minute_count >= self._requests_per_minute:
            logger.warning(f"Rate limit exceeded (per minute) for: {identifier}")
            return False
        # Check hour limit
        hour_count = len(self._hour_requests[identifier])
        if hour_count >= self._requests_per_hour:
            logger.warning(f"Rate limit exceeded (per hour) for: {identifier}")
            return False
        # Record request
        self._minute_requests[identifier].append(now)
        self._hour_requests[identifier].append(now)
        return True

    def _cleanup_old_entries(self, identifier: str, now: datetime) -> None:
        """Clean up old rate limit entries."""
        # Remove entries older than 1 minute
        cutoff_minute = now - timedelta(minutes=1)
        self._minute_requests[identifier] = [
            ts for ts in self._minute_requests[identifier]
            if ts > cutoff_minute
        ]
        # Remove entries older than 1 hour
        cutoff_hour = now - timedelta(hours=1)
        self._hour_requests[identifier] = [
            ts for ts in self._hour_requests[identifier]
            if ts > cutoff_hour
        ]
