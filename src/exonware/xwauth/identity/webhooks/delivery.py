#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/webhooks/delivery.py
Webhook Delivery
Handles webhook HTTP delivery with retry logic and HMAC signing.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any
from exonware.xwsystem.io.serialization.formats.text import json as xw_json
import hmac
import hashlib
import base64
from datetime import datetime
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
logger = get_logger(__name__)
# Try to import HTTP client
try:
    from exonware.xwsystem.http import AsyncHttpClient
    HTTP_CLIENT_AVAILABLE = True
except ImportError:
    HTTP_CLIENT_AVAILABLE = False
    AsyncHttpClient = None


class WebhookDelivery:
    """
    Webhook delivery handler.
    Handles HTTP delivery of webhook events with retry logic and HMAC signing.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize webhook delivery.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._http_client = None
        logger.debug("WebhookDelivery initialized")

    async def deliver(
        self,
        webhook: dict[str, Any],
        event_payload: dict[str, Any],
        max_retries: int = 3,
    ) -> dict[str, Any]:
        """
        Deliver webhook event to endpoint.
        Args:
            webhook: Webhook configuration
            event_payload: Event payload to deliver
            max_retries: Maximum number of retry attempts
        Returns:
            Delivery result dictionary
        """
        url = webhook.get("url")
        secret = webhook.get("secret")
        if not HTTP_CLIENT_AVAILABLE:
            logger.warning("HTTP client not available, webhook delivery disabled")
            return {
                "success": False,
                "error": "HTTP client not available",
            }
        # Initialize HTTP client if needed
        if self._http_client is None:
            self._http_client = AsyncHttpClient()
        # Serialize payload
        payload_json = xw_json.dumps(event_payload)
        # Generate HMAC signature
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "xwauth-webhook/1.0",
        }
        if secret:
            signature = self._generate_signature(payload_json, secret)
            headers["X-Webhook-Signature"] = signature
        # Deliver with retry logic
        last_error = None
        for attempt in range(max_retries):
            try:
                response = await self._http_client.post(
                    url,
                    data=payload_json,
                    headers=headers,
                    timeout=10.0,
                )
                if 200 <= response.status_code < 300:
                    logger.debug(f"Webhook delivered successfully: {url} (attempt {attempt + 1})")
                    return {
                        "success": True,
                        "status_code": response.status_code,
                        "attempt": attempt + 1,
                    }
                else:
                    last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                    logger.warning(f"Webhook delivery failed: {url} - {last_error} (attempt {attempt + 1})")
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Webhook delivery error: {url} - {last_error} (attempt {attempt + 1})")
            # Exponential backoff (wait before retry)
            if attempt < max_retries - 1:
                import asyncio
                wait_time = 2 ** attempt  # 1s, 2s, 4s, etc.
                await asyncio.sleep(wait_time)
        logger.error(f"Webhook delivery failed after {max_retries} attempts: {url} - {last_error}")
        return {
            "success": False,
            "status_code": None,
            "error": last_error,
            "attempts": max_retries,
        }

    def _generate_signature(self, payload: str, secret: str) -> str:
        """
        Generate HMAC signature for webhook payload.
        Args:
            payload: JSON payload string
            secret: Webhook secret
        Returns:
            Base64-encoded HMAC signature
        """
        signature = hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).digest()
        return base64.b64encode(signature).decode('ascii')
