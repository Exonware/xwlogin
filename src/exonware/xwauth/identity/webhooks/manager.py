#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/webhooks/manager.py
Webhook Manager
Manages webhook registration, storage, and event triggering.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any, Optional
from datetime import datetime
import uuid
import secrets
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.errors import XWAuthError
from .delivery import WebhookDelivery
logger = get_logger(__name__)


class WebhookManager:
    """
    Webhook manager for registration and event triggering.
    Handles webhook registration, storage, and triggering events.
    """
    # Supported webhook events
    EVENTS = [
        "user.created",
        "user.deleted",
        "user.updated",
        "org.created",
        "org.deleted",
        "org.updated",
        "login.failed",
        "login.succeeded",
        "mfa.enrolled",
        "mfa.removed",
        "token.issued",
        "token.revoked",
    ]

    def __init__(self, auth: ABaseAuth):
        """
        Initialize webhook manager.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._storage = auth.storage
        self._delivery = WebhookDelivery(auth)
        logger.debug("WebhookManager initialized")

    async def register_webhook(
        self,
        url: str,
        events: list[str],
        secret: Optional[str] = None,
        active: bool = True,
    ) -> dict[str, Any]:
        """
        Register a new webhook endpoint.
        Args:
            url: Webhook URL endpoint
            events: List of events to subscribe to
            secret: Optional webhook secret for HMAC signature (auto-generated if not provided)
            active: Whether webhook is active
        Returns:
            Webhook registration details
        """
        # Validate URL
        if not url or not url.startswith(('http://', 'https://')):
            raise XWAuthError(
                "Invalid webhook URL. Must be a valid HTTP/HTTPS URL.",
                error_code="invalid_url"
            )
        # Validate events
        invalid_events = [e for e in events if e not in self.EVENTS]
        if invalid_events:
            raise XWAuthError(
                f"Invalid events: {', '.join(invalid_events)}",
                error_code="invalid_events"
            )
        # Generate webhook ID and secret
        webhook_id = str(uuid.uuid4())
        if not secret:
            secret = self._generate_secret()
        # Create webhook data
        webhook_data = {
            "id": webhook_id,
            "url": url,
            "events": events,
            "secret": secret,
            "active": active,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
        }
        # Save webhook
        await self._save_webhook(webhook_id, webhook_data)
        logger.debug(f"Registered webhook: {webhook_id} for URL: {url}")
        return {
            "id": webhook_id,
            "url": url,
            "events": events,
            "active": active,
            "created_at": webhook_data["created_at"],
        }

    async def list_webhooks(self) -> list[dict[str, Any]]:
        """
        List all registered webhooks.
        Returns:
            List of webhook registrations (without secrets)
        """
        webhooks = await self._list_all_webhooks()
        # Remove secrets from response
        result = []
        for webhook in webhooks:
            result.append({
                "id": webhook.get("id"),
                "url": webhook.get("url"),
                "events": webhook.get("events", []),
                "active": webhook.get("active", True),
                "created_at": webhook.get("created_at"),
                "updated_at": webhook.get("updated_at"),
            })
        return result

    async def get_webhook(self, webhook_id: str) -> Optional[dict[str, Any]]:
        """
        Get webhook by ID.
        Args:
            webhook_id: Webhook identifier
        Returns:
            Webhook data (without secret) or None
        """
        webhook = await self._get_webhook(webhook_id)
        if not webhook:
            return None
        # Remove secret from response
        return {
            "id": webhook.get("id"),
            "url": webhook.get("url"),
            "events": webhook.get("events", []),
            "active": webhook.get("active", True),
            "created_at": webhook.get("created_at"),
            "updated_at": webhook.get("updated_at"),
        }

    async def delete_webhook(self, webhook_id: str) -> None:
        """
        Delete a webhook.
        Args:
            webhook_id: Webhook identifier
        """
        webhook = await self._get_webhook(webhook_id)
        if not webhook:
            raise XWAuthError(
                f"Webhook not found: {webhook_id}",
                error_code="webhook_not_found"
            )
        await self._delete_webhook(webhook_id)
        logger.debug(f"Deleted webhook: {webhook_id}")

    async def test_webhook(self, webhook_id: str) -> dict[str, Any]:
        """
        Test webhook delivery.
        Args:
            webhook_id: Webhook identifier
        Returns:
            Test delivery result
        """
        webhook = await self._get_webhook(webhook_id)
        if not webhook:
            raise XWAuthError(
                f"Webhook not found: {webhook_id}",
                error_code="webhook_not_found"
            )
        # Send test event
        test_event = {
            "event": "webhook.test",
            "timestamp": datetime.now().isoformat(),
            "data": {
                "message": "This is a test webhook event",
                "webhook_id": webhook_id,
            }
        }
        result = await self._delivery.deliver(webhook, test_event)
        return {
            "webhook_id": webhook_id,
            "url": webhook.get("url"),
            "delivered": result.get("success", False),
            "status_code": result.get("status_code"),
            "error": result.get("error"),
        }

    async def trigger_event(self, event: str, data: dict[str, Any]) -> None:
        """
        Trigger webhook event for all subscribed webhooks.
        Args:
            event: Event name (e.g., "user.created")
            data: Event data payload
        """
        # Get all active webhooks subscribed to this event
        webhooks = await self._get_webhooks_for_event(event)
        # Deliver to each webhook
        for webhook in webhooks:
            if not webhook.get("active", True):
                continue
            event_payload = {
                "event": event,
                "timestamp": datetime.now().isoformat(),
                "data": data,
            }
            # Deliver asynchronously (fire and forget)
            try:
                await self._delivery.deliver(webhook, event_payload)
            except Exception as e:
                logger.error(f"Failed to deliver webhook {webhook.get('id')}: {e}")

    def _generate_secret(self) -> str:
        """Generate webhook secret for HMAC signing."""
        return secrets.token_urlsafe(32)
    # Storage helper methods

    async def _save_webhook(self, webhook_id: str, webhook_data: dict[str, Any]) -> None:
        """Save webhook to storage."""
        webhook_key = f"webhook:{webhook_id}"
        if hasattr(self._storage, 'write'):
            await self._storage.write(webhook_key, webhook_data)
        else:
            # Fallback to in-memory storage
            if not hasattr(self._storage, '_webhooks'):
                self._storage._webhooks = {}
            self._storage._webhooks[webhook_id] = webhook_data

    async def _get_webhook(self, webhook_id: str) -> Optional[dict[str, Any]]:
        """Get webhook from storage."""
        webhook_key = f"webhook:{webhook_id}"
        if hasattr(self._storage, 'read'):
            return await self._storage.read(webhook_key)
        else:
            # Fallback to in-memory storage
            if hasattr(self._storage, '_webhooks'):
                return self._storage._webhooks.get(webhook_id)
        return None

    async def _list_all_webhooks(self) -> list[dict[str, Any]]:
        """List all webhooks from storage."""
        webhooks = []
        if hasattr(self._storage, 'read'):
            # Would need indexing in real implementation
            pass
        else:
            # Fallback: search in-memory storage
            if hasattr(self._storage, '_webhooks'):
                webhooks = list(self._storage._webhooks.values())
        return webhooks

    async def _get_webhooks_for_event(self, event: str) -> list[dict[str, Any]]:
        """Get all webhooks subscribed to an event."""
        all_webhooks = await self._list_all_webhooks()
        subscribed = []
        for webhook in all_webhooks:
            if event in webhook.get("events", []):
                subscribed.append(webhook)
        return subscribed

    async def _delete_webhook(self, webhook_id: str) -> None:
        """Delete webhook from storage."""
        webhook_key = f"webhook:{webhook_id}"
        if hasattr(self._storage, 'delete'):
            await self._storage.delete(webhook_key)
        else:
            # Fallback to in-memory storage
            if hasattr(self._storage, '_webhooks'):
                self._storage._webhooks.pop(webhook_id, None)
