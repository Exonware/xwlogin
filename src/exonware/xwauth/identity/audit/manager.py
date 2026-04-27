#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/audit/manager.py
Audit Log Manager
Manages audit log creation and querying for security events.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any
from datetime import datetime
import uuid
from copy import deepcopy
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.storage.mock import MockAuditLog
logger = get_logger(__name__)


class AuditLogManager:
    """
    Audit log manager.
    Handles audit log creation and querying for security events.
    """
    # Supported event types
    EVENT_TYPES = [
        "login.succeeded",
        "login.failed",
        "logout",
        "password.changed",
        "password.reset",
        "mfa.enrolled",
        "mfa.removed",
        "mfa.verified",
        "token.issued",
        "token.revoked",
        "authz.decision",
        "user.created",
        "user.deleted",
        "user.updated",
        "role.assigned",
        "role.removed",
        "org.created",
        "org.deleted",
        "org.updated",
        "admin.action",
        "mfa.totp.setup.completed",
        "mfa.totp.verify.completed",
        "mfa.totp.verify.failed",
        "webauthn.register.completed",
        "webauthn.register.failed",
        "webauthn.login.completed",
        "webauthn.login.failed",
    ]

    def __init__(self, auth: ABaseAuth):
        """
        Initialize audit log manager.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._storage = auth.storage
        logger.debug("AuditLogManager initialized")

    async def log_event(
        self,
        event_type: str,
        user_id: str | None = None,
        resource: str | None = None,
        attributes: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        *,
        tenant_id: str | None = None,
        org_id: str | None = None,
        project_id: str | None = None,
        correlation_id: str | None = None,
    ) -> None:
        """
        Log an audit event.
        Args:
            event_type: Event type (e.g., "login.succeeded")
            user_id: User identifier (None for system actions)
            resource: Resource affected (optional)
            attributes: Additional event attributes
            context: Request context (IP, user agent, etc.)
            tenant_id: Deployment / billing tenant slice (optional)
            org_id: B2B organization id (optional)
            project_id: Application / project id (optional)
            correlation_id: Distributed trace / request correlation (optional)
        """
        safe_attributes = deepcopy(attributes or {})
        safe_context = deepcopy(context or {})
        if tenant_id is not None and str(tenant_id).strip():
            safe_context["tenant_id"] = str(tenant_id).strip()
        if org_id is not None and str(org_id).strip():
            safe_context["org_id"] = str(org_id).strip()
        if project_id is not None and str(project_id).strip():
            safe_context["project_id"] = str(project_id).strip()
        if correlation_id is not None and str(correlation_id).strip():
            safe_context["correlation_id"] = str(correlation_id).strip()
        safe_event_type = str(event_type or "").strip()
        safe_user_id = str(user_id) if user_id is not None else None
        safe_resource = str(resource) if resource is not None else None
        audit_log = MockAuditLog(
            id=str(uuid.uuid4()),
            user_id=safe_user_id,
            action=safe_event_type,
            timestamp=datetime.now(),
            resource=safe_resource,
            attributes=safe_attributes,
            context=safe_context,
        )
        await self._storage.save_audit_log(audit_log)
        logger.debug(f"Logged audit event: {safe_event_type} for user: {safe_user_id}")

    async def query_logs(
        self,
        user_id: str | None = None,
        event_type: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """
        Query audit logs with filters.
        Args:
            user_id: Filter by user ID
            event_type: Filter by event type
            start_date: Filter by start date
            end_date: Filter by end date
            limit: Maximum number of results
            offset: Pagination offset
        Returns:
            Dictionary with logs and pagination info
        """
        # Build filters
        filters = {}
        if user_id:
            filters["user_id"] = user_id
        if event_type:
            filters["action"] = event_type
        # Get logs from storage
        all_logs = await self._storage.get_audit_logs(filters if filters else None)
        # Apply date filters
        if start_date or end_date:
            filtered_logs = []
            for log in all_logs:
                log_timestamp = log.timestamp if hasattr(log.timestamp, 'timestamp') else log.timestamp
                if isinstance(log_timestamp, datetime):
                    if start_date and log_timestamp < start_date:
                        continue
                    if end_date and log_timestamp > end_date:
                        continue
                    filtered_logs.append(log)
                else:
                    # Try to parse if it's a string
                    try:
                        if isinstance(log_timestamp, str):
                            log_dt = datetime.fromisoformat(log_timestamp.replace('Z', '+00:00'))
                        else:
                            log_dt = datetime.fromtimestamp(log_timestamp)
                        if start_date and log_dt < start_date:
                            continue
                        if end_date and log_dt > end_date:
                            continue
                        filtered_logs.append(log)
                    except Exception:
                        # Include if we can't parse
                        filtered_logs.append(log)
            all_logs = filtered_logs
        # Sort by timestamp (newest first)
        try:
            all_logs.sort(
                key=lambda log: log.timestamp if isinstance(log.timestamp, datetime) else datetime.fromisoformat(str(log.timestamp).replace('Z', '+00:00')),
                reverse=True
            )
        except Exception:
            # If sorting fails, keep original order
            pass
        # Apply pagination
        total = len(all_logs)
        paginated_logs = all_logs[offset:offset + limit]
        # Convert to dictionaries
        logs = []
        for log in paginated_logs:
            log_dict = {
                "id": log.id,
                "user_id": log.user_id,
                "event_type": log.action,
                "timestamp": log.timestamp.isoformat() if isinstance(log.timestamp, datetime) else str(log.timestamp),
                "resource": log.resource if hasattr(log, 'resource') else None,
            }
            # Add attributes
            if hasattr(log, 'attributes') and log.attributes:
                log_dict["attributes"] = log.attributes
            # Add context
            if hasattr(log, 'context') and log.context:
                log_dict["context"] = log.context
            logs.append(log_dict)
        return {
            "logs": logs,
            "total": total,
            "limit": limit,
            "offset": offset,
        }
