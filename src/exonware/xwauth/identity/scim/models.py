#!/usr/bin/env python3
"""
SCIM 2.0 core models for xwauth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from exonware.xwsystem.io.serialization.formats.text import json as xw_json


SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"


def utc_now_iso() -> str:
    """Return UTC timestamp in SCIM-friendly ISO format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def compute_etag(payload: dict[str, Any]) -> str:
    """Compute stable weak ETag for a SCIM payload."""
    canonical = xw_json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = sha256(canonical.encode("utf-8")).hexdigest()
    return f'W/"{digest}"'


@dataclass(slots=True)
class ScimMeta:
    """SCIM resource metadata block."""

    resource_type: str
    created: str = field(default_factory=utc_now_iso)
    last_modified: str = field(default_factory=utc_now_iso)
    version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "resourceType": self.resource_type,
            "created": self.created,
            "lastModified": self.last_modified,
            "version": self.version,
        }


@dataclass(slots=True)
class ScimResource:
    """Normalized SCIM resource model."""

    id: str
    schemas: list[str]
    attributes: dict[str, Any] = field(default_factory=dict)
    external_id: str | None = None
    meta: ScimMeta | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "schemas": list(self.schemas),
            **self.attributes,
        }
        if self.external_id is not None:
            payload["externalId"] = self.external_id
        if self.meta is not None:
            payload["meta"] = self.meta.to_dict()
        return payload

