#!/usr/bin/env python3
"""
Minimal SCIM 2.0 service foundation for xwauth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .filtering import match_scim_filter, validate_scim_filter
from .models import (
    SCIM_LIST_RESPONSE_SCHEMA,
    ScimMeta,
    ScimResource,
    compute_etag,
    utc_now_iso,
)
from .patch import ScimPatchOperation, apply_scim_patch


@dataclass(slots=True)
class ScimService:
    """In-memory SCIM service behavior for Users/Groups semantics and tests."""

    resource_type: str
    default_schema: str
    resources: dict[str, ScimResource] = field(default_factory=dict)

    def create(self, resource_id: str, attributes: dict[str, Any], external_id: str | None = None) -> ScimResource:
        if resource_id in self.resources:
            raise ValueError(f"SCIM resource already exists: {resource_id}")
        resource = ScimResource(
            id=resource_id,
            schemas=[self.default_schema],
            attributes=dict(attributes),
            external_id=external_id,
            meta=ScimMeta(resource_type=self.resource_type),
        )
        payload = resource.to_dict()
        resource.meta.version = compute_etag(payload)
        self.resources[resource_id] = resource
        return resource

    def get(self, resource_id: str) -> ScimResource | None:
        return self.resources.get(resource_id)

    def delete(self, resource_id: str) -> bool:
        return self.resources.pop(resource_id, None) is not None

    def patch(self, resource_id: str, operations: list[ScimPatchOperation]) -> ScimResource:
        resource = self.resources.get(resource_id)
        if resource is None:
            raise KeyError(f"SCIM resource not found: {resource_id}")

        patched_attributes = apply_scim_patch(dict(resource.attributes), operations)
        resource.attributes = patched_attributes
        if resource.meta is None:
            resource.meta = ScimMeta(resource_type=self.resource_type)
        resource.meta.last_modified = utc_now_iso()
        resource.meta.version = compute_etag(resource.to_dict())
        return resource

    def list_response(
        self,
        filter_expression: str | None = None,
        start_index: int = 1,
        count: int = 100,
    ) -> dict[str, Any]:
        if start_index < 1:
            raise ValueError("SCIM startIndex must be >= 1")
        if count < 0:
            raise ValueError("SCIM count must be >= 0")
        validate_scim_filter(filter_expression)

        all_resources = [resource.to_dict() for resource in self.resources.values()]
        filtered = [item for item in all_resources if match_scim_filter(item, filter_expression)]

        start_offset = start_index - 1
        end_offset = start_offset + count
        page = filtered[start_offset:end_offset]

        return {
            "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
            "totalResults": len(filtered),
            "startIndex": start_index,
            "itemsPerPage": len(page),
            "Resources": page,
        }

