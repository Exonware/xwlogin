#!/usr/bin/env python3
"""
SCIM 2.0 PATCH operation helpers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class ScimPatchOperation:
    op: str
    path: str | None = None
    value: Any = None

    def normalized_op(self) -> str:
        return self.op.strip().lower()


def _validate_patch_path(path: str) -> None:
    if not path.strip():
        raise ValueError("SCIM patch path cannot be empty")
    if "[" in path or "]" in path:
        raise ValueError("SCIM patch array path selectors are not supported")


def _set_path(data: dict[str, Any], path: str, value: Any) -> None:
    current = data
    parts = path.split(".")
    for part in parts[:-1]:
        next_value = current.get(part)
        if not isinstance(next_value, dict):
            next_value = {}
            current[part] = next_value
        current = next_value
    current[parts[-1]] = value


def _remove_path(data: dict[str, Any], path: str) -> None:
    current = data
    parts = path.split(".")
    for part in parts[:-1]:
        next_value = current.get(part)
        if not isinstance(next_value, dict):
            return
        current = next_value
    current.pop(parts[-1], None)


def apply_scim_patch(resource: dict[str, Any], operations: list[ScimPatchOperation]) -> dict[str, Any]:
    """
    Apply SCIM PATCH operations to a resource document.
    Supports add/replace/remove with dotted-path access.
    """
    if not operations:
        raise ValueError("SCIM patch requires at least one operation")

    patched = dict(resource)
    for operation in operations:
        op = operation.normalized_op()
        if op not in {"add", "replace", "remove"}:
            raise ValueError(f"Unsupported SCIM patch operation: {operation.op}")
        if operation.path is not None and not str(operation.path).strip():
            raise ValueError("SCIM patch path cannot be empty")
        if operation.path is not None:
            _validate_patch_path(operation.path)
        if op == "remove":
            if operation.path is None:
                raise ValueError("SCIM remove operation requires a path")
            _remove_path(patched, operation.path)
            continue

        if operation.path is None:
            if not isinstance(operation.value, dict):
                raise ValueError("SCIM patch operation without path requires object value")
            patched.update(operation.value)
            continue

        if op == "replace" and operation.value is None:
            raise ValueError("SCIM replace operation requires a value")
        _set_path(patched, operation.path, operation.value)
    return patched


def enforce_scim_if_match(if_match_header: str | None, current_etag: str | None) -> None:
    """Validate SCIM If-Match precondition according to weak service semantics."""
    if if_match_header is None or not if_match_header.strip():
        return
    if current_etag is None:
        raise ValueError("If-Match precondition failed")
    if_match = if_match_header.strip()
    if if_match != "*" and if_match != current_etag:
        raise ValueError("If-Match precondition failed")

