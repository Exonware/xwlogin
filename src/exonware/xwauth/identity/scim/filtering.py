#!/usr/bin/env python3
"""
SCIM 2.0 filter parsing and evaluation helpers.
Supports a practical subset used in enterprise provisioning flows.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


_TERM_RE = re.compile(
    r'^\s*([A-Za-z0-9_.-]+)\s+(eq|ne|co|sw|ew|pr|gt|ge|lt|le)(?:\s+"((?:[^"\\]|\\.)*)"|\s+([^\s]+))?\s*$'
)
_LOGICAL_SPLIT = re.compile(r"\s+(and|or)\s+", flags=re.IGNORECASE)


@dataclass(slots=True)
class ScimFilterTerm:
    attribute: str
    operator: str
    value: str


def _unescape_quoted(text: str) -> str:
    return text.replace('\\"', '"').replace("\\\\", "\\")


def parse_scim_term(expression: str) -> ScimFilterTerm:
    """Parse a single SCIM filter term."""
    match = _TERM_RE.match(expression)
    if match is None:
        raise ValueError(f"Unsupported SCIM filter expression: {expression}")
    attribute, operator, raw_quoted_value, raw_unquoted_value = match.groups()
    normalized_operator = operator.lower()
    if normalized_operator == "pr":
        return ScimFilterTerm(attribute=attribute, operator=normalized_operator, value="")
    raw_value = raw_quoted_value if raw_quoted_value is not None else raw_unquoted_value
    if raw_value is None:
        raise ValueError(f"SCIM filter operator '{normalized_operator}' requires a value")
    return ScimFilterTerm(attribute=attribute, operator=normalized_operator, value=_unescape_quoted(raw_value))


def _coerce_numeric(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except Exception:
        return None


def get_path_value(data: dict[str, Any], dotted_path: str) -> Any:
    """Read dotted-path value from nested dict payloads."""
    current: Any = data
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _coerce_to_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _evaluate_term(data: dict[str, Any], term: ScimFilterTerm) -> bool:
    raw_source = get_path_value(data, term.attribute)
    source = _coerce_to_text(raw_source)
    target = term.value
    if term.operator == "pr":
        return raw_source is not None and source != ""
    if term.operator == "eq":
        return source == target
    if term.operator == "ne":
        return source != target
    if term.operator == "co":
        return target in source
    if term.operator == "sw":
        return source.startswith(target)
    if term.operator == "ew":
        return source.endswith(target)
    if term.operator in {"gt", "ge", "lt", "le"}:
        source_num = _coerce_numeric(raw_source)
        target_num = _coerce_numeric(target)
        if source_num is not None and target_num is not None:
            if term.operator == "gt":
                return source_num > target_num
            if term.operator == "ge":
                return source_num >= target_num
            if term.operator == "lt":
                return source_num < target_num
            return source_num <= target_num
        # Fallback lexical comparison for non-numeric values.
        if term.operator == "gt":
            return source > target
        if term.operator == "ge":
            return source >= target
        if term.operator == "lt":
            return source < target
        return source <= target
    raise ValueError(f"Unsupported SCIM operator: {term.operator}")


def match_scim_filter(data: dict[str, Any], expression: str | None) -> bool:
    """
    Match SCIM filter against a resource dict.
    Supports top-level `or` and `and` combinations without parenthesis.
    """
    if expression is None or not expression.strip():
        return True

    tokens = _tokenize_scim_filter(expression)
    if not tokens:
        return True

    current_and_result: bool | None = None
    current_or_result = False
    pending_operator = "or"

    for token in tokens:
        normalized = token.lower()
        if normalized in {"and", "or"}:
            pending_operator = normalized
            continue
        term_result = _evaluate_term(data, parse_scim_term(token))
        if current_and_result is None:
            current_and_result = term_result
        elif pending_operator == "and":
            current_and_result = current_and_result and term_result
        elif pending_operator == "or":
            current_or_result = current_or_result or current_and_result
            current_and_result = term_result
        else:
            raise ValueError(f"Unsupported logical operator: {pending_operator}")

    if current_and_result is not None:
        current_or_result = current_or_result or current_and_result
    return current_or_result


def _tokenize_scim_filter(expression: str) -> list[str]:
    if "(" in expression or ")" in expression:
        raise ValueError("SCIM filter parenthesis are not supported in this implementation")
    return [token.strip() for token in _LOGICAL_SPLIT.split(expression.strip()) if token.strip()]


def validate_scim_filter(expression: str | None) -> None:
    """Validate SCIM filter syntax and supported operators without evaluating data."""
    if expression is None or not expression.strip():
        return
    tokens = _tokenize_scim_filter(expression)
    has_term = False
    for token in tokens:
        normalized = token.lower()
        if normalized in {"and", "or"}:
            continue
        parse_scim_term(token)
        has_term = True
    if not has_term:
        raise ValueError("SCIM filter must include at least one expression term")

