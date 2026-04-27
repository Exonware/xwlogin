#!/usr/bin/env python3
"""
SCIM 2.0 foundations for xwauth.
"""

from .filtering import ScimFilterTerm, match_scim_filter, parse_scim_term
from .models import (
    SCIM_GROUP_SCHEMA,
    SCIM_LIST_RESPONSE_SCHEMA,
    SCIM_PATCH_OP_SCHEMA,
    SCIM_USER_SCHEMA,
    ScimMeta,
    ScimResource,
    compute_etag,
)
from .patch import ScimPatchOperation, apply_scim_patch
from .service import ScimService

__all__ = [
    "SCIM_GROUP_SCHEMA",
    "SCIM_LIST_RESPONSE_SCHEMA",
    "SCIM_PATCH_OP_SCHEMA",
    "SCIM_USER_SCHEMA",
    "ScimFilterTerm",
    "ScimMeta",
    "ScimPatchOperation",
    "ScimResource",
    "ScimService",
    "apply_scim_patch",
    "compute_etag",
    "match_scim_filter",
    "parse_scim_term",
]

