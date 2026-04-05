# exonware/xwlogin/tokens_connector.py
"""OIDC ID-token signing helpers from the connector (``xwauth.tokens.oidc_id_token_signing``).

Reference AS hosts (e.g. xwauth-api) should import from here instead of ``xwauth.tokens.*`` so
token wiring stays on the **xwlogin** façade (GUIDE_32).
"""

from __future__ import annotations

from exonware.xwauth.tokens.oidc_id_token_signing import (
    infer_id_token_signing_algorithms_for_discovery,
)

__all__ = ["infer_id_token_signing_algorithms_for_discovery"]
