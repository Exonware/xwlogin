# exonware/xwlogin/handlers/oauth_form_post.py
"""HTML document for OIDC/OAuth2 ``response_mode=form_post`` (auto-submit POST to client ``redirect_uri``).

Implementation module for OIDC ``form_post`` HTML. **Public façade:** ``exonware.xwlogin.form_post_connector``
(GUIDE_32). **xwauth** ``handlers.mixins.auth_core`` imports that façade when ``exonware-xwlogin``
is importable, with a small inline fallback for connector-only installs.
"""

from __future__ import annotations

import html
from typing import Any, Mapping

__all__ = ["render_oidc_form_post_html"]


def render_oidc_form_post_html(
    redirect_uri: str, form_fields: Mapping[str, Any]
) -> str:
    """Return a minimal HTML page that POSTs hidden fields to ``redirect_uri`` on load."""
    action = html.escape(str(redirect_uri))
    inputs = "".join(
        f'<input type="hidden" name="{html.escape(str(k))}" value="{html.escape(str(v))}"/>'
        for k, v in form_fields.items()
    )
    return (
        "<!DOCTYPE html><html><body onload=\"document.forms[0].submit()\">"
        f'<form method="post" action="{action}">{inputs}</form>'
        "</body></html>"
    )
