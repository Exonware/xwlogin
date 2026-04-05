# exonware/xwlogin/form_post_connector.py
"""OIDC/OAuth2 ``response_mode=form_post`` HTML (package-level façade).

**xwauth** ``handlers.mixins.auth_core`` imports this module so it does not need the deep path
``handlers.oauth_form_post``. Implementation lives in ``handlers.oauth_form_post`` (GUIDE_32).
"""

from __future__ import annotations

from exonware.xwlogin.handlers.oauth_form_post import render_oidc_form_post_html

__all__ = ["render_oidc_form_post_html"]
