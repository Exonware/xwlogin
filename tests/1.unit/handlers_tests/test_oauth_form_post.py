#!/usr/bin/env python3
"""Unit tests for OIDC form_post HTML helper (xwlogin.handlers.oauth_form_post)."""

from __future__ import annotations

import pytest

from exonware.xwauth.identity.handlers.oauth_form_post import render_oidc_form_post_html


@pytest.mark.xwlogin_unit
def test_render_oidc_form_post_html_escapes_uri_and_fields() -> None:
    html_doc = render_oidc_form_post_html(
        'https://rp.example/cb?x=1&y=<">',
        {"code": "abc&def", "state": '"><script>'},
    )
    assert 'action="https://rp.example/cb?x=1&amp;y=&lt;&quot;&gt;"' in html_doc
    assert 'name="code"' in html_doc
    assert "abc&amp;def" in html_doc
    assert "&quot;&gt;&lt;script&gt;" in html_doc
    assert "<script>" not in html_doc
    assert 'method="post"' in html_doc
    assert "document.forms[0].submit()" in html_doc


@pytest.mark.xwlogin_unit
def test_render_oidc_form_post_html_empty_fields() -> None:
    html_doc = render_oidc_form_post_html("https://rp.example/", {})
    assert '<form method="post" action="https://rp.example/"' in html_doc
    assert 'type="hidden"' not in html_doc
