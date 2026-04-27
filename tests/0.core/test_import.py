"""Smoke-import the canonical xwauth-identity surface.

This file was rewritten when the zero-shims rule landed (see
``~/.claude/projects/.../no_shims_rule.md``). The prior version of this test
module asserted the presence of compat aliases (top-level ``xwlogin`` package,
``test_support`` barrel, ``form_post_connector`` lazy attr, the whole
``*_connector`` facade family, etc.). Those aliases were eliminated, so the
legacy assertions are intentionally gone -- do NOT re-add them.

What we DO assert: every canonical module that real callers import directly
loads cleanly, and the provider-classes lazy ``__getattr__`` still resolves
provider names (Google, GitHub, etc.) on demand from
``exonware.xwauth.connect.providers``.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xwlogin_core


def test_form_post_renderer_is_callable() -> None:
    """Canonical OIDC form-post renderer is reachable at its real module path."""
    from exonware.xwauth.identity.handlers.oauth_form_post import (
        render_oidc_form_post_html,
    )

    html = render_oidc_form_post_html("https://rp.example/cb", {"a": "1"})
    assert "https://rp.example/cb" in html
    assert 'name="a"' in html


def test_canonical_provider_import_from_submodule() -> None:
    """Providers live in ``exonware.xwauth.connect.providers.<submodule>``."""
    from exonware.xwauth.connect.providers.google import GoogleProvider

    assert GoogleProvider.__name__ == "GoogleProvider"


def test_providers_package_lazy_class_resolution() -> None:
    """``from exonware.xwauth.connect.providers import GoogleProvider`` must work.

    The providers package exposes the common base class / registry eagerly and
    resolves class-named attributes lazily via PEP 562 ``__getattr__`` (no
    shim, no pre-imported module dict).
    """
    from exonware.xwauth.connect.providers import GoogleProvider, GitHubProvider

    assert GoogleProvider.__name__ == "GoogleProvider"
    assert GitHubProvider.__name__ == "GitHubProvider"


def test_discovery_helpers_reachable() -> None:
    from exonware.xwauth.identity.oauth_http.discovery import (
        oauth_authorization_server_metadata,
        openid_configuration,
    )

    assert callable(oauth_authorization_server_metadata)
    assert callable(openid_configuration)


def test_audit_and_storage_canonical_imports() -> None:
    from exonware.xwauth.identity.audit.context import (
        attach_audit_correlation,
        reset_audit_correlation,
    )
    from exonware.xwauth.identity.storage.xwstorage_provider import XWStorageProvider
    from exonware.xwauth.identity.tokens.oidc_id_token_signing import (
        infer_id_token_signing_algorithms_for_discovery,
    )

    assert callable(infer_id_token_signing_algorithms_for_discovery)
    assert callable(attach_audit_correlation)
    assert callable(reset_audit_correlation)
    assert XWStorageProvider.__name__ == "XWStorageProvider"


def test_oauth_errors_and_ops_hooks_reachable() -> None:
    from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
    from exonware.xwauth.identity.ops_hooks import track_critical_handler

    assert callable(oauth_error_to_http)
    assert callable(track_critical_handler)
