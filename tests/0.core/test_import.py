"""Smoke import: xwlogin.providers loads with xwauth core."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xwlogin_core


def test_top_level_xwlogin_alias_matches_exonware_package() -> None:
    import xwlogin as tl
    import exonware.xwlogin as ns

    assert tl is ns
    assert tl.__version__ == ns.__version__
    assert tl.form_post_connector is ns.form_post_connector


def test_form_post_connector_matches_implementation() -> None:
    from exonware.xwlogin.form_post_connector import render_oidc_form_post_html as fpc
    from exonware.xwlogin.handlers.oauth_form_post import render_oidc_form_post_html as impl

    assert fpc is impl
    html = fpc("https://rp.example/cb", {"a": "1"})
    assert "https://rp.example/cb" in html
    assert 'name="a"' in html


def test_root_lazy_form_post_connector() -> None:
    import exonware.xwlogin as xl

    assert xl.form_post_connector.render_oidc_form_post_html is not None


def test_test_support_barrel_exports_facades() -> None:
    from exonware.xwlogin import test_support as ts

    assert callable(ts.oauth_error_to_http)
    assert callable(ts.track_critical_handler)
    assert callable(ts.get_auth)
    assert callable(ts.render_oidc_form_post_html)


def test_import_google_provider() -> None:
    from exonware.xwlogin.providers import GoogleProvider

    assert GoogleProvider.__name__ == "GoogleProvider"


def test_xwauth_providers_delegates_google() -> None:
    from exonware.xwauth.providers import GoogleProvider

    assert GoogleProvider.__name__ == "GoogleProvider"


def test_api_services_connector_import_surface() -> None:
    """xwauth-api and similar hosts should import login route wiring from one façade (GUIDE_32)."""
    from exonware.xwlogin.handlers.api_services_connector import (
        get_provider_callback_routes,
        login_route_mixins,
    )

    assert callable(get_provider_callback_routes)
    assert login_route_mixins.__name__ == "exonware.xwlogin.handlers.mixins"


def test_root_lazy_api_services_connector() -> None:
    """Root package PEP 562 exposes ``api_services_connector`` like other façades."""
    import exonware.xwlogin as xl

    mod = xl.api_services_connector
    assert mod.__name__ == "exonware.xwlogin.handlers.api_services_connector"
    assert callable(mod.get_provider_callback_routes)


def test_discovery_connector_reexports() -> None:
    """AS discovery metadata for reference apps (xwauth-api) via xwlogin façade."""
    from exonware.xwlogin.discovery_connector import (
        oauth_authorization_server_metadata,
        openid_configuration,
    )

    assert callable(oauth_authorization_server_metadata)
    assert callable(openid_configuration)


def test_tokens_audit_storage_connectors() -> None:
    """xwauth-api server/storage wiring via xwlogin façades (GUIDE_32)."""
    from exonware.xwlogin.audit_connector import (
        attach_audit_correlation,
        reset_audit_correlation,
    )
    from exonware.xwlogin.storage_connector import XWStorageProvider
    from exonware.xwlogin.tokens_connector import (
        infer_id_token_signing_algorithms_for_discovery,
    )

    assert callable(infer_id_token_signing_algorithms_for_discovery)
    assert callable(attach_audit_correlation)
    assert callable(reset_audit_correlation)
    assert XWStorageProvider.__name__ == "XWStorageProvider"


def test_connector_route_mixins_facade() -> None:
    from exonware.xwlogin.handlers.connector_route_mixins import connector_route_mixins

    assert connector_route_mixins.__name__ == "exonware.xwauth.handlers.mixins"


def test_root_lazy_tokens_connector() -> None:
    import exonware.xwlogin as xl

    assert callable(xl.tokens_connector.infer_id_token_signing_algorithms_for_discovery)


def test_oauth_errors_and_ops_connectors() -> None:
    from exonware.xwlogin.oauth_errors_connector import oauth_error_to_http
    from exonware.xwlogin.ops_connector import track_critical_handler

    assert callable(oauth_error_to_http)
    assert callable(track_critical_handler)


def test_connector_transport_uses_package_facades() -> None:
    import exonware.xwlogin.handlers.connector_transport as ct

    assert callable(ct.oauth_error_to_http)
    assert callable(ct.track_critical_handler)


def test_handlers_common_connector_alias() -> None:
    """``handlers.connector_common`` must match package-level ``handlers_common_connector``."""
    import exonware.xwlogin.handlers_common_connector as hcc
    from exonware.xwlogin.handlers import connector_common as cc

    assert hcc.get_auth is cc.get_auth
    assert hcc.AUTH_TAGS is cc.AUTH_TAGS


def test_root_lazy_handlers_common_connector() -> None:
    import exonware.xwlogin as xl

    assert xl.handlers_common_connector.get_auth is xl.handlers.connector_common.get_auth
