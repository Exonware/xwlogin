# xwauth-identity

**Identity layer** for the eXonware stack: OAuth 2.0 / OIDC **authorization server** core (tokens, sessions, federation, grants, RFC modules), **first-party login** (password, magic link, phone OTP, MFA, WebAuthn/passkeys), SCIM, organizations, webhooks, FGA, and audit — shipped as a standalone identity provider.

**Architecture.** `exonware-xwauth-identity` and `exonware-xwauth-connect` are sibling distributions that share the `exonware.xwauth` namespace via `pkgutil.extend_path`. Identity is the first-party auth provider. Connect is the connector/broker for external IdPs. **Neither package imports the other** — they coexist under one namespace and discover each other at runtime via `discover_connect_package()` / `discover_identity_package()` helpers.

**Company:** eXonware.com · **Author:** eXonware Backend Team · **Email:** connect@exonware.com

[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## 📦 Install

```bash
pip install exonware-xwauth-identity
# Optional composition extras:
pip install "exonware-xwauth-identity[stack]"      # xwnode, xwdata, xwentity, xwmodels, xwquery, xwaction
pip install "exonware-xwauth-identity[handlers]"   # FastAPI route mixins
```

After `[stack]`, call `import exonware.xwauth.identity.stack` at process startup to eagerly import that chain.

To run both identity and connect sides in one process (BaaS-style composition), install both distributions:

```bash
pip install exonware-xwauth-identity exonware-xwauth-connect
```

**Deployable hosts** (xwapi + xwaction pinned together) should prefer `exonware-xwauth-identity-api`. Library-only users can stay on `exonware-xwauth-identity` without xwapi.

---

## 🚀 Usage

```python
from exonware.xwauth.identity.facade import XWAuth
from exonware.xwauth.identity.config.config import XWAuthConfig

auth = XWAuth(config=XWAuthConfig(jwt_secret="your-secret"))
```

Common façade modules: `auth_connector`, `config_connector`, `facade_connector`, `api_connector`, `handlers.connector_http`, `security`, `test_support` (tests only).

### Mutual discovery (coexistence with `xwauth-connect`)

```python
from exonware.xwauth.identity import discover_connect_package, connect_is_available

if connect_is_available():
    connect = discover_connect_package()
    # compose connector-side routes into your host app
```

The helper returns `None` when `exonware-xwauth-connect` is not installed — safe, cached, env-var disableable (`XWAUTH_IDENTITY_DISABLE_CONNECT_DISCOVERY=1`) for test harnesses.

---

## 🗂️ Layout

| Package | Responsibility |
|--------|------------------|
| **exonware-xwauth-identity** (this repo) | Standalone identity provider: OAuth 2.0 / OIDC AS, first-party login ceremonies, MFA/WebAuthn, SCIM, organizations, webhooks, FGA, audit |
| **exonware-xwauth-connect** (sibling) | Multi-provider connector/broker to external IdPs (Google, Apple, Microsoft, SAML, Keycloak, Auth0, …) |

Both share the `exonware.xwauth` namespace and are installable together or separately.

---

## 📜 License

Apache-2.0 — see [LICENSE](LICENSE).

Version: 0.0.1.4 | Updated: 20-Apr-2026

*Built with ❤️ by eXonware.com - Revolutionizing Python Development Since 2025*
