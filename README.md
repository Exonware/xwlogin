# xwlogin

**Login layer** for the Exonware stack: OAuth/OIDC **identity providers** (100+ modules), **RP / agent clients** (`OAuth2Session`, token managers), **first-party login** (password, magic link, phone OTP, MFA, WebAuthn/passkeys), and callback discovery. **xwauth** is the **OAuth2/OIDC AS connector** that **composes** this package (target: *xwlogin* has **no** dependency on *xwauth*; see **[REF_41_DEPENDENCY_DIRECTIONS.md](../.docs/guides/REF_41_DEPENDENCY_DIRECTIONS.md)** — migration in progress while `pyproject.toml` still lists `exonware-xwauth` to avoid a pip cycle).

**Company:** eXonware.com · **Author:** eXonware Backend Team · **Email:** connect@exonware.com

[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## 📦 Install

```bash
pip install exonware-xwlogin
pip install "exonware-xwlogin[stack]"   # optional: xwnode, xwdata, xwentity, xwmodels, xwquery, xwaction — xwjson is in [handlers]; xwschema via xwauth (REF_41 §8)
```

After **`[stack]`**, optional: **`import exonware.xwlogin.stack`** at process startup to eagerly import that chain (REF_41 §8).

`exonware-xwauth` is installed automatically as a dependency.

For FastAPI route mixins (`exonware.xwlogin.handlers.mixins`), install the optional extra:

```bash
pip install "exonware-xwlogin[handlers]"
```

**Deployable hosts** (xwapi + xwaction pinned together) should prefer **`exonware-xwlogin-api`**, which is the composition package aligned with **REF_40** (same family as `exonware-xwauth-api`). Library-only users can stay on `exonware-xwlogin` without xwapi.

---

## 🚀 Usage

Prefer **xwlogin** as the import root for IdPs and connector façades; reach into **xwauth** only when you need the full AS surface (grants, federation internals, etc.):

```python
from exonware.xwlogin.providers import GoogleProvider, ProviderRegistry
from exonware.xwlogin.facade_connector import XWAuth
# Other façades: provider_connector, auth_connector, config_connector, api_connector,
# handlers.connector_http, security, test_support (tests), …
```

For backwards compatibility, `from exonware.xwauth.providers import GoogleProvider` still works **when xwlogin is installed** (delegation in `exonware.xwauth.providers`). See `xwauth/.references/COMPETITIVE_STACK.md` for the full split vs Authlib / social-auth style stacks.

---

## 🗂️ Layout

| Package | Responsibility |
|--------|------------------|
| **xwauth** | Connector: OAuth2/OIDC **authorization server** core, tokens, sessions, federation, `XWAuth` implementation |
| **xwlogin** (this repo) | Login: IdP catalog (`providers`), façade modules (`provider_connector`, `facade_connector`, `handlers.connector_*`, `security`, …), OAuth RP clients, WebAuthn/MFA, first-party authenticators |

---

## 📜 License

MIT — see [LICENSE](LICENSE) if present in your checkout.
Version: 0.0.1.2 | Updated: 08-Apr-2026

*Built with ❤️ by eXonware.com - Revolutionizing Python Development Since 2025*
