"""
``exonware.xwauth`` — namespace package bridging coexisting distributions.

``exonware-xwauth-connect`` (``exonware.xwauth.connect.*``) and
``exonware-xwauth-identity`` (``exonware.xwauth.identity.*``) are independent
distributions that share this namespace. ``pkgutil.extend_path`` merges their
on-disk locations at import time so both can coexist when installed together.

**Hard rule:** this file must NOT contain package-specific logic. Multiple
distributions each ship an identical copy; exactly one wins at import time.
Leaf subpackages (``connect/__init__.py``, ``identity/__init__.py``) hold the
real package code and metadata.
"""
# Namespace package — pkgutil pattern, matches xwsystem and every other exonware dist.
__path__ = __import__("pkgutil").extend_path(__path__, __name__)
