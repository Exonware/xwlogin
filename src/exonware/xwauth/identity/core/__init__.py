#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/__init__.py
Core OAuth 2.0/OIDC Module
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from .oauth2 import OAuth2Server
from .oidc import OIDCProvider
from .pkce import PKCE
from .par import PARManager
from .dcr import DCRManager
from .logout import LogoutManager
from .saml import SAMLManager
from .grants.base import ABaseGrant
from .grants.authorization_code import AuthorizationCodeGrant
from .grants.client_credentials import ClientCredentialsGrant
from .grants.resource_owner_password import ResourceOwnerPasswordGrant
from .grants.device_code import DeviceCodeGrant
from .grants.refresh_token import RefreshTokenGrant
# OAuth 1.0 support
from .oauth1 import OAuth1Server, OAuth1Client, OAuth1Signature, OAuth1RequestValidator
# Advanced RFC support
from .rfc import RFC9101BrowserBasedApps, RFC9207IssuerIdentification, RFC9068JWTProfile, RFC7521JWTBearerToken
__all__ = [
    "OAuth2Server",
    "OIDCProvider",
    "PKCE",
    "PARManager",
    "DCRManager",
    "LogoutManager",
    "SAMLManager",
    "ABaseGrant",
    "AuthorizationCodeGrant",
    "ClientCredentialsGrant",
    "ResourceOwnerPasswordGrant",
    "DeviceCodeGrant",
    "RefreshTokenGrant",
    # OAuth 1.0
    "OAuth1Server",
    "OAuth1Client",
    "OAuth1Signature",
    "OAuth1RequestValidator",
    # Advanced RFC support
    "RFC9101BrowserBasedApps",
    "RFC9207IssuerIdentification",
    "RFC9068JWTProfile",
    "RFC7521JWTBearerToken",
]
