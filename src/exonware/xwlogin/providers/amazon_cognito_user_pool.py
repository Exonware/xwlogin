#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/amazon_cognito_user_pool.py
Amazon Cognito User Pool (hosted UI) OIDC / OAuth Provider
Uses your Cognito hosted UI domain (e.g. myapp.auth.us-east-1.amazoncognito.com), not IAM.
This is distinct from mapping arbitrary OIDC issuers — it encodes Cognito URL layout.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class AmazonCognitoUserPoolProvider(ABaseProvider):
    """OAuth 2.0 / OIDC against a Cognito User Pool hosted UI domain."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        region: str,
        user_pool_id: str,
        cognito_domain: str,
        **kwargs: Any,
    ):
        """
        Args:
            client_id: App client id from the Cognito user pool.
            client_secret: App client secret (omit for public clients — pass empty string).
            region: AWS region (e.g. us-east-1).
            user_pool_id: Pool id (e.g. us-east-1_xxxx).
            cognito_domain: Hosted UI domain host only, e.g. myapp.auth.us-east-1.amazoncognito.com
        """
        domain = cognito_domain.removeprefix("https://").removeprefix("http://").strip().rstrip("/")
        base = f"https://{domain}"
        issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
        self._issuer = issuer
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{base}/oauth2/authorize",
            token_url=f"{base}/oauth2/token",
            userinfo_url=f"{base}/oauth2/userInfo",
            **kwargs
        )

    @property
    def provider_name(self) -> str:
        return "amazon_cognito_user_pool"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.AMAZON_COGNITO_USER_POOL

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/.well-known/jwks.json"
