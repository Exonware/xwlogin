#!/usr/bin/env python3

"""

#exonware/xwauth.connector/tests/1.unit/providers_tests/test_microsoft_provider.py

Unit tests for Microsoft OAuth provider.

Company: eXonware.com

Author: eXonware Backend Team

Email: connect@exonware.com

Version: 0.0.1.0

Generation Date: 20-Dec-2025

"""



import pytest

from urllib.parse import parse_qs, urlparse

from unittest.mock import AsyncMock, Mock



from exonware.xwauth.identity.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError

from exonware.xwauth.connect.providers.microsoft import MicrosoftProvider

@pytest.mark.xwlogin_unit



class TestMicrosoftProvider:

    """Test MicrosoftProvider implementation."""

    @pytest.fixture



    def provider(self):

        """Create MicrosoftProvider instance."""

        return MicrosoftProvider(

            client_id="test_microsoft_client",

            client_secret="test_microsoft_secret"

        )



    def test_provider_name(self, provider):

        """Test provider name."""

        assert provider.provider_name == "microsoft"



    def test_provider_type(self, provider):

        """Test provider type."""

        assert provider.provider_type == ProviderType.MICROSOFT

    @pytest.mark.asyncio



    async def test_get_authorization_url(self, provider):

        """Test authorization URL generation."""

        url = await provider.get_authorization_url(

            client_id="test_microsoft_client",

            redirect_uri="https://example.com/callback",

            state="test_state",

            scopes=["openid", "profile", "email"]

        )

        assert url is not None

        parsed = urlparse(url)

        assert parsed.netloc == "login.microsoftonline.com"

        assert parsed.path == "/common/oauth2/v2.0/authorize"

        query = parse_qs(parsed.query)

        assert query["client_id"] == ["test_microsoft_client"]

        assert query["redirect_uri"] == ["https://example.com/callback"]

        assert query["state"] == ["test_state"]

        assert query["response_type"] == ["code"]

        assert query["scope"] == ["openid profile email"]

        assert query["response_mode"] == ["query"]



    @pytest.mark.asyncio

    async def test_get_authorization_url_uses_tenant_specific_endpoint(self):

        """Test tenant_id builds tenant-specific authorize endpoint."""

        provider = MicrosoftProvider(

            client_id="test_microsoft_client",

            client_secret="test_microsoft_secret",

            tenant_id="contoso.onmicrosoft.com",

        )

        url = await provider.get_authorization_url(

            client_id="test_microsoft_client",

            redirect_uri="https://example.com/callback",

            state="test_state",

            scopes=["openid"],

        )

        parsed = urlparse(url)

        assert parsed.path == "/contoso.onmicrosoft.com/oauth2/v2.0/authorize"



    @pytest.mark.asyncio

    async def test_get_authorization_url_strips_tenant_id(self):

        """Test tenant_id whitespace is stripped before URL construction."""

        provider = MicrosoftProvider(

            client_id="test_microsoft_client",

            client_secret="test_microsoft_secret",

            tenant_id="  tenant-guid  ",

        )

        url = await provider.get_authorization_url(

            client_id="test_microsoft_client",

            redirect_uri="https://example.com/callback",

            state="test_state",

            scopes=["openid"],

        )

        parsed = urlparse(url)

        assert parsed.path == "/tenant-guid/oauth2/v2.0/authorize"



    @pytest.mark.asyncio



    async def test_exchange_code_for_token(self, provider):

        """Test code exchange for token with deterministic async mock."""

        provider._async_http_client = AsyncMock()

        provider._async_http_client.post.return_value = Mock(

            status_code=200,

            json=lambda: {"access_token": "ms-at", "token_type": "Bearer"},

        )

        response = await provider.exchange_code_for_token(

            code="test_code",

            redirect_uri="https://example.com/callback"

        )

        assert response == {"access_token": "ms-at", "token_type": "Bearer"}



    @pytest.mark.asyncio

    async def test_exchange_code_for_token_non_200_raises_provider_error(self, provider):

        """Test token exchange maps non-200 to provider connection error."""

        provider._async_http_client = AsyncMock()

        provider._async_http_client.post.return_value = AsyncMock(status_code=400, text="bad request")

        with pytest.raises(XWProviderConnectionError):

            await provider.exchange_code_for_token(

                code="bad_code",

                redirect_uri="https://example.com/callback"

            )



    @pytest.mark.asyncio

    async def test_get_user_info_normalizes_mail_and_name_fields(self, provider):

        """Test Microsoft Graph user payload normalization."""

        original = ABaseProvider.get_user_info

        ABaseProvider.get_user_info = AsyncMock(

            return_value={

                "id": "ms-1",

                "mail": "user@contoso.com",

                "displayName": "User Name",

                "givenName": "User",

                "surname": "Name",

            }

        )

        try:

            user_info = await provider.get_user_info("test_access_token")

        finally:

            ABaseProvider.get_user_info = original



        assert user_info == {

            "id": "ms-1",

            "email": "user@contoso.com",

            "name": "User Name",

            "given_name": "User",

            "family_name": "Name",

        }



    @pytest.mark.asyncio

    async def test_get_user_info_falls_back_to_user_principal_name(self, provider):

        """Test email fallback uses userPrincipalName when mail missing."""

        original = ABaseProvider.get_user_info

        ABaseProvider.get_user_info = AsyncMock(

            return_value={"id": "ms-2", "userPrincipalName": "upn@contoso.com"}

        )

        try:

            user_info = await provider.get_user_info("test_access_token")

        finally:

            ABaseProvider.get_user_info = original

        assert user_info["email"] == "upn@contoso.com"

