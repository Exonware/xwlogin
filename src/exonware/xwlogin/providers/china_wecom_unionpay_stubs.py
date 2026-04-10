#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/china_wecom_unionpay_stubs.py
企业微信 (WeChat Work / WeCom) and 银联 UnionPay — enterprise / issuer flows that
are not expressed as a single generic OAuth2 userinfo client here.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 07-Apr-2026
"""
from exonware.xwlogin.provider_connector import ProviderType
from .apac_india_sea_cis_stubs import _ApacPartnerOrRailsOAuth


class WeComProvider(_ApacPartnerOrRailsOAuth):
    """WeCom — corpId, agentId, qyapi.weixin.qq.com gettoken and auth/getuserinfo (or QR SSO)."""

    _hint = (
        "WeCom login uses enterprise credentials: follow Tencent 企业微信 docs for OAuth2, "
        "QR connect, or internal app getuserinfo — not consumer WeChat open.weixin.qq.com qrconnect."
    )

    @property
    def provider_name(self) -> str:
        return "wecom"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.WECOM


class UnionPayProvider(_ApacPartnerOrRailsOAuth):
    """中国银联 / UnionPay — bank card network and 云闪付 partner rails, not one public SSO URL."""

    _hint = (
        "UnionPay identity and payments integrate via issuer, acquirer, or UnionPay developer programs "
        "(region and product specific)."
    )

    @property
    def provider_name(self) -> str:
        return "unionpay"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.UNIONPAY
