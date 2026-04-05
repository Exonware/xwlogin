#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/providers/__init__.py
XWLogin — OAuth / OIDC identity provider integrations (companion to xwauth).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 20-Dec-2025
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderRegistry
# Social / Consumer IdPs
from .google import GoogleProvider
from .github import GitHubProvider
from .discord import DiscordProvider
from .discord_gaming import DiscordGamingProvider
from .slack import SlackProvider
from .microsoft import MicrosoftProvider
from .tier1_global_essential_providers import (
    Microsoft365Provider,
    XProvider,
    MetaOAuthProvider,
    MicrosoftEntraExternalIdProvider,
    AppleBusinessManagerStub,
    AppleIcloudWebStub,
    AppleGameCenterStub,
)
from .apple import (
    AppleProvider,
    build_apple_client_secret_jwt,
    merge_apple_sign_in_profile,
    parse_apple_authorization_user,
)
from .samsung import SamsungProvider
from .twitter import TwitterProvider
from .linkedin import LinkedInProvider
from .reddit import RedditProvider
from .spotify import SpotifyProvider
from .dropbox import DropboxProvider
from .pinterest import PinterestProvider
from .tumblr import TumblrProvider
from .vimeo import VimeoProvider
from .facebook import FacebookProvider
from .amazon import AmazonProvider
from .instagram import InstagramProvider
from .yahoo import YahooProvider
from .yahoo_japan import YahooJapanProvider
from .naver import NaverProvider
from .paypal import PayPalProvider
from .tiktok import TikTokProvider
from .snapchat import SnapchatProvider
from .telegram import TelegramProvider
from .threads import ThreadsProvider
from .mastodon import MastodonProvider
from .bluesky import BlueskyProvider
from .medium import MediumProvider
# Messaging apps
from .whatsapp import WhatsAppProvider
from .signal import SignalProvider
from .viber import ViberProvider
from .line import LineProvider
from .microsoft_teams import MicrosoftTeamsProvider
from .zoom import ZoomProvider
from .skype import SkypeProvider
from .kakaotalk import KakaoTalkProvider
from .zalo import ZaloProvider
from .threema import ThreemaProvider
from .wire import WireProvider
from .element import ElementProvider
from .matrix import MatrixProvider
from .rocket_chat import RocketChatProvider
from .mattermost import MattermostProvider
# Global AI/LLM platforms
from .openai import OpenAIProvider
from .anthropic import AnthropicProvider
from .google_gemini import GoogleGeminiProvider
from .azure_openai import AzureOpenAIProvider
from .cohere import CohereProvider
from .hugging_face import HuggingFaceProvider
from .mistral import MistralProvider
from .perplexity import PerplexityProvider
from .together_ai import TogetherAIProvider
from .groq import GroqProvider
# Chinese AI/LLM platforms
from .alibaba_tongyi import AlibabaTongyiProvider
from .tencent_hunyuan import TencentHunyuanProvider
from .iflytek import IFlytekProvider
from .zhipu_ai import ZhipuAIProvider
from .minimax import MiniMaxProvider
from .moonshot_ai import MoonshotAIProvider
from .deepseek import DeepSeekProvider
from .qwen import QwenProvider
from .chatglm import ChatGLMProvider
# Russian AI/LLM platforms
from .gigachat import GigaChatProvider
from .sber_ai import SberAIProvider
# Russian social media
from .odnoklassniki import OdnoklassnikiProvider
from .mail_ru import MailRuProvider
from .my_world import MyWorldProvider
# Additional Chinese social media
from .zhihu import ZhihuProvider
from .bilibili import BilibiliProvider
from .kuaishou import KuaishouProvider
# Middle Eastern job/shop platforms
from .bayt import BaytProvider
from .akhtaboot import AkhtabootProvider
from .wuzzuf import WuzzufProvider
from .gulf_talents import GulfTalentsProvider
from .nafs import NafsProvider
# Live streaming platforms
from .liveme import LiveMeProvider
from .jaco import JACOProvider
from .tango import TangoProvider
from .bigo_live import BigoLiveProvider
from .younow import YouNowProvider
from .periscope import PeriscopeProvider
# Developer / Work platforms
from .gitlab import GitLabProvider
from .bitbucket import BitbucketProvider
from .stack_overflow import StackOverflowProvider
from .salesforce import SalesforceProvider
from .box import BoxProvider
from .box_enterprise import BoxEnterpriseProvider
from .shopify import ShopifyProvider
from .wordpress import WordPressProvider
from .woocommerce import WooCommerceProvider
from .dropbox_business import DropboxBusinessProvider
from .bigcommerce import BigCommerceProvider
from .square import SquareProvider
from .stripe import StripeConnectProvider
from .amazon_cognito_user_pool import AmazonCognitoUserPoolProvider
from .tier7_api_flow_providers import (
    PlaidProvider,
    YodleeProvider,
    MXProvider,
    TruliooProvider,
    OnfidoProvider,
    JumioProvider,
)
from .auth_js_meta import AuthJsMetaProvider
from .yammer import YammerProvider
from .soundcloud import SoundCloudProvider
from .evernote import EvernoteProvider
from .replit import ReplitProvider
from .codepen import CodePenProvider
from .codesandbox import CodeSandboxProvider
from .glitch import GlitchProvider
from .vercel import VercelProvider
from .digitalocean import DigitalOceanProvider
from .heroku import HerokuProvider
from .notion import NotionProvider
from .linear import LinearProvider
from .figma import FigmaProvider
from .deviantart import DeviantArtProvider
from .netlify import NetlifyProvider
from .circleci import CircleCIProvider
from .docker_hub import DockerHubProvider
from .npm import NPMProvider
# Regional providers
from .vkontakte import VKontakteProvider
from .yandex import YandexProvider
from .weibo import WeiboProvider
from .renren import RenRenProvider
from .aol import AOLProvider
# Chinese providers
from .wechat import WeChatProvider
from .qq import QQProvider
from .baidu import BaiduProvider
from .alipay import AlipayProvider
from .douyin import DouyinProvider
from .xiaohongshu import XiaohongshuProvider
from .dingtalk import DingTalkProvider
from .taobao import TaobaoProvider
from .tmall import TmallProvider
from .feishu import FeishuProvider, LarkIntlProvider
from .xiaomi_account import XiaomiAccountProvider
from .huawei_id import HuaweiIdProvider
from .china_wecom_unionpay_stubs import WeComProvider, UnionPayProvider
# Middle Eastern providers
from .noon import NoonProvider
from .careem import CareemProvider
from .anghami import AnghamiProvider
from .tamara import TamaraProvider
from .stc_pay import STCPayProvider
from .fawry import FawryProvider
from .paytabs import PayTabsProvider
from .rakbank import RAKBANKProvider
from .mea_emea_fintech_stubs import (
    MafCarrefourProvider,
    AlipayHKProvider,
    MPesaProvider,
    AirtelMoneyProvider,
    JumiaProvider,
    TeldaProvider,
    OpayProvider,
    FlutterwaveProvider,
)
# Streaming platforms
from .twitch import TwitchProvider
from .pandora import PandoraProvider
from .tidal import TidalProvider
from .deezer import DeezerProvider
from .crunchyroll import CrunchyrollProvider
from .youtube_music import YouTubeMusicProvider
from .youtube import YouTubeProvider
from .strava import StravaProvider
from .fitbit import FitbitProvider
from .garmin import GarminProvider
from .iheartradio import IHeartRadioProvider
from .siriusxm import SiriusXMProvider
from .apple_music import AppleMusicProvider
# Shopping / E-commerce platforms
from .ebay import eBayProvider
from .etsy import EtsyProvider
from .mercado_libre import MercadoLibreProvider
from .latam_fintech_retail_stubs import (
    RappiProvider,
    NubankProvider,
    PicPayProvider,
    UolProvider,
    GloboProvider,
    OxxoProvider,
    SpeiProvider,
    NequiProvider,
    DaviviendaProvider,
    BancolombiaProvider,
    AgrupacionDragonProvider,
    PersonalPayProvider,
)
from .eidas_europe_providers import (
    IdAustriaProvider,
    ItsmeProvider,
    BankIDNordicProvider,
    BankIDSwedenProvider,
    BankIDNorwayProvider,
    MitIDProvider,
    DigiDProvider,
    FcBarcelonaDigitalIdProvider,
    FranceConnectProvider,
    SpidProvider,
    PosteIdProvider,
    SwissIdProvider,
    FtnProvider,
    SmartIdProvider,
    GovUkVerifyProvider,
    NhsLoginProvider,
    GovUkOneLoginProvider,
    GermanEidProvider,
    IdinProvider,
    VerifiedMeProvider,
    MobileConnectGsmaProvider,
    Auth0EuropeProvider,
    KeycloakEuProvider,
)
from .apac_india_sea_cis_stubs import (
    MixiProvider,
    GarenaProvider,
    GrabProvider,
    GotoProvider,
    MomoProvider,
    TouchNGoProvider,
    GCashProvider,
    PayMayaProvider,
    PhonePeProvider,
    PaytmProvider,
    AadhaarProvider,
    DigiLockerProvider,
    IndiaStackAaProvider,
    JioProvider,
    TrueIdProvider,
    LineBankProvider,
    KakaoBankProvider,
    TossProvider,
    TinkoffProvider,
    SberbankOnlineProvider,
    AlfaBankRuProvider,
    RaiffeisenProvider,
)
from .flipkart import FlipkartProvider
from .rakuten import RakutenProvider
from .jd_com import JDComProvider
from .lazada import LazadaProvider
from .shopee import ShopeeProvider
from .coupang import CoupangProvider
# Gaming platforms
from .playstation import PlayStationProvider
from .xbox import XboxProvider
from .nintendo import NintendoProvider
from .steam import SteamProvider
from .epic_games import EpicGamesProvider
from .battle_net import BattleNetProvider
from .riot_games import RiotGamesProvider
from .ubisoft import UbisoftProvider
from .tier6_non_oauth_stubs import EaOriginProvider, PelotonProvider, BandcampProvider
# Enterprise / Workforce federation
from .microsoft_entra_id import MicrosoftEntraIDProvider
from .google_workspace import GoogleWorkspaceProvider
from .adfs import ADFSProvider
from .active_directory import ActiveDirectoryProvider
from .ldap import LDAPProvider
from .ping_federate import PingFederateProvider
from .okta import OktaProvider
from .auth0 import Auth0Provider
from .keycloak import KeycloakProvider, RedHatSsoProvider
from .enterprise_tier2_oidc import (
    OneLoginOidcProvider,
    JumpCloudOidcProvider,
    PingOneOidcProvider,
    AzureAdB2CPolicyProvider,
    FusionAuthProvider,
    ZitadelProvider,
    AuthentikApplicationProvider,
    Wso2IdentityServerProvider,
    GluuServerProvider,
    OracleIdentityCloudProvider,
    ForgeRockAmOidcProvider,
    CurityIdentityServerProvider,
    DuendeIdentityServerProvider,
    SapCloudIdentityProvider,
)
from .tier2_enterprise_iam_stubs import (
    CyberArkIdaptiveStub,
    IbmSecurityVerifyStub,
    SailPointIdentityGovernanceStub,
    DuoSecurityStub,
    RsaSecurIdAccessStub,
    SecureAuthStub,
    ShibbolethStub,
    SimpleSamlPhpStub,
    GoogleWorkspaceSamlStub,
    Connect2idServerStub,
    VmwareWorkspaceOneStub,
    CitrixCloudStub,
    NetIqStub,
    IbmTivoliAccessManagerStub,
    CaSiteMinderStub,
    WorkOSStub,
    FronteggStub,
    SuperTokensStub,
)
# Extended from xwsystem (xwauth extends xwsystem)
__all__ = [
    "ABaseProvider",
    "ProviderRegistry",
    # Social / Consumer IdPs
    "GoogleProvider",
    "GitHubProvider",
    "DiscordProvider",
    "DiscordGamingProvider",
    "SlackProvider",
    "MicrosoftProvider",
    "Microsoft365Provider",
    "MicrosoftEntraExternalIdProvider",
    "AppleProvider",
    "AppleBusinessManagerStub",
    "AppleIcloudWebStub",
    "AppleGameCenterStub",
    "build_apple_client_secret_jwt",
    "merge_apple_sign_in_profile",
    "parse_apple_authorization_user",
    "SamsungProvider",
    "TwitterProvider",
    "XProvider",
    "LinkedInProvider",
    "RedditProvider",
    "SpotifyProvider",
    "DropboxProvider",
    "PinterestProvider",
    "TumblrProvider",
    "VimeoProvider",
    "FacebookProvider",
    "MetaOAuthProvider",
    "AmazonProvider",
    "InstagramProvider",
    "YahooProvider",
    "YahooJapanProvider",
    "NaverProvider",
    "PayPalProvider",
    "TikTokProvider",
    "SnapchatProvider",
    "TelegramProvider",
    "ThreadsProvider",
    "MastodonProvider",
    "BlueskyProvider",
    "MediumProvider",
    # Messaging apps
    "WhatsAppProvider",
    "SignalProvider",
    "ViberProvider",
    "LineProvider",
    "MicrosoftTeamsProvider",
    "ZoomProvider",
    "SkypeProvider",
    "KakaoTalkProvider",
    "ZaloProvider",
    "ThreemaProvider",
    "WireProvider",
    "ElementProvider",
    "MatrixProvider",
    "RocketChatProvider",
    "MattermostProvider",
    # Global AI/LLM platforms
    "OpenAIProvider",
    "AnthropicProvider",
    "GoogleGeminiProvider",
    "AzureOpenAIProvider",
    "CohereProvider",
    "HuggingFaceProvider",
    "MistralProvider",
    "PerplexityProvider",
    "TogetherAIProvider",
    "GroqProvider",
    # Chinese AI/LLM platforms
    "AlibabaTongyiProvider",
    "TencentHunyuanProvider",
    "IFlytekProvider",
    "ZhipuAIProvider",
    "MiniMaxProvider",
    "MoonshotAIProvider",
    "DeepSeekProvider",
    "QwenProvider",
    "ChatGLMProvider",
    # Russian AI/LLM platforms
    "GigaChatProvider",
    "SberAIProvider",
    # Russian social media
    "OdnoklassnikiProvider",
    "MailRuProvider",
    "MyWorldProvider",
    # Additional Chinese social media
    "ZhihuProvider",
    "BilibiliProvider",
    "KuaishouProvider",
    # Middle Eastern job/shop platforms
    "BaytProvider",
    "AkhtabootProvider",
    "WuzzufProvider",
    "GulfTalentsProvider",
    "NafsProvider",
    # Live streaming platforms
    "LiveMeProvider",
    "JACOProvider",
    "TangoProvider",
    "BigoLiveProvider",
    "YouNowProvider",
    "PeriscopeProvider",
    # Developer / Work platforms
    "GitLabProvider",
    "BitbucketProvider",
    "StackOverflowProvider",
    "SalesforceProvider",
    "BoxProvider",
    "BoxEnterpriseProvider",
    "ShopifyProvider",
    "WordPressProvider",
    "WooCommerceProvider",
    "DropboxBusinessProvider",
    "BigCommerceProvider",
    "SquareProvider",
    "StripeConnectProvider",
    "AmazonCognitoUserPoolProvider",
    "PlaidProvider",
    "YodleeProvider",
    "MXProvider",
    "TruliooProvider",
    "OnfidoProvider",
    "JumioProvider",
    "AuthJsMetaProvider",
    "YammerProvider",
    "SoundCloudProvider",
    "EvernoteProvider",
    "ReplitProvider",
    "CodePenProvider",
    "CodeSandboxProvider",
    "GlitchProvider",
    "VercelProvider",
    "NetlifyProvider",
    "CircleCIProvider",
    "DockerHubProvider",
    "NPMProvider",
    # Regional providers
    "VKontakteProvider",
    "YandexProvider",
    "WeiboProvider",
    "RenRenProvider",
    "AOLProvider",
    # Chinese providers
    "WeChatProvider",
    "QQProvider",
    "BaiduProvider",
    "AlipayProvider",
    "DouyinProvider",
    "XiaohongshuProvider",
    "DingTalkProvider",
    "TaobaoProvider",
    "TmallProvider",
    "FeishuProvider",
    "LarkIntlProvider",
    "XiaomiAccountProvider",
    "HuaweiIdProvider",
    "WeComProvider",
    "UnionPayProvider",
    # Middle Eastern providers
    "NoonProvider",
    "CareemProvider",
    "AnghamiProvider",
    "TamaraProvider",
    "STCPayProvider",
    "FawryProvider",
    "PayTabsProvider",
    "RAKBANKProvider",
    "MafCarrefourProvider",
    "AlipayHKProvider",
    "MPesaProvider",
    "AirtelMoneyProvider",
    "JumiaProvider",
    "TeldaProvider",
    "OpayProvider",
    "FlutterwaveProvider",
    # Streaming platforms
    "TwitchProvider",
    "PandoraProvider",
    "TidalProvider",
    "DeezerProvider",
    "CrunchyrollProvider",
    "YouTubeMusicProvider",
    "YouTubeProvider",
    "StravaProvider",
    "FitbitProvider",
    "GarminProvider",
    "IHeartRadioProvider",
    "SiriusXMProvider",
    "AppleMusicProvider",
    # Shopping / E-commerce platforms
    "eBayProvider",
    "EtsyProvider",
    "MercadoLibreProvider",
    "RappiProvider",
    "NubankProvider",
    "PicPayProvider",
    "UolProvider",
    "GloboProvider",
    "OxxoProvider",
    "SpeiProvider",
    "NequiProvider",
    "DaviviendaProvider",
    "BancolombiaProvider",
    "AgrupacionDragonProvider",
    "PersonalPayProvider",
    # EU / eIDAS and national digital identity
    "IdAustriaProvider",
    "ItsmeProvider",
    "BankIDNordicProvider",
    "BankIDSwedenProvider",
    "BankIDNorwayProvider",
    "MitIDProvider",
    "DigiDProvider",
    "FcBarcelonaDigitalIdProvider",
    "FranceConnectProvider",
    "SpidProvider",
    "PosteIdProvider",
    "SwissIdProvider",
    "FtnProvider",
    "SmartIdProvider",
    "GovUkVerifyProvider",
    "NhsLoginProvider",
    "GovUkOneLoginProvider",
    "GermanEidProvider",
    "IdinProvider",
    "VerifiedMeProvider",
    "MobileConnectGsmaProvider",
    "Auth0EuropeProvider",
    "KeycloakEuProvider",
    # APAC wallets / India rails / CIS banking (stubs)
    "MixiProvider",
    "GarenaProvider",
    "GrabProvider",
    "GotoProvider",
    "MomoProvider",
    "TouchNGoProvider",
    "GCashProvider",
    "PayMayaProvider",
    "PhonePeProvider",
    "PaytmProvider",
    "AadhaarProvider",
    "DigiLockerProvider",
    "IndiaStackAaProvider",
    "JioProvider",
    "TrueIdProvider",
    "LineBankProvider",
    "KakaoBankProvider",
    "TossProvider",
    "TinkoffProvider",
    "SberbankOnlineProvider",
    "AlfaBankRuProvider",
    "RaiffeisenProvider",
    "FlipkartProvider",
    "RakutenProvider",
    "JDComProvider",
    "LazadaProvider",
    "ShopeeProvider",
    "CoupangProvider",
    # Gaming platforms
    "PlayStationProvider",
    "XboxProvider",
    "NintendoProvider",
    "SteamProvider",
    "EpicGamesProvider",
    "BattleNetProvider",
    "RiotGamesProvider",
    "UbisoftProvider",
    "EaOriginProvider",
    "PelotonProvider",
    "BandcampProvider",
    # Enterprise / Workforce federation
    "MicrosoftEntraIDProvider",
    "GoogleWorkspaceProvider",
    "ADFSProvider",
    "ActiveDirectoryProvider",
    "LDAPProvider",
    "PingFederateProvider",
    "OktaProvider",
    "Auth0Provider",
    "KeycloakProvider",
    "RedHatSsoProvider",
    "OneLoginOidcProvider",
    "JumpCloudOidcProvider",
    "PingOneOidcProvider",
    "AzureAdB2CPolicyProvider",
    "FusionAuthProvider",
    "ZitadelProvider",
    "AuthentikApplicationProvider",
    "Wso2IdentityServerProvider",
    "GluuServerProvider",
    "OracleIdentityCloudProvider",
    "ForgeRockAmOidcProvider",
    "CurityIdentityServerProvider",
    "DuendeIdentityServerProvider",
    "SapCloudIdentityProvider",
    "CyberArkIdaptiveStub",
    "IbmSecurityVerifyStub",
    "SailPointIdentityGovernanceStub",
    "DuoSecurityStub",
    "RsaSecurIdAccessStub",
    "SecureAuthStub",
    "ShibbolethStub",
    "SimpleSamlPhpStub",
    "GoogleWorkspaceSamlStub",
    "Connect2idServerStub",
    "VmwareWorkspaceOneStub",
    "CitrixCloudStub",
    "NetIqStub",
    "IbmTivoliAccessManagerStub",
    "CaSiteMinderStub",
    "WorkOSStub",
    "FronteggStub",
    "SuperTokensStub",
]
