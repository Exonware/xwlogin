#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/defs.py
Type Definitions and Enums
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 08-Apr-2026
"""

from enum import Enum
from typing import Any
# ==============================================================================
# GRANT TYPES
# ==============================================================================


class GrantType(str, Enum):
    """OAuth 2.0 grant types."""
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    RESOURCE_OWNER_PASSWORD = "password"
    REFRESH_TOKEN = "refresh_token"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
    TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # RFC 8693
# ==============================================================================
# TOKEN TYPES
# ==============================================================================


class TokenType(str, Enum):
    """Token types."""
    JWT = "JWT"
    OPAQUE = "opaque"
    BEARER = "Bearer"
    MAC = "MAC"  # OAuth 2.0 MAC tokens (rarely used)
# ==============================================================================
# RESPONSE TYPES
# ==============================================================================


class ResponseType(str, Enum):
    """OAuth 2.0 response types."""
    CODE = "code"
    TOKEN = "token"  # Implicit flow
    ID_TOKEN = "id_token"  # OpenID Connect
    ID_TOKEN_TOKEN = "id_token token"  # OpenID Connect
    CODE_ID_TOKEN = "code id_token"  # OpenID Connect
    CODE_TOKEN = "code token"  # OpenID Connect
    CODE_ID_TOKEN_TOKEN = "code id_token token"  # OpenID Connect
# ==============================================================================
# CLIENT TYPES
# ==============================================================================


class ClientType(str, Enum):
    """OAuth 2.0 client types."""
    PUBLIC = "public"
    CONFIDENTIAL = "confidential"
# ==============================================================================
# SESSION STATUS
# ==============================================================================


class SessionStatus(str, Enum):
    """Session status."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    TERMINATED = "terminated"
# ==============================================================================
# USER STATUS
# ==============================================================================


class UserStatus(str, Enum):
    """User account status."""

    ACTIVE = "active"
    PENDING = "pending"
    SUSPENDED = "suspended"
    DISABLED = "disabled"
    DELETED = "deleted"


# ==============================================================================
# MFA METHODS
# ==============================================================================


class MFAMethod(str, Enum):
    """Multi-factor authentication methods."""

    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    WEBAUTHN = "webauthn"
    BACKUP_CODE = "backup_code"
# ==============================================================================
# PROVIDER TYPES
# ==============================================================================


class ProviderType(str, Enum):
    """OAuth provider types (auto-merged registry plus tier-2 enterprise IAM)."""
    AADHAAR = "aadhaar"
    ACTIVE_DIRECTORY = "active_directory"
    ADFS = "adfs"
    AGRUPACION_DRAGON = "agrupacion_dragon"
    AIRTEL_MONEY = "airtel_money"
    AKHTABOOT = "akhtaboot"
    ALFA_BANK_RU = "alfa_bank_ru"
    ALIBABA_TONGYI = "alibaba_tongyi"
    ALIPAY = "alipay"
    ALIPAY_HK = "alipay_hk"
    AMAZON = "amazon"
    AMAZON_COGNITO_USER_POOL = "amazon_cognito_user_pool"
    ANGHAMI = "anghami"
    ANTHROPIC = "anthropic"
    AOL = "aol"
    APPLE = "apple"
    APPLE_BUSINESS_MANAGER = "apple_business_manager"
    APPLE_GAME_CENTER = "apple_game_center"
    APPLE_ICLOUD_WEB = "apple_icloud_web"
    APPLE_MUSIC = "apple_music"
    AUTH0 = "auth0"
    AUTH0_EUROPE = "auth0_europe"
    AUTHENTIK = "authentik"
    AUTH_JS_META = "auth_js_meta"
    AZURE_AD_B2C = "azure_ad_b2c"
    AZURE_OPENAI = "azure_openai"
    BAIDU = "baidu"
    BANCOLOMBIA = "bancolombia"
    BANDCAMP = "bandcamp"
    BANKID_NORDIC = "bankid_nordic"
    BANKID_NORWAY = "bankid_norway"
    BANKID_SWEDEN = "bankid_sweden"
    BATTLE_NET = "battle_net"
    BAYT = "bayt"
    BIGCOMMERCE = "bigcommerce"
    BIGO_LIVE = "bigo_live"
    BILIBILI = "bilibili"
    BITBUCKET = "bitbucket"
    BLUESKY = "bluesky"
    BOX = "box"
    BOX_ENTERPRISE = "box_enterprise"
    CAREEM = "careem"
    CA_SITEMINDER = "ca_siteminder"
    CHATGLM = "chatglm"
    CHINESE = "chinese"
    CIRCLECI = "circleci"
    CITRIX_CLOUD = "citrix_cloud"
    CODEPEN = "codepen"
    CODESANDBOX = "codesandbox"
    COHERE = "cohere"
    CONNECT2ID_SERVER = "connect2id_server"
    COUPANG = "coupang"
    CRUNCHYROLL = "crunchyroll"
    CURITY_IDENTITY_SERVER = "curity_identity_server"
    CUSTOM = "custom"
    CYBERARK_IDAPTIVE = "cyberark_idaptive"
    DAVIVIENDA = "davivienda"
    DEEPSEEK = "deepseek"
    DEEZER = "deezer"
    DEVIANTART = "deviantart"
    DIGID = "digid"
    DIGILOCKER = "digilocker"
    DIGITALOCEAN = "digitalocean"
    DINGTALK = "dingtalk"
    DISCORD = "discord"
    DISCORD_GAMING = "discord_gaming"
    DOCKER_HUB = "docker_hub"
    DOUYIN = "douyin"
    DROPBOX = "dropbox"
    DROPBOX_BUSINESS = "dropbox_business"
    DUENDE_IDENTITY_SERVER = "duende_identity_server"
    DUO_SECURITY = "duo_security"
    EA_ORIGIN = "ea_origin"
    EBAY = "ebay"
    ELEMENT = "element"
    ENTERPRISE = "enterprise"
    EPIC_GAMES = "epic_games"
    ETSY = "etsy"
    EVERNOTE = "evernote"
    FACEBOOK = "facebook"
    FAWRY = "fawry"
    FC_BARCELONA_DIGITAL_ID = "fc_barcelona_digital_id"
    FEISHU = "feishu"
    FIGMA = "figma"
    FITBIT = "fitbit"
    FLIPKART = "flipkart"
    FLUTTERWAVE = "flutterwave"
    FORGEROCK = "forgerock"
    FRANCE_CONNECT = "france_connect"
    FRONTEGG = "frontegg"
    FTN = "ftn"
    FUSIONAUTH = "fusionauth"
    GARENA = "garena"
    GARMIN = "garmin"
    GCASH = "gcash"
    GERMAN_EID = "german_eid"
    GIGACHAT = "gigachat"
    GITHUB = "github"
    GITLAB = "gitlab"
    GLITCH = "glitch"
    GLOBO = "globo"
    GLUU_SERVER = "gluu_server"
    GOOGLE = "google"
    GOOGLE_GEMINI = "google_gemini"
    GOOGLE_WORKSPACE = "google_workspace"
    GOOGLE_WORKSPACE_SAML = "google_workspace_saml"
    GOTO = "goto"
    GOVUK_ONE_LOGIN = "govuk_one_login"
    GOVUK_VERIFY = "govuk_verify"
    GRAB = "grab"
    GROQ = "groq"
    GULF_TALENTS = "gulf_talents"
    HEROKU = "heroku"
    HUAWEI_ID = "huawei_id"
    HUGGING_FACE = "hugging_face"
    IBM_SECURITY_VERIFY = "ibm_security_verify"
    IBM_TIVOLI_ACCESS = "ibm_tivoli_access"
    IDIN = "idin"
    ID_AUSTRIA = "id_austria"
    IFlyTEK = "iflytek"
    IHEARTRADIO = "iheartradio"
    INDIA_STACK_AA = "india_stack_aa"
    INSTAGRAM = "instagram"
    ITSME = "itsme"
    JACO = "jaco"
    JD_COM = "jd_com"
    JIO = "jio"
    JUMIA = "jumia"
    JUMIO = "jumio"
    JUMPCLOUD = "jumpcloud"
    KAKAOBANK = "kakaobank"
    KAKAOTALK = "kakaotalk"
    KEYCLOAK = "keycloak"
    KEYCLOAK_EU = "keycloak_eu"
    KUAISHOU = "kuaishou"
    LARK = "lark"
    LAZADA = "lazada"
    LDAP = "ldap"
    LINE = "line"
    LINEAR = "linear"
    LINE_BANK = "line_bank"
    LINKEDIN = "linkedin"
    LIVEME = "liveme"
    MAF_CARREFOUR = "maf_carrefour"
    MAIL_RU = "mail_ru"
    MASTODON = "mastodon"
    MATRIX = "matrix"
    MATTERMOST = "mattermost"
    MEDIUM = "medium"
    MERCADO_LIBRE = "mercado_libre"
    META = "meta"
    MICROSOFT = "microsoft"
    MICROSOFT_365 = "microsoft_365"
    MICROSOFT_ENTRA_EXTERNAL_ID = "microsoft_entra_external_id"
    MICROSOFT_ENTRA_ID = "microsoft_entra_id"
    MICROSOFT_TEAMS = "microsoft_teams"
    MINIMAX = "minimax"
    MISTRAL = "mistral"
    MITID = "mitid"
    MIXI = "mixi"
    MOBILE_CONNECT_GSMA = "mobile_connect_gsma"
    MOMO = "momo"
    MOONSHOT_AI = "moonshot_ai"
    MX = "mx"
    MY_WORLD = "my_world"
    M_PESA = "m_pesa"
    NAFS = "nafs"
    NAVER = "naver"
    NEQUI = "nequi"
    NETIQ = "netiq"
    NETLIFY = "netlify"
    NHS_LOGIN = "nhs_login"
    NINTENDO = "nintendo"
    NOON = "noon"
    NOTION = "notion"
    NPM = "npm"
    NUBANK = "nubank"
    ODNOKLASSNIKI = "odnoklassniki"
    OKTA = "okta"
    ONELOGIN = "onelogin"
    ONFIDO = "onfido"
    OPAY = "opay"
    OPENAI = "openai"
    OPENID_CONNECT = "openid_connect"
    ORACLE_IDENTITY_CLOUD = "oracle_identity_cloud"
    OXXO = "oxxo"
    PANDORA = "pandora"
    PAYMAYA = "paymaya"
    PAYPAL = "paypal"
    PAYTABS = "paytabs"
    PAYTM = "paytm"
    PELOTON = "peloton"
    PERISCOPE = "periscope"
    PERPLEXITY = "perplexity"
    PERSONAL_PAY = "personal_pay"
    PHONEPE = "phonepe"
    PICPAY = "picpay"
    PING_FEDERATE = "ping_federate"
    PING_ONE = "ping_one"
    PLAID = "plaid"
    PLAYSTATION = "playstation"
    POSTEID = "posteid"
    QQ = "qq"
    QWEN = "qwen"
    RAIFFEISEN = "raiffeisen"
    RAKBANK = "rakbank"
    RAKUTEN = "rakuten"
    RAPPI = "rappi"
    RED_HAT_SSO = "red_hat_sso"
    RENREN = "renren"
    REPLIT = "replit"
    RIOT_GAMES = "riot_games"
    ROCKET_CHAT = "rocket_chat"
    RSA_SECURID_ACCESS = "rsa_securid_access"
    SAILPOINT = "sailpoint"
    SALESFORCE = "salesforce"
    SAML = "saml"
    SAMSUNG = "samsung"
    SAP_CLOUD_IDENTITY = "sap_cloud_identity"
    SBERBANK_ONLINE = "sberbank_online"
    SBER_AI = "sber_ai"
    SECUREAUTH = "secureauth"
    SHIBBOLETH = "shibboleth"
    SHOPEE = "shopee"
    SHOPIFY = "shopify"
    SIGNAL = "signal"
    SIMPLE_SAML_PHP = "simple_saml_php"
    SIRIUSXM = "siriusxm"
    SKYPE = "skype"
    SLACK = "slack"
    SMART_ID = "smart_id"
    SNAPCHAT = "snapchat"
    SOCIAL = "social"
    SOUNDCLOUD = "soundcloud"
    SPEI = "spei"
    SPID = "spid"
    SQUARE = "square"
    STACK_OVERFLOW = "stack_overflow"
    STC_PAY = "stc_pay"
    STEAM = "steam"
    STRAVA = "strava"
    STRIPE_CONNECT = "stripe"
    SUPER_TOKENS = "super_tokens"
    SWISSID = "swissid"
    TAMARA = "tamara"
    TANGO = "tango"
    TAOBAO = "taobao"
    TELDA = "telda"
    TELEGRAM = "telegram"
    TENCENT_HUNYUAN = "tencent_hunyuan"
    THREADS = "threads"
    THREEMA = "threema"
    TIDAL = "tidal"
    TIKTOK = "tiktok"
    TINKOFF = "tinkoff"
    TMALL = "tmall"
    TOGETHER_AI = "together_ai"
    TOSS = "toss"
    TOUCH_N_GO = "touch_n_go"
    TRUEID = "trueid"
    TRULIOO = "trulioo"
    TWITCH = "twitch"
    TWITTER = "twitter"
    UBISOFT = "ubisoft"
    UNIONPAY = "unionpay"
    UOL = "uol"
    VERCEL = "vercel"
    VERIFIED_ME = "verified_me"
    VIBER = "viber"
    VKONTAKTE = "vkontakte"
    VMWARE_WORKSPACE_ONE = "vmware_workspace_one"
    WECHAT = "wechat"
    WECOM = "wecom"
    WEIBO = "weibo"
    WHATSAPP = "whatsapp"
    WIRE = "wire"
    WOOCOMMERCE = "woocommerce"
    WORDPRESS = "wordpress"
    WORKOS = "workos"
    WSO2_IDENTITY_SERVER = "wso2_identity_server"
    WUZZUF = "wuzzuf"
    XBOX = "xbox"
    XIAOHONGSHU = "xiaohongshu"
    XIAOMI = "xiaomi"
    YAHOO = "yahoo"
    YAHOO_JAPAN = "yahoo_japan"
    YAMMER = "yammer"
    YANDEX = "yandex"
    YODLEE = "yodlee"
    YOUNOW = "younow"
    YOUTUBE = "youtube"
    YOUTUBE_MUSIC = "youtube_music"
    ZALO = "zalo"
    ZHIHU = "zhihu"
    ZHIPU_AI = "zhipu_ai"
    ZITADEL = "zitadel"
    ZOOM = "zoom"

# ==============================================================================
# AUTHORIZATION MODELS
# ==============================================================================


class AuthorizationModel(str, Enum):
    """Authorization model types."""
    RBAC = "rbac"
    ABAC = "abac"
    REBAC = "rebac"
    POLICY_ENGINE = "policy_engine"
# ==============================================================================
# PASSWORD HASH ALGORITHMS
# ==============================================================================


class PasswordHashAlgorithm(str, Enum):
    """Password hashing algorithms."""
    BCRYPT = "bcrypt"
    ARGON2 = "argon2"
    SCRYPT = "scrypt"
    PBKDF2 = "pbkdf2"
# ==============================================================================
# TYPE ALIASES
# ==============================================================================
# User ID type
UserID = str
# Client ID type
ClientID = str
# Token string type
TokenString = str
# Scope string type
ScopeString = str
# Session ID type
SessionID = str
# Provider name type
ProviderName = str
# Configuration dictionary type
ConfigDict = dict[str, Any]
