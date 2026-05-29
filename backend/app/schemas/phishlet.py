from pydantic import BaseModel, Field
from typing import Optional, Union, Literal


# ---------------------------------------------------------------------------
# Phishlet Params (variable substitution e.g. {okta_orga})
# ---------------------------------------------------------------------------

class PhishletParam(BaseModel):
    """A user-defined variable that can be referenced as {name} throughout the phishlet."""
    name: str
    default: str = ""
    required: bool = False


# ---------------------------------------------------------------------------
# Proxy Hosts
# ---------------------------------------------------------------------------

class ProxyHost(BaseModel):
    phish_sub: str = ""
    orig_sub: str = ""
    domain: str
    session: bool = True
    is_landing: bool = False
    auto_filter: bool = True


# ---------------------------------------------------------------------------
# Sub Filters (content rewriting rules)
# ---------------------------------------------------------------------------

class SubFilter(BaseModel):
    """A match-and-replace rule applied to proxied responses.

    The ``search`` field is a regex-capable string that Evilginx will look for
    in the response body. The ``replace`` field is the substitution.
    ``triggers_on`` specifies which proxy host's responses are filtered.

    Advanced sub_filters (from Wavestone research) include:
    - JS-level URL rewriting for CORS bypass
    - Integrity hash stripping (SRI)
    - Redirect URI manipulation
    - X-Frame-Options removal
    """
    triggers_on: str
    orig_sub: str = ""
    domain: str
    search: str = "{hostname}"
    replace: str = "{hostname}"
    mimes: list[str] = Field(
        default_factory=lambda: [
            "text/html",
            "application/json",
            "application/javascript",
            "text/javascript",
        ]
    )
    redirect_only: bool = False


# ---------------------------------------------------------------------------
# Auth Tokens
# ---------------------------------------------------------------------------

class AuthTokenCookie(BaseModel):
    domain: str
    keys: list[str]
    type: Literal["cookie"] = "cookie"


class AuthTokenBody(BaseModel):
    domain: str
    path: str
    name: str
    search: str
    type: Literal["body"] = "body"


class AuthTokenHeader(BaseModel):
    domain: str
    path: str
    name: str
    header: str
    type: Literal["http"] = "http"


AuthToken = Union[AuthTokenCookie, AuthTokenBody, AuthTokenHeader]


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

class CredentialField(BaseModel):
    """A credential capture definition.

    ``type`` can be:
    - ``post`` — captured from POST form data
    - ``json`` — captured from a JSON request body using a regex on the raw body
    - ``header`` — captured from an HTTP header
    """
    key: str
    search: str = "(.*)"
    type: Literal["post", "json", "header"] = "post"


class Credentials(BaseModel):
    username: Optional[CredentialField] = None
    password: Optional[CredentialField] = None
    custom: Optional[list[CredentialField]] = None


# ---------------------------------------------------------------------------
# Force Post
# ---------------------------------------------------------------------------

class ForcePostSearch(BaseModel):
    key: str
    search: str = ".*"


class ForcePostForce(BaseModel):
    """A key-value pair that Evilginx will inject into the POST request.

    Common uses:
    - ``LoginOptions: 1``  (auto-accept KMSI prompt on Azure/Okta)
    - ``rememberMFA: true`` (auto-accept MFA persistence on Azure)
    - CSRF token passthrough values
    """
    key: str
    value: str


class ForcePost(BaseModel):
    """Defines a POST path that Evilginx will intercept and optionally modify.

    ``force`` is **required** by Evilginx — even if no forced values are
    needed, it must be present as an empty list ``[]``.
    """
    path: str
    search: list[ForcePostSearch] = Field(default_factory=list)
    force: list[ForcePostForce] = Field(default_factory=list)
    type: Literal["post"] = "post"


# ---------------------------------------------------------------------------
# JS Inject
# ---------------------------------------------------------------------------

class JsInject(BaseModel):
    """JavaScript to inject into proxied pages.

    Advanced uses (from Wavestone research):
    - MFA enrollment automation (enumerate authenticators → redirect to setup → exfil QR code)
    - Frame buster bypass (self===top, target=_top removal)
    - Decoy page redirect after auth completion
    - Dynamic URL rewriting for CORS-bypassed scripts
    """
    trigger_domains: list[str] = Field(default_factory=list)
    trigger_paths: list[str] = Field(default_factory=list)
    trigger_params: list[str] = Field(default_factory=list)
    script: str = ""


# ---------------------------------------------------------------------------
# Login Config
# ---------------------------------------------------------------------------

class LoginConfig(BaseModel):
    domain: str
    path: str = "/"


# ---------------------------------------------------------------------------
# Phishlet (root model)
# ---------------------------------------------------------------------------

class Phishlet(BaseModel):
    """Complete Evilginx v3 phishlet definition.

    Supports all sections: params, proxy_hosts, sub_filters, auth_tokens,
    credentials, auth_urls, login, force_post, js_inject, redirect_url.
    """
    name: str
    author: str = "@rtlphishletgen"
    min_ver: str = "3.2.0"
    params: list[PhishletParam] = Field(default_factory=list)
    proxy_hosts: list[ProxyHost] = Field(default_factory=list)
    sub_filters: list[SubFilter] = Field(default_factory=list)
    auth_tokens: list[AuthToken] = Field(default_factory=list)
    credentials: Credentials = Field(default_factory=Credentials)
    auth_urls: list[str] = Field(default_factory=list)
    login: LoginConfig
    force_post: list[ForcePost] = Field(default_factory=list)
    js_inject: list[JsInject] = Field(default_factory=list)
    redirect_url: Optional[str] = None


# ---------------------------------------------------------------------------
# API Response
# ---------------------------------------------------------------------------

class PhishletGenerateResponse(BaseModel):
    yaml_content: str
    phishlet: Phishlet
    warnings: list[str] = Field(default_factory=list)
    suggestions: list[str] = Field(default_factory=list)
