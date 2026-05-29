from pydantic import BaseModel, Field
from typing import Optional


class AnalysisRequest(BaseModel):
    url: str
    author: str = "@rtlphishletgen"
    use_ai: bool = False
    custom_name: Optional[str] = None


class DiscoveredDomain(BaseModel):
    domain: str
    subdomains: list[str] = Field(default_factory=list)
    is_auth_related: bool = False
    is_cdn: bool = False
    is_cdn_static: bool = False  # e.g. oktacdn.com, aadcdn.msftauth.net


class LoginFormField(BaseModel):
    field_name: str
    field_type: str
    field_id: Optional[str] = None
    placeholder: Optional[str] = None
    label: Optional[str] = None
    field_value: Optional[str] = None  # For hidden inputs (CSRF tokens etc.)


class LoginFormInfo(BaseModel):
    action_url: str
    method: str = "POST"
    fields: list[LoginFormField] = Field(default_factory=list)
    submit_button_text: Optional[str] = None
    is_spa_form: bool = False  # True if form is JS-rendered, not a real <form>


class AuthFlowStep(BaseModel):
    step_number: int
    url: str
    method: str = "GET"
    content_type: Optional[str] = None
    is_redirect: bool = False
    status_code: int = 200
    sets_cookies: list[str] = Field(default_factory=list)
    description: str = ""


class AnalysisResult(BaseModel):
    target_url: str
    base_domain: str
    discovered_domains: list[DiscoveredDomain] = Field(default_factory=list)
    login_forms: list[LoginFormInfo] = Field(default_factory=list)
    auth_flow_steps: list[AuthFlowStep] = Field(default_factory=list)
    cookies_observed: dict[str, list[str]] = Field(default_factory=dict)
    redirect_chain: list[str] = Field(default_factory=list)
    post_login_url: Optional[str] = None
    login_path: str = "/"
    has_mfa: bool = False
    has_kmsi: bool = False  # "Keep me signed in" prompt detected
    uses_javascript_auth: bool = False
    auth_api_endpoints: list[str] = Field(default_factory=list)
    page_title: str = ""
    suggested_name: str = ""
    # Advanced detection results
    sri_integrity_hashes: list[str] = Field(default_factory=list)  # subresource integrity hashes found
    x_frame_options: Optional[str] = None  # DENY / SAMEORIGIN if present
    cors_origins: list[str] = Field(default_factory=list)
    oidc_redirect_uris: list[str] = Field(default_factory=list)
