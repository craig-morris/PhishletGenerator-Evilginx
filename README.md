# RTLPhishletGenerator v2.0

Automated Evilginx Phishlet Generator for Authorized Red Team Engagements — **Wavestone-Grade Advanced Techniques**.

## Overview

RTLPhishletGenerator v2.0 analyzes target login pages and generates production-ready Evilginx v3 phishlet YAML configurations using techniques from the [Wavestone "Pushing Evilginx to its Limit"](https://www.riskinsight-wavestone.com/en/2025/07/phishing-pushing-evilginx-to-its-limit/) research. It uses Playwright browser automation to map authentication flows, detect login forms, capture cookies, and discover all involved domains — then produces a complete phishlet with CORS bypass, SRI stripping, MFA enrollment automation, frame buster bypass, and optional AI refinement.

**This tool is designed exclusively for authorized red team and purple team security testing engagements. All users must have proper NDA and written authorization.**

## Features

- **Platform Fingerprinting** — Automatic detection of Okta, Azure/Microsoft 365, Google, Instagram with platform-specific phishlet templates
- **Advanced `sub_filters`** — CORS bypass (redirectUri rewriting), SRI integrity hash stripping, X-Frame-Options removal, frame buster bypass (self===top, target=_top), OIDC redirect URI validation fix
- **Multi-step `js_inject`** — MFA enrollment automation (enumerate authenticators → redirect to setup → exfil QR code), decoy page redirects after auth, frame buster bypass injection
- **`params` Variable Substitution** — Okta phishlets use `{okta_orga}` for tenant names, making phishlets reusable across Okta organizations
- **`force_post` with `force` Field** — KMSI auto-accept (`LoginOptions: 1`), MFA persistence (`rememberMFA: true`), CSRF token passthrough — always includes the required `force` field
- **`credentials` with `type: json`** — Okta uses JSON body authentication; the generator correctly sets `type: json` with regex search patterns
- **Automated URL Analysis** — Playwright-powered browser analysis detects login forms, authentication flows, cookies, redirect chains, SRI hashes, X-Frame-Options headers, OIDC redirect URIs, and KMSI prompts
- **AI Enhancement (Optional)** — LLM integration via litellm for improved accuracy. Supports cloud providers (OpenAI, Anthropic, DeepSeek) and local providers (Ollama, LM Studio). AI is trained on Wavestone-grade advanced techniques.
- **Built-in Validation** — Schema validation and cross-section logical checks ensure Evilginx v3 compatibility, including `force` field verification, `params` validation, and proxy_host/login domain consistency
- **YAML Editor** — Full-featured Monaco editor with syntax highlighting for manual fine-tuning
- **Real-time Progress** — WebSocket-based analysis progress with step-by-step feedback
- **Web GUI** — Modern dark-themed interface with wizard workflow (URL input → Analysis → Review → Editor)
- **Phishlet Library** — Save, organize, and manage generated phishlets
- **Cookie Intelligence** — Case-insensitive matching against 60+ known session cookie names across 17+ platforms

## What's New in v2.0

Based on the [Wavestone "Pushing Evilginx to its Limit"](https://www.riskinsight-wavestone.com/en/2025/07/phishing-pushing-evilginx-to-its-limit/) research:

- **Platform fingerprinting engine** — Auto-detects Okta, Azure, Google, Instagram and applies the correct template
- **Okta CORS bypass** — `sub_filters` that rewrite `redirectUri` in Okta's JavaScript, preventing CORS errors
- **Okta SRI stripping** — Automatically strips `integrity` hashes from `<script>` tags and disables `mainScript.integrity` checks
- **Okta redirect URI fix** — Rewrites `getIssuerOrigin()` to ensure OIDC callback URIs remain valid
- **Okta MFA enrollment automation** — 3-step `js_inject`: decoy redirect → enumerate authenticators → automate QR code exfiltration
- **Azure frame buster bypass** — `self === top` override, `target="_top"` removal, framework-specific form action fix, X-Frame-Options header stripping
- **Azure KMSI + MFA persistence** — `force_post` entries for `/kmsi` (LoginOptions=1) and `/common/SAS` (rememberMFA=true)
- **`params` support** — Okta phishlets use `{okta_orga}` variable substitution
- **`credentials` type: json** — Okta auth uses JSON API bodies; username captured via regex `"identifier":"([^"]*)"`
- **Advanced scraper detection** — SRI hashes, X-Frame-Options, OIDC redirect URIs, KMSI prompts, CORS origins

## Prerequisites

- Python 3.11+
- Node.js 20+
- Docker (optional, for containerized deployment)

## Quick Start

### Option 1: Docker (Recommended)

```bash
cp .env.example .env
# Edit .env with your AI configuration (optional)
docker-compose up -d
```

Open http://localhost:3000

### Option 2: Manual Setup

```bash
# Backend
cd backend
pip install -r requirements.txt
playwright install chromium
cd ..

# Frontend
cd frontend
npm install
cd ..

# Run both (requires Make)
make dev
```

- Backend: http://localhost:8000 (API docs at /docs)
- Frontend: http://localhost:5173

### Option 3: One-command Install

```bash
make install
make dev
```

## Configuration

Copy `.env.example` to `.env` and configure:

```env
# AI Provider: openai, anthropic, deepseek, ollama, lmstudio, custom
AI_PROVIDER=deepseek

# API Key (required for cloud providers, not needed for Ollama/LM Studio)
AI_API_KEY=your-api-key-here

# Model identifier (litellm format)
AI_MODEL=deepseek/deepseek-chat

# Base URL (optional, auto-configured for Ollama/LM Studio)
# AI_BASE_URL=http://localhost:11434
```

## AI Integration

RTLPhishletGenerator uses [litellm](https://github.com/BerriAI/litellm) for multi-provider AI support. The AI layer is **optional** — the rule-based engine always produces a complete, valid phishlet. AI refines it with:

- Platform-specific cookie/credential knowledge
- Missing subdomain detection
- Cross-domain sub_filter suggestions
- JavaScript injection recommendations for SPA targets
- Improved `force_post` entries with appropriate `force` field values

### Supported AI Providers

| Provider | Configuration | Notes |
|---|---|---|
| **Ollama** (Local) | `AI_PROVIDER=ollama`, `AI_MODEL=ollama/llama3` | No API key needed. Runs locally on port 11434 |
| **LM Studio** (Local) | `AI_PROVIDER=lmstudio`, `AI_MODEL=openai/lmstudio-local` | No API key needed. Runs locally on port 1234 |
| **OpenAI** | `AI_PROVIDER=openai`, `AI_MODEL=openai/gpt-4o` | Requires `AI_API_KEY` |
| **Anthropic** | `AI_PROVIDER=anthropic`, `AI_MODEL=anthropic/claude-sonnet-4-20250514` | Requires `AI_API_KEY` |
| **DeepSeek** | `AI_PROVIDER=deepseek`, `AI_MODEL=deepseek/deepseek-chat` | Requires `AI_API_KEY` |
| **Custom** | `AI_PROVIDER=custom`, `AI_BASE_URL=http://your-server/v1` | Any OpenAI-compatible API |

### Ollama Setup

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull llama3

# Configure .env
AI_PROVIDER=ollama
AI_MODEL=ollama/llama3
# No API key needed - auto-enabled
```

### LM Studio Setup

1. Download and install [LM Studio](https://lmstudio.ai/)
2. Load a model (e.g., Llama 3, Mistral, or any GGUF model)
3. Start the local server (default: http://localhost:1234/v1)
4. Configure `.env`:

```env
AI_PROVIDER=lmstudio
AI_MODEL=openai/lmstudio-local
# No API key needed - auto-enabled
```

## Usage

1. **Enter Target URL** — Provide the login page URL (e.g., `https://login.example.com/signin`)
2. **Review Analysis** — Check discovered domains, login forms, cookies, and auth flow steps
3. **Generate Phishlet** — Click "Generate" to produce the YAML configuration with all required fields including `force_post.force`
4. **Edit & Validate** — Fine-tune in the Monaco editor, run built-in validation
5. **Export** — Download the `.yaml` file and deploy to your Evilginx phishlets directory

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/health` | GET | Health check and AI status |
| `/api/v1/analyze/` | POST | Analyze a target URL |
| `/api/v1/analyze/ws` | WebSocket | Analyze with real-time progress updates |
| `/api/v1/generate/from-url` | POST | End-to-end: analyze + generate phishlet |
| `/api/v1/generate/from-analysis` | POST | Generate from existing analysis data |
| `/api/v1/generate/ai-status` | GET | Check AI provider configuration and connectivity |
| `/api/v1/validate/` | POST | Validate phishlet YAML against Evilginx schema |
| `/api/v1/phishlets/` | GET | List saved phishlets |
| `/api/v1/phishlets/` | POST | Save a phishlet to the library |
| `/api/v1/phishlets/{id}` | GET | Get a specific saved phishlet |
| `/api/v1/phishlets/{id}` | PUT | Update a saved phishlet |
| `/api/v1/phishlets/{id}` | DELETE | Delete a saved phishlet |

Full interactive API documentation available at http://localhost:8000/docs when the backend is running.

## Generated Phishlet Format

The generator produces Evilginx v3.2.0+ compatible YAML with all required fields:

```yaml
name: 'example'
author: '@yourhandle'
min_ver: '3.2.0'

proxy_hosts:
  - {phish_sub: 'www', orig_sub: 'www', domain: 'example.com', session: true, is_landing: true}

sub_filters:
  - {triggers_on: 'www.example.com', orig_sub: 'api', domain: 'example.com',
     search: 'api.example.com', replace: 'api.example.com',
     mimes: [text/html, application/json, application/javascript, text/javascript]}

auth_tokens:
  - domain: '.example.com'
    keys: ['sessionid', 'csrftoken']

credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

auth_urls:
  - '/dashboard'
  - '/login'

login:
  domain: 'example.com'
  path: '/login'

force_post:
  - path: '/login'
    search:
      - {key: 'email', search: '(.*)'}
      - {key: 'password', search: '(.*)'}
      - {key: 'csrf_token', search: '(.*)'}
    force:
      - {key: 'csrf_token', value: ''}
    type: 'post'

js_inject:
  - trigger_domains: ['example.com']
    trigger_paths: ['/login']
    trigger_params: []
    script: |
      // SPA authentication interception
      ...
```

### Key: `force_post.force` Field

The `force` field in `force_post` is **required** by Evilginx. The generator always includes it:
- When CSRF tokens are detected in hidden form fields, they are added to the `force` list with their captured values
- When no forced values are needed, the field is set to an empty list `force: []`
- The built-in validator will flag any `force_post` entry missing the `force` field as invalid

## Project Structure

```
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI application
│   │   ├── config.py        # Settings (pydantic-settings) with multi-provider AI config
│   │   ├── routers/         # API endpoints
│   │   │   ├── analyze.py   # Analysis routes + WebSocket
│   │   │   ├── generate.py  # Generation routes + AI status
│   │   │   ├── validate.py  # Validation routes
│   │   │   └── phishlets.py # Library CRUD routes
│   │   ├── services/        # Core business logic
│   │   │   ├── scraper.py   # Playwright website analysis
│   │   │   ├── analyzer.py  # Analysis orchestration
│   │   │   ├── generator.py # Phishlet YAML generation (with force field)
│   │   │   ├── ai_service.py # LLM integration (multi-provider)
│   │   │   └── validator.py # Phishlet validation (with force field check)
│   │   ├── schemas/         # Pydantic models
│   │   │   ├── phishlet.py  # Phishlet data models (ForcePost, ForcePostForce, etc.)
│   │   │   ├── analysis.py  # Analysis data models
│   │   │   ├── common.py    # Shared types
│   │   │   └── saved.py     # Library storage models
│   │   └── templates/       # Base phishlet YAML template
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/      # React components
│   │   │   ├── URLInput.tsx
│   │   │   ├── AnalysisProgress.tsx
│   │   │   ├── AnalysisReview.tsx
│   │   │   ├── PhishletEditor.tsx
│   │   │   ├── PhishletCard.tsx
│   │   │   └── Layout.tsx
│   │   ├── pages/           # Page components
│   │   │   ├── Home.tsx
│   │   │   ├── Generator.tsx
│   │   │   ├── Library.tsx
│   │   │   └── Settings.tsx
│   │   ├── services/        # API client (axios)
│   │   ├── store/           # Zustand state management
│   │   ├── hooks/           # Custom React hooks
│   │   └── types/           # TypeScript type definitions
│   └── package.json
├── docs/
│   ├── lesson-01-using-rtlphishletgenerator.md
│   └── lesson-02-creating-phishlets-manual.md
├── docker-compose.yml
├── Makefile
└── .env.example
```

## Documentation

- [Lesson 1: Using RTLPhishletGenerator](docs/lesson-01-using-rtlphishletgenerator.md)
- [Lesson 2: Creating Phishlets - Techniques & Best Practices](docs/lesson-02-creating-phishlets-manual.md)

## Tech Stack

**Backend:** Python 3.11+, FastAPI, Playwright, BeautifulSoup4, ruamel.yaml, litellm, Pydantic v2

**Frontend:** TypeScript, React 18, Vite 6, TailwindCSS 4, Monaco Editor, TanStack Query, Zustand

## Known Platform Patterns

The generator includes built-in intelligence for these platforms:

| Platform | Key Cookies | Credential Fields |
|---|---|---|
| Microsoft 365/Azure | ESTSAUTH, ESTSAUTHPERSISTENT, SignInStateCookie | loginfmt, passwd |
| Google | SID, HSID, SSID, APISID, SAPISID | identifier, Passwd |
| Instagram | sessionid, csrftoken, ds_user_id, ig_did | username, enc_password |
| Okta | sid, idx | username, password |
| GitHub | user_session, _gh_sess, logged_in | login, password |
| AWS | aws-creds, aws-userInfo | username, password |
| Facebook | c_user, xs, fr, datr, sb | email, pass |
| Twitter/X | auth_token, ct0, twid | session[username_or_email], session[password] |
| LinkedIn | li_at, JSESSIONID | session_key, session_password |
| Discord | __dcfduid, __sdcfduid | email, password |
| Slack | d, d-s | email, password |

Plus generic session cookie detection for 50+ common patterns.

## Legal Disclaimer

This tool is provided for authorized security testing purposes only. Users must:

1. Have written authorization from the target organization
2. Operate under a valid NDA/SOW for the engagement
3. Comply with all applicable laws and regulations
4. Not use this tool for unauthorized access or malicious purposes

The developers assume no liability for misuse of this tool. By using RTLPhishletGenerator, you agree to use it exclusively within the scope of authorized security assessments.

## Credits

- **Original Author:** JoasASantos — [github.com/JoasASantos](https://github.com/JoasASantos)
- **Edits & Updates:** Cysec Don | cysecdon@gmail.com — [github.com/cysec-don](https://github.com/cysec-don)

## License

Private — Authorized use only under NDA.
