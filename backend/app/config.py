from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import model_validator
from typing import Optional

# Resolve .env from project root (parent of backend/)
_env_file = Path(__file__).resolve().parent.parent.parent / ".env"


class Settings(BaseSettings):
    # AI Configuration
    # Supported backends:
    #   - OpenAI:        AI_PROVIDER=openai,  AI_API_KEY=sk-...,         AI_MODEL=openai/gpt-4o
    #   - Anthropic:     AI_PROVIDER=anthropic, AI_API_KEY=sk-ant-...,   AI_MODEL=anthropic/claude-sonnet-4-20250514
    #   - DeepSeek:      AI_PROVIDER=deepseek, AI_API_KEY=dsk-...,       AI_MODEL=deepseek/deepseek-chat
    #   - Ollama:        AI_PROVIDER=ollama,   AI_API_KEY= (leave empty), AI_MODEL=ollama/llama3
    #   - LM Studio:     AI_PROVIDER=lmstudio, AI_API_KEY=lm-studio,     AI_MODEL=openai/lmstudio-local
    #   - Custom OpenAI-compatible: AI_PROVIDER=custom, AI_API_KEY=..., AI_MODEL=openai/model-name, AI_BASE_URL=http://...
    ai_provider: str = "deepseek"
    ai_api_key: Optional[str] = None
    ai_model: str = "deepseek/deepseek-chat"
    ai_base_url: Optional[str] = None
    ai_enabled: bool = False

    # Server
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    debug: bool = False

    # Playwright
    playwright_headless: bool = True
    playwright_timeout: int = 30000

    # Evilginx
    evilginx_min_ver: str = "3.2.0"

    model_config = {
        "env_file": str(_env_file),
        "env_file_encoding": "utf-8",
    }

    @model_validator(mode="after")
    def _auto_enable_ai(self) -> "Settings":
        """Auto-enable AI if provider is configured with an API key or is a local provider."""
        if self.ai_api_key or self.ai_provider in ("ollama", "lmstudio"):
            self.ai_enabled = True
        return self

    def get_litellm_params(self) -> dict:
        """Build litellm-compatible parameters based on the AI provider."""
        params: dict = {
            "model": self.ai_model,
            "api_key": self.ai_api_key or "not-needed",
        }

        if self.ai_provider == "ollama":
            params["api_base"] = self.ai_base_url or "http://localhost:11434"
            params["api_key"] = self.ai_api_key or "ollama"
            if not self.ai_model.startswith("ollama/"):
                params["model"] = f"ollama/{self.ai_model}"
        elif self.ai_provider == "lmstudio":
            params["api_base"] = self.ai_base_url or "http://localhost:1234/v1"
            params["api_key"] = self.ai_api_key or "lm-studio"
            if not self.ai_model.startswith("openai/"):
                params["model"] = f"openai/{self.ai_model}"
        elif self.ai_provider == "custom":
            if self.ai_base_url:
                params["api_base"] = self.ai_base_url
        elif self.ai_base_url:
            params["api_base"] = self.ai_base_url

        return params


settings = Settings()
