"""Application configuration.

All settings are read from environment variables with the ``MAILTESTER_``
prefix.  A ``.env`` file in the project root (next to ``pyproject.toml``)
is loaded automatically at import time if ``python-dotenv`` is installed.

This module is the **single source of truth** for configuration.  No other
module should read ``os.environ`` directly -- always use ``settings.<key>``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# Load .env file if python-dotenv is available (optional dependency).
try:
    from dotenv import load_dotenv

    _env_file = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(_env_file)
except ImportError:
    pass


def _env(key: str, default: str = "") -> str:
    """Read ``MAILTESTER_<key>`` from the environment."""
    return os.environ.get(f"MAILTESTER_{key}", default)


@dataclass
class Settings:
    """Centralized configuration.  All values come from env vars."""

    # ── Paths ─────────────────────────────────────────────────────
    base_dir: Path = field(
        default_factory=lambda: Path(__file__).resolve().parent.parent
    )

    @property
    def data_dir(self) -> Path:
        return Path(_env("DATA_DIR", str(self.base_dir / "data")))

    @property
    def eml_dir(self) -> Path:
        return self.data_dir / "emails"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "mail_tester.db"

    # ── SMTP Server ───────────────────────────────────────────────
    smtp_host: str = field(default_factory=lambda: _env("SMTP_HOST", "0.0.0.0"))
    smtp_port: int = field(default_factory=lambda: int(_env("SMTP_PORT", "2525")))
    smtp_domain: str = field(
        default_factory=lambda: _env("SMTP_DOMAIN", "mail-tester.phishing.click")
    )

    # ── Web Server ────────────────────────────────────────────────
    web_host: str = field(default_factory=lambda: _env("WEB_HOST", "0.0.0.0"))
    web_port: int = field(default_factory=lambda: int(_env("WEB_PORT", "31337")))

    # ── Analysis ──────────────────────────────────────────────────
    link_check_timeout: float = field(
        default_factory=lambda: float(_env("LINK_CHECK_TIMEOUT", "5.0"))
    )
    max_links_to_check: int = field(
        default_factory=lambda: int(_env("MAX_LINKS_TO_CHECK", "20"))
    )
    dnsbl_timeout: float = field(
        default_factory=lambda: float(_env("DNSBL_TIMEOUT", "3.0"))
    )
    dns_resolver: str = field(
        default_factory=lambda: _env("DNS_RESOLVER", "8.8.8.8")
    )

    # ── LLM ───────────────────────────────────────────────────────
    llm_provider: str = field(
        default_factory=lambda: _env("LLM_PROVIDER", "none")
    )
    llm_model: str = field(default_factory=lambda: _env("LLM_MODEL"))
    chat_timeout: float = field(
        default_factory=lambda: float(_env("CHAT_TIMEOUT", "60.0"))
    )
    ollama_url: str = field(
        default_factory=lambda: _env("OLLAMA_URL", "http://localhost:11434")
    )
    openai_api_key: str = field(default_factory=lambda: _env("OPENAI_API_KEY"))
    anthropic_api_key: str = field(
        default_factory=lambda: _env("ANTHROPIC_API_KEY")
    )
    malwarebytes_api_key: str = field(
        default_factory=lambda: _env("MALWAREBYTES_API_KEY")
    )
    malwarebytes_api_url: str = field(
        default_factory=lambda: _env(
            "MALWAREBYTES_API_URL",
            "https://api.malwarebytes.com/scamguard/v1",
        )
    )


settings = Settings()
