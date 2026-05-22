"""
TalonResponse - Configuration
config/settings.py - Settings, environment variables, .env file loading

Author  : Rayyan Umair
Date    : 2026-05-22
Purpose : Centralised configuration for TalonResponse. All settings are
          read from environment variables or a .env file with sensible
          defaults. Every setting is documented. Nothing is hardcoded
          anywhere else in the codebase - always import from here.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/TalonResponse

"Verify the threat. Execute the isolation. Preserve the evidence."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# -- Standard Library ---------------------------------------------------------
from pathlib import Path
from typing import List, Optional

# -- Third Party --------------------------------------------------------------
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# -- Base Paths ---------------------------------------------------------------

BASE_DIR  = Path(__file__).resolve().parent.parent
DATA_DIR  = BASE_DIR / "data"
LOGS_DIR  = BASE_DIR / "logs"
CASES_DIR = DATA_DIR / "cases"

DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
CASES_DIR.mkdir(exist_ok=True)


# -- Settings -----------------------------------------------------------------

class Settings(BaseSettings):
    """
    All TalonResponse configuration.
    Values are loaded from environment variables or .env file.
    Defaults are production-safe and work out of the box.
    """

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -- Application ----------------------------------------------------------

    app_name: str = Field(
        default="TalonResponse",
        description="Application name shown in logs and API responses",
    )
    app_version: str = Field(
        default="1.0.0",
        description="Application version",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level: DEBUG, INFO, WARNING, ERROR",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode - verbose logging",
    )

    # -- Server ---------------------------------------------------------------

    host: str = Field(
        default="0.0.0.0",
        description="Host to bind the FastAPI server",
    )
    port: int = Field(
        default=8005,
        description="Port to bind the FastAPI server - TalonResponse=8005",
    )

    # -- ZeroMQ Transport -----------------------------------------------------

    zmq_alert_subscriber_address: str = Field(
        default="tcp://127.0.0.1:5556",
        description="ZeroMQ address to subscribe to - receives critical alerts from SIEMulate and AD-Audit",
    )
    zmq_recv_timeout_ms: int = Field(
        default=1000,
        description="ZeroMQ receive timeout in milliseconds - controls shutdown responsiveness",
    )
    zmq_queue_maxsize: int = Field(
        default=1000,
        description="Maximum items in the internal alert queue before backpressure",
    )

    # -- Playbook Engine ------------------------------------------------------

    playbook_dir: str = Field(
        default=str(BASE_DIR / "playbooks"),
        description="Directory containing YAML playbook files",
    )
    playbook_hot_reload: bool = Field(
        default=True,
        description="Reload playbooks from disk when files change - no restart required",
    )
    playbook_reload_interval: int = Field(
        default=60,
        description="Seconds between playbook reload checks",
    )

    # -- Forensic Triage ------------------------------------------------------

    case_file_storage_dir: str = Field(
        default=str(CASES_DIR),
        description="Directory where immutable Markdown case files are written",
    )
    evidence_hash_algorithm: str = Field(
        default="sha256",
        description="Hash algorithm for evidence integrity chains - sha256 or sha512",
    )
    triage_timeout_seconds: int = Field(
        default=30,
        description="Maximum seconds allowed for a forensic triage run before timeout",
    )

    # -- Isolation Signing ----------------------------------------------------

    isolation_signing_key: str = Field(
        default="change-this-to-a-secure-hmac-key-2026",
        description="HMAC signing key for isolation payloads dispatched to endpoint agents - MUST be changed in production",
    )
    isolation_token_expiry_seconds: int = Field(
        default=300,
        description="Seconds before a signed isolation token expires",
    )

    # -- NetRaptor Ecosystem APIs ---------------------------------------------

    ad_audit_api_url: str = Field(
        default="http://localhost:8004",
        description="AD-Audit API base URL - account lockdown directives sent here",
    )
    siemulate_api_url: str = Field(
        default="http://localhost:8002",
        description="SIEMulate API base URL - case status updates sent here",
    )
    go_agent_port: int = Field(
        default=9000,
        description="Port the Go endpoint isolation agent listens on",
    )
    api_timeout_seconds: int = Field(
        default=10,
        description="Seconds before an outbound API call times out",
    )
    enrichment_enabled: bool = Field(
        default=False,
        description="Enable live callbacks to AD-Audit and SIEMulate - False for standalone mode",
    )

    # -- Storage --------------------------------------------------------------

    db_path: str = Field(
        default=str(DATA_DIR / "talonresponse.duckdb"),
        description="Path to DuckDB case index database",
    )
    retention_days: int = Field(
        default=365,
        description="Days to retain case records in DuckDB - case files on disk are never deleted",
    )

    # -- WebSocket ------------------------------------------------------------

    ws_heartbeat_interval: int = Field(
        default=30,
        description="Seconds between WebSocket heartbeat pings",
    )
    ws_max_connections: int = Field(
        default=50,
        description="Maximum concurrent WebSocket connections",
    )

    # -- AI Layer -------------------------------------------------------------

    ai_enabled: bool = Field(
        default=False,
        description="Master switch for AI features",
    )
    ai_provider: Optional[str] = Field(
        default=None,
        description="AI provider: anthropic | openai | gemini | groq | ollama | None",
    )
    ai_api_key: Optional[str] = Field(
        default=None,
        description="API key for the chosen AI provider",
    )
    ai_model: Optional[str] = Field(
        default=None,
        description="Model override - uses provider default if not set",
    )
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for Ollama local AI server",
    )
    ollama_model: str = Field(
        default="llama3",
        description="Ollama model name for local AI",
    )

    # -- Security -------------------------------------------------------------

    secret_key: str = Field(
        default="change-this-in-production-talonresponse-secret-key-2026",
        description="Secret key for JWT signing - MUST be changed in production",
    )
    allow_anonymous: bool = Field(
        default=True,
        description="Allow unauthenticated API access - True for local-only deployments",
    )

    # -- Validators -----------------------------------------------------------

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v = v.upper()
        if v not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return v

    @field_validator("evidence_hash_algorithm")
    @classmethod
    def validate_hash_algorithm(cls, v: str) -> str:
        valid = {"sha256", "sha512"}
        v = v.lower()
        if v not in valid:
            raise ValueError(f"evidence_hash_algorithm must be one of {valid}")
        return v

    @field_validator("ai_provider")
    @classmethod
    def validate_ai_provider(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        valid = {"anthropic", "openai", "gemini", "groq", "ollama"}
        v = v.lower()
        if v not in valid:
            raise ValueError(f"ai_provider must be one of {valid}")
        return v

    # -- Derived Properties ---------------------------------------------------

    @property
    def cases_path(self) -> Path:
        p = Path(self.case_file_storage_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def playbook_path(self) -> Path:
        return Path(self.playbook_dir)

    @property
    def is_ai_configured(self) -> bool:
        if not self.ai_enabled:
            return False
        if self.ai_provider == "ollama":
            return True
        return bool(self.ai_api_key)

    @property
    def effective_model(self) -> Optional[str]:
        if self.ai_model:
            return self.ai_model
        defaults = {
            "anthropic": "claude-haiku-4-5-20251001",
            "openai":    "gpt-4o",
            "gemini":    "gemini-2.0-flash",
            "groq":      "llama-3.1-8b-instant",
            "ollama":    self.ollama_model,
        }
        return defaults.get(self.ai_provider or "", None)


# -- .env.example Generator ---------------------------------------------------

def generate_env_example() -> None:
    lines = [
        "# ===========================================================================",
        "# TalonResponse - Environment Configuration",
        "# Copy this file to .env and fill in your values",
        "# Built by Rayyan Umair",
        "# Verify the threat. Execute the isolation. Preserve the evidence.",
        "# ===========================================================================",
        "",
        "# -- Application -----------------------------------------------------",
        "LOG_LEVEL=INFO",
        "DEBUG=false",
        "",
        "# -- Server ----------------------------------------------------------",
        "HOST=0.0.0.0",
        "PORT=8005",
        "",
        "# -- ZeroMQ ----------------------------------------------------------",
        "ZMQ_ALERT_SUBSCRIBER_ADDRESS=tcp://127.0.0.1:5556",
        "",
        "# -- NetRaptor Ecosystem APIs ----------------------------------------",
        "AD_AUDIT_API_URL=http://localhost:8004",
        "SIEMULATE_API_URL=http://localhost:8002",
        "GO_AGENT_PORT=9000",
        "ENRICHMENT_ENABLED=false",
        "",
        "# -- Isolation Signing -----------------------------------------------",
        "# CHANGE THIS to a secure random string in production",
        "ISOLATION_SIGNING_KEY=change-this-to-a-secure-hmac-key-2026",
        "",
        "# -- Storage ----------------------------------------------------------",
        "DB_PATH=./data/talonresponse.duckdb",
        "CASE_FILE_STORAGE_DIR=./data/cases",
        "RETENTION_DAYS=365",
        "",
        "# -- AI Layer ---------------------------------------------------------",
        "AI_ENABLED=false",
        "# AI_PROVIDER=groq",
        "# AI_API_KEY=your-api-key-here",
        "",
        "# -- Security ---------------------------------------------------------",
        "SECRET_KEY=change-this-in-production-talonresponse-secret-key-2026",
        "ALLOW_ANONYMOUS=true",
        "",
    ]
    env_example = BASE_DIR / ".env.example"
    env_example.write_text("\n".join(lines))
    print(f"[+] Written environment template to {env_example}")


if __name__ == "__main__":
    generate_env_example()
    settings = Settings()
    print(f"\nLoaded settings:")
    print(f"  Port              : {settings.port}")
    print(f"  ZMQ address       : {settings.zmq_alert_subscriber_address}")
    print(f"  DB path           : {settings.db_path}")
    print(f"  Cases dir         : {settings.case_file_storage_dir}")
    print(f"  Playbook dir      : {settings.playbook_dir}")
    print(f"  Enrichment        : {settings.enrichment_enabled}")
    print(f"  AI enabled        : {settings.ai_enabled}")
    print(f"  Log level         : {settings.log_level}")