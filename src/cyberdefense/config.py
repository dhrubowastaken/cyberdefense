"""
CyberDefense Configuration Loader
===================================
Loads settings from config.yaml + .env and exposes them as typed Pydantic models.
Environment variables override config.yaml values for sensitive data (API keys).
"""

import os
import logging
from pathlib import Path
from typing import Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# ── Locate project root ─────────────────────────────────────
# Walk up from this file to find config.yaml
_THIS_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parent.parent.parent  # src/cyberdefense/config.py → project root

CONFIG_PATH = _PROJECT_ROOT / "config.yaml"
ENV_PATH = _PROJECT_ROOT / ".env"

# Load .env file (API keys, secrets)
load_dotenv(ENV_PATH)


# ── Pydantic Settings Models ────────────────────────────────

class GeminiSettings(BaseModel):
    model: str = "gemini-3.8-flash"
    temperature: float = 0.2
    max_output_tokens: int = 2048
    api_key: str = Field(default="", description="Loaded from GEMINI_API_KEY env var")


class OllamaSettings(BaseModel):
    model: str = "llama3"
    base_url: str = "http://localhost:11434"
    temperature: float = 0.2


class LLMSettings(BaseModel):
    provider: Literal["gemini", "ollama", "none"] = "gemini"
    gemini: GeminiSettings = GeminiSettings()
    ollama: OllamaSettings = OllamaSettings()


class BruteForceSettings(BaseModel):
    enabled: bool = True
    window_seconds: int = 300
    failed_login_threshold: int = 5
    spray_user_threshold: int = 5
    spray_attempt_threshold: int = 3


class PortScanSettings(BaseModel):
    enabled: bool = True
    window_seconds: int = 60
    unique_port_threshold: int = 10
    rejection_rate_threshold: float = 0.8


class PrivilegeEscalationSettings(BaseModel):
    enabled: bool = True
    high_priv_users: list[str] = ["root", "admin", "SYSTEM", "Administrator"]
    service_accounts: list[str] = ["www-data", "apache", "nginx", "httpd", "nobody"]


class DataExfiltrationSettings(BaseModel):
    enabled: bool = True
    window_seconds: int = 600
    byte_threshold: int = 104857600  # 100MB
    unknown_dest_multiplier: float = 0.5


class DetectionSettings(BaseModel):
    brute_force: BruteForceSettings = BruteForceSettings()
    port_scan: PortScanSettings = PortScanSettings()
    privilege_escalation: PrivilegeEscalationSettings = PrivilegeEscalationSettings()
    data_exfiltration: DataExfiltrationSettings = DataExfiltrationSettings()


class DashboardSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000


class DataSettings(BaseModel):
    log_dir: str = "data"
    cicids_dir: str = "data/cicids"
    synthetic_dir: str = "data/synthetic"
    audit_log: str = "data/audit.jsonl"


class LoggingSettings(BaseModel):
    level: str = "INFO"


class ProjectSettings(BaseModel):
    name: str = "CyberDefense"
    version: str = "0.1.0"


class AppConfig(BaseModel):
    """Root configuration model for the entire application."""
    project: ProjectSettings = ProjectSettings()
    llm: LLMSettings = LLMSettings()
    detection: DetectionSettings = DetectionSettings()
    dashboard: DashboardSettings = DashboardSettings()
    data: DataSettings = DataSettings()
    logging: LoggingSettings = LoggingSettings()


# ── Config Loading ───────────────────────────────────────────

def load_config(config_path: Path | None = None) -> AppConfig:
    """
    Load configuration from YAML file and environment variables.

    Priority:
      1. Environment variables (highest — for secrets like API keys)
      2. config.yaml values
      3. Pydantic defaults (lowest)
    """
    path = config_path or CONFIG_PATH

    # Load YAML if it exists
    raw_config = {}
    if path.exists():
        with open(path) as f:
            raw_config = yaml.safe_load(f) or {}

    # Parse into typed config
    config = AppConfig(**raw_config) if raw_config else AppConfig()

    # Override with environment variables
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    if gemini_key:
        config.llm.gemini.api_key = gemini_key

    ollama_url = os.environ.get("OLLAMA_BASE_URL", "")
    if ollama_url:
        config.llm.ollama.base_url = ollama_url

    # Resolve relative data paths to absolute
    config.data.log_dir = str(_PROJECT_ROOT / config.data.log_dir)
    config.data.cicids_dir = str(_PROJECT_ROOT / config.data.cicids_dir)
    config.data.synthetic_dir = str(_PROJECT_ROOT / config.data.synthetic_dir)
    config.data.audit_log = str(_PROJECT_ROOT / config.data.audit_log)

    return config


def setup_logging(config: AppConfig) -> None:
    """Configure Python logging based on config settings."""
    logging.basicConfig(
        level=getattr(logging, config.logging.level, logging.INFO),
        format="%(asctime)s │ %(name)-25s │ %(levelname)-8s │ %(message)s",
        datefmt="%H:%M:%S",
    )


# ── Singleton Config Instance ────────────────────────────────
# Import this from anywhere: from cyberdefense.config import settings
settings = load_config()
