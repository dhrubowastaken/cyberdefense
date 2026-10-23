#!/usr/bin/env python3
"""
CyberDefense Setup Script
==========================
Interactive CLI tool to configure the CyberDefense project.
Run this once to set up, or re-run anytime to change settings.

Usage:
    python setup.py           # Full interactive setup
    python setup.py --reset   # Reset to defaults and reconfigure
"""

import os
import sys
import yaml
import shutil
from pathlib import Path

# ── ANSI Colors ──────────────────────────────────────────────
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"

BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.yaml"
ENV_PATH = BASE_DIR / ".env"


# ── Default Configuration ────────────────────────────────────
DEFAULT_CONFIG = {
    "project": {
        "name": "CyberDefense",
        "version": "0.1.0",
    },
    "llm": {
        "provider": "gemini",
        "gemini": {
            "model": "gemini-3.5-flash-lite",
            "temperature": 0.2,
            "max_output_tokens": 2048,
        },
        "ollama": {
            "model": "llama3",
            "base_url": "http://localhost:11434",
            "temperature": 0.2,
        },
    },
    "detection": {
        "brute_force": {
            "enabled": True,
            "window_seconds": 300,
            "failed_login_threshold": 5,
            "spray_user_threshold": 5,
            "spray_attempt_threshold": 3,
        },
        "port_scan": {
            "enabled": True,
            "window_seconds": 60,
            "unique_port_threshold": 10,
            "rejection_rate_threshold": 0.8,
        },
        "privilege_escalation": {
            "enabled": True,
            "high_priv_users": ["root", "admin", "SYSTEM", "Administrator"],
            "service_accounts": ["www-data", "apache", "nginx", "httpd", "nobody"],
        },
        "data_exfiltration": {
            "enabled": True,
            "window_seconds": 600,
            "byte_threshold": 104857600,  # 100MB
            "unknown_dest_multiplier": 0.5,
        },
    },
    "dashboard": {
        "host": "127.0.0.1",
        "port": 8000,
    },
    "data": {
        "log_dir": "data",
        "cicids_dir": "data/cicids",
        "synthetic_dir": "data/synthetic",
        "audit_log": "data/audit.jsonl",
    },
    "logging": {
        "level": "INFO",
    },
}


def banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ██████╗██╗   ██╗██████╗ ███████╗██████╗                            ║
║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗                           ║
║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝                           ║
║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗                           ║
║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║                           ║
║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝                           ║
║          ██████╗ ███████╗███████╗███████╗███╗   ██╗███████╗███████╗  ║
║          ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝  ║
║          ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║███████╗█████╗    ║
║          ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║╚════██║██╔══╝    ║
║          ██████╔╝███████╗██║     ███████╗██║ ╚████║███████║███████╗  ║
║          ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝  ║
║                                                                      ║
║  Agentic SOAR-Lite · LLM-Powered Threat Investigation                ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝{RESET}
""")


def prompt_choice(question: str, options: list[str], default: int = 0) -> int:
    """Display a numbered choice menu and return the selected index."""
    print(f"\n{BOLD}{question}{RESET}")
    for i, opt in enumerate(options):
        marker = f"{GREEN}→{RESET}" if i == default else " "
        default_tag = f" {DIM}(default){RESET}" if i == default else ""
        print(f"  {marker} {YELLOW}{i + 1}{RESET}. {opt}{default_tag}")

    while True:
        raw = input(f"\n  {DIM}Enter choice [1-{len(options)}] (press Enter for default): {RESET}").strip()
        if raw == "":
            return default
        try:
            choice = int(raw)
            if 1 <= choice <= len(options):
                return choice - 1
        except ValueError:
            pass
        print(f"  {RED}Invalid choice. Try again.{RESET}")


def prompt_input(question: str, default: str = "", secret: bool = False) -> str:
    """Prompt for text input with an optional default."""
    default_display = f" {DIM}[{default}]{RESET}" if default and not secret else ""
    if secret and default:
        masked = default[:4] + "..." + default[-4:] if len(default) > 8 else "****"
        default_display = f" {DIM}[{masked}]{RESET}"

    raw = input(f"  {BOLD}{question}{default_display}: {RESET}").strip()
    return raw if raw else default


def prompt_number(question: str, default: float, min_val: float = 0, max_val: float = float("inf")) -> float:
    """Prompt for a numeric input with validation."""
    while True:
        raw = input(f"  {BOLD}{question} {DIM}[{default}]{RESET}: ").strip()
        if raw == "":
            return default
        try:
            val = float(raw)
            if min_val <= val <= max_val:
                return val
            print(f"  {RED}Value must be between {min_val} and {max_val}.{RESET}")
        except ValueError:
            print(f"  {RED}Invalid number. Try again.{RESET}")


def prompt_yes_no(question: str, default: bool = True) -> bool:
    """Prompt for a yes/no answer."""
    default_str = "Y/n" if default else "y/N"
    raw = input(f"  {BOLD}{question} {DIM}[{default_str}]{RESET}: ").strip().lower()
    if raw == "":
        return default
    return raw in ("y", "yes", "true", "1")


def section_header(title: str, step: int, total: int):
    """Print a section header."""
    print(f"\n{BLUE}{'─' * 60}{RESET}")
    print(f"{BLUE}{BOLD}  Step {step}/{total}: {title}{RESET}")
    print(f"{BLUE}{'─' * 60}{RESET}")


def configure_llm(config: dict) -> dict:
    """Configure LLM provider settings."""
    section_header("LLM Investigation Agent", 1, 4)

    print(f"""
  {DIM}The LLM agent is what makes CyberDefense special — it investigates
  alerts and produces natural-language analysis reports.{RESET}
""")

    provider_idx = prompt_choice(
        "Which LLM provider do you want to use?",
        [
            f"Google Gemini API {DIM}(Free tier: 15 req/min, needs internet + API key){RESET}",
            f"Ollama (Local) {DIM}(Runs on your machine, fully offline, needs ~8GB RAM){RESET}",
            f"None {DIM}(Skip LLM — rule-based detection only, no investigation reports){RESET}",
        ],
        default=0,
    )

    provider_map = {0: "gemini", 1: "ollama", 2: "none"}
    config["llm"]["provider"] = provider_map[provider_idx]

    env_vars = {}

    if provider_idx == 0:  # Gemini
        print(f"\n  {CYAN}Gemini Configuration:{RESET}")
        print(f"  {DIM}Get your API key from: https://aistudio.google.com/apikey{RESET}\n")

        existing_key = os.environ.get("GEMINI_API_KEY", "")
        api_key = prompt_input("Gemini API Key", default=existing_key, secret=True)
        env_vars["GEMINI_API_KEY"] = api_key

        # Dynamically fetch available non-retired models from Google API
        print(f"  {DIM}Querying Google API for active Gemini models...{RESET}")
        try:
            from cyberdefense.investigation import fetch_available_gemini_models
            available_models = fetch_available_gemini_models(api_key, force_refresh=True)
        except Exception:
            available_models = ["gemini-3.5-flash-lite", "gemini-3-flash-preview", "gemini-3.5-flash"]

        choices = [f"{m} {DIM}(Active on Google API){RESET}" for m in available_models[:4]]
        choices.append("Custom model name")

        model_idx = prompt_choice("Which Gemini model?", choices, default=0)
        if model_idx == len(choices) - 1:
            config["llm"]["gemini"]["model"] = prompt_input("Custom model name")
        else:
            config["llm"]["gemini"]["model"] = available_models[model_idx]

        config["llm"]["gemini"]["temperature"] = prompt_number(
            "Temperature (0.0 = deterministic, 1.0 = creative)",
            default=0.2, min_val=0.0, max_val=2.0,
        )

    elif provider_idx == 1:  # Ollama
        print(f"\n  {CYAN}Ollama Configuration:{RESET}")
        print(f"  {DIM}Make sure Ollama is running: https://ollama.com{RESET}\n")

        config["llm"]["ollama"]["base_url"] = prompt_input(
            "Ollama server URL",
            default="http://localhost:11434",
        )
        env_vars["OLLAMA_BASE_URL"] = config["llm"]["ollama"]["base_url"]

        model_idx = prompt_choice(
            "Which Ollama model?",
            [
                f"llama3 {DIM}(Recommended — good balance of speed and quality){RESET}",
                f"mistral {DIM}(Fast, good for structured output){RESET}",
                f"gemma2 {DIM}(Google's open model){RESET}",
                f"Custom model name",
            ],
            default=0,
        )
        model_names = ["llama3", "mistral", "gemma2", None]
        if model_idx == 3:
            config["llm"]["ollama"]["model"] = prompt_input("Custom model name (must be pulled in Ollama)")
        else:
            config["llm"]["ollama"]["model"] = model_names[model_idx]

        config["llm"]["ollama"]["temperature"] = prompt_number(
            "Temperature (0.0 = deterministic, 1.0 = creative)",
            default=0.2, min_val=0.0, max_val=2.0,
        )

    else:  # None
        print(f"\n  {YELLOW}⚠ LLM disabled. Detection modules will still work but alerts won't")
        print(f"  have LLM-generated investigation reports.{RESET}")

    return env_vars


def configure_detection(config: dict):
    """Configure detection module thresholds."""
    section_header("Detection Thresholds", 2, 4)

    print(f"""
  {DIM}These thresholds control when each detection module fires an alert.
  Lower values = more sensitive (more alerts, possible false positives).
  Higher values = less sensitive (fewer alerts, might miss attacks).{RESET}
""")

    if prompt_yes_no("Use default thresholds? (recommended for first run)", default=True):
        print(f"  {GREEN}✓ Using defaults.{RESET}")
        return

    # Brute Force
    print(f"\n  {MAGENTA}── Brute Force (MITRE T1110) ──{RESET}")
    bf = config["detection"]["brute_force"]
    bf["enabled"] = prompt_yes_no("Enable brute force detection?", default=True)
    if bf["enabled"]:
        bf["window_seconds"] = int(prompt_number(
            "Time window (seconds)", default=300, min_val=30, max_val=3600,
        ))
        bf["failed_login_threshold"] = int(prompt_number(
            "Failed login threshold (per IP per window)", default=5, min_val=1, max_val=1000,
        ))

    # Port Scan
    print(f"\n  {MAGENTA}── Port Scan (MITRE T1046) ──{RESET}")
    ps = config["detection"]["port_scan"]
    ps["enabled"] = prompt_yes_no("Enable port scan detection?", default=True)
    if ps["enabled"]:
        ps["window_seconds"] = int(prompt_number(
            "Time window (seconds)", default=60, min_val=10, max_val=600,
        ))
        ps["unique_port_threshold"] = int(prompt_number(
            "Unique ports threshold (per IP per window)", default=10, min_val=3, max_val=500,
        ))

    # Privilege Escalation
    print(f"\n  {MAGENTA}── Privilege Escalation (MITRE T1068) ──{RESET}")
    pe = config["detection"]["privilege_escalation"]
    pe["enabled"] = prompt_yes_no("Enable privilege escalation detection?", default=True)

    # Data Exfiltration
    print(f"\n  {MAGENTA}── Data Exfiltration (MITRE T1041/T1048) ──{RESET}")
    dx = config["detection"]["data_exfiltration"]
    dx["enabled"] = prompt_yes_no("Enable data exfiltration detection?", default=True)
    if dx["enabled"]:
        dx["window_seconds"] = int(prompt_number(
            "Time window (seconds)", default=600, min_val=60, max_val=3600,
        ))
        mb_threshold = prompt_number(
            "Outbound data threshold (MB)", default=100, min_val=1, max_val=10000,
        )
        dx["byte_threshold"] = int(mb_threshold * 1024 * 1024)


def configure_dashboard(config: dict):
    """Configure dashboard server settings."""
    section_header("Dashboard Settings", 3, 4)

    config["dashboard"]["host"] = prompt_input("Dashboard host", default="127.0.0.1")
    config["dashboard"]["port"] = int(prompt_number(
        "Dashboard port", default=8000, min_val=1024, max_val=65535,
    ))


def configure_general(config: dict):
    """Configure general settings."""
    section_header("General Settings", 4, 4)

    log_idx = prompt_choice(
        "Logging level?",
        ["DEBUG (verbose)", "INFO (recommended)", "WARNING (quiet)", "ERROR (errors only)"],
        default=1,
    )
    log_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
    config["logging"]["level"] = log_levels[log_idx]


def write_config(config: dict):
    """Write configuration to config.yaml."""
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False, indent=2)
    print(f"  {GREEN}✓ Config written to {CONFIG_PATH}{RESET}")


def write_env(env_vars: dict):
    """Write or update .env file with sensitive values."""
    existing = {}

    # Read existing .env if it exists
    if ENV_PATH.exists():
        with open(ENV_PATH, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    existing[key.strip()] = value.strip()

    # Merge new values
    existing.update(env_vars)

    # Write back
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.write("# CyberDefense Environment Variables\n")
        f.write("# Auto-generated by setup.py - do not commit this file!\n\n")
        for key, value in existing.items():
            if value:
                f.write(f"{key}={value}\n")
            else:
                f.write(f"# {key}=\n")

    print(f"  {GREEN}✓ Environment variables written to {ENV_PATH}{RESET}")


def create_directories():
    """Create required data directories."""
    dirs = ["data", "data/cicids", "data/synthetic", "data/combined"]
    for d in dirs:
        path = BASE_DIR / d
        path.mkdir(parents=True, exist_ok=True)
    print(f"  {GREEN}✓ Data directories created.{RESET}")


def print_summary(config: dict):
    """Print a summary of the configuration."""
    llm = config["llm"]
    det = config["detection"]

    print(f"\n{GREEN}{'═' * 60}{RESET}")
    print(f"{GREEN}{BOLD}  ✅ Setup Complete!{RESET}")
    print(f"{GREEN}{'═' * 60}{RESET}")

    print(f"\n  {BOLD}LLM Provider:{RESET}", end=" ")
    if llm["provider"] == "gemini":
        print(f"{CYAN}Google Gemini ({llm['gemini']['model']}){RESET}")
    elif llm["provider"] == "ollama":
        print(f"{CYAN}Ollama Local ({llm['ollama']['model']}){RESET}")
    else:
        print(f"{YELLOW}Disabled{RESET}")

    print(f"\n  {BOLD}Detection Modules:{RESET}")
    modules = {
        "Brute Force (T1110)": det["brute_force"]["enabled"],
        "Port Scan (T1046)": det["port_scan"]["enabled"],
        "Priv Escalation (T1068)": det["privilege_escalation"]["enabled"],
        "Data Exfiltration (T1041)": det["data_exfiltration"]["enabled"],
    }
    for name, enabled in modules.items():
        status = f"{GREEN}✓ Enabled{RESET}" if enabled else f"{RED}✗ Disabled{RESET}"
        print(f"    {status}  {name}")

    print(f"\n  {BOLD}Dashboard:{RESET} http://{config['dashboard']['host']}:{config['dashboard']['port']}")
    print(f"  {BOLD}Config:{RESET} {CONFIG_PATH}")
    print(f"  {BOLD}Log Level:{RESET} {config['logging']['level']}")

    print(f"\n  {DIM}To reconfigure at any time, run: python setup.py{RESET}")
    print(f"  {DIM}To start the system, run: uv run python -m cyberdefense{RESET}")
    print()


def main():
    banner()

    # Check for --reset flag
    reset = "--reset" in sys.argv

    if CONFIG_PATH.exists() and not reset:
        print(f"  {YELLOW}Existing config found at {CONFIG_PATH}{RESET}")
        if not prompt_yes_no("Reconfigure? (No = keep current settings)", default=False):
            print(f"  {GREEN}Keeping current configuration.{RESET}")
            return

    # Start with defaults
    import copy
    config = copy.deepcopy(DEFAULT_CONFIG)

    # Interactive configuration
    env_vars = configure_llm(config)
    configure_detection(config)
    configure_dashboard(config)
    configure_general(config)

    # Write files
    print(f"\n{BLUE}{'─' * 60}{RESET}")
    print(f"{BLUE}{BOLD}  Writing configuration files...{RESET}")
    print(f"{BLUE}{'─' * 60}{RESET}\n")

    write_config(config)
    write_env(env_vars)
    create_directories()
    print_summary(config)


if __name__ == "__main__":
    main()
