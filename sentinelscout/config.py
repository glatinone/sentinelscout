"""Config loader — reads .env and environment variables."""
import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

ENV_FILE = Path(__file__).parent.parent / ".env"
load_dotenv(ENV_FILE)

def get_env(key: str, default: Optional[str] = None) -> Optional[str]:
    return os.getenv(key, default)

# ── API Keys ──────────────────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY = get_env("VIRUSTOTAL_API_KEY", "")
ALIENVAULT_API_KEY = get_env("ALIENVAULT_API_KEY", "")
SHODAN_API_KEY = get_env("SHODAN_API_KEY", "")
OPENAI_API_KEY = get_env("OPENAI_API_KEY", "")

# ── Async client settings ─────────────────────────────────────────────────────
MAX_CONCURRENT = int(get_env("MAX_CONCURRENT", "5"))
REQUEST_TIMEOUT = int(get_env("REQUEST_TIMEOUT", "10"))