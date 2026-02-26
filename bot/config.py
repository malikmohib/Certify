import os
import re
import logging
from pathlib import Path
from dotenv import load_dotenv

# Load env (production-safe: don't crash if file missing)
load_dotenv(os.getenv("ENV_FILE", "requirement.env"))

# =============================================================================
# LOGGING
# =============================================================================
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("coupon-bot")

# =============================================================================
# HELPERS
# =============================================================================
def _require_env(name: str) -> str:
    v = os.getenv(name, "").strip()
    if not v:
        raise RuntimeError(f"{name} is not set")
    return v

def _require_int(name: str) -> int:
    raw = os.getenv(name, "").strip()
    if not raw or not raw.isdigit():
        raise RuntimeError(f"{name} is not set or not a valid integer")
    return int(raw)

def _require_path(name: str, default: str = "", must_exist: bool = True, must_be_file: bool = True) -> Path:
    raw = os.getenv(name, default).strip()
    if not raw:
        raise RuntimeError(f"{name} is not set")
    p = Path(raw).expanduser().resolve()
    if must_exist and not p.exists():
        raise RuntimeError(f"{name} path does not exist: {p}")
    if must_exist and must_be_file and not p.is_file():
        raise RuntimeError(f"{name} must be a file: {p}")
    if must_exist and (not must_be_file) and not p.is_dir():
        raise RuntimeError(f"{name} must be a directory: {p}")
    return p

# =============================================================================
# ENV CONFIG
# =============================================================================
BOT_TOKEN = _require_env("BOT_TOKEN")
DATABASE_URL = _require_env("DATABASE_URL")
ADMIN_TELEGRAM_ID = _require_int("ADMIN_TELEGRAM_ID")

CERT_API_BASE = os.getenv("CERT_API_BASE", "https://cert.diannaozy.top").strip().rstrip("/")
if not CERT_API_BASE.lower().startswith("https://"):
    raise RuntimeError("CERT_API_BASE must start with https://")
CERT_API_TOKEN = _require_env("CERT_API_TOKEN")

# P12 password (provider requirement)
# NOTE: "1" is intentionally allowed by design
CERT_PASSWORD = _require_env("CERT_PASSWORD")

if CERT_PASSWORD == "":
    raise RuntimeError("CERT_PASSWORD must not be empty")


# =============================================================================
# SIGNING CONFIG
# =============================================================================
ZSIGN_BIN = _require_path("ZSIGN_BIN", default="/usr/local/bin/zsign", must_exist=True, must_be_file=True)

# Optional: ensure zsign is executable (Linux)
if os.name != "nt" and not os.access(ZSIGN_BIN, os.X_OK):
    raise RuntimeError(f"ZSIGN_BIN is not executable: {ZSIGN_BIN}")

# Use env-driven IPA paths (production).
IPA_MAP = {
    "gbox": _require_path("IPA_GBOX", must_exist=True, must_be_file=True),
    "esign": _require_path("IPA_ESIGN", must_exist=True, must_be_file=True),
    "scarlet": _require_path("IPA_SCARLET", must_exist=True, must_be_file=True),
}

BUNDLE_ID_MAP = {
    "esign": os.getenv("BUNDLE_ESIGN", "com.example.esign").strip(),
    "gbox": os.getenv("BUNDLE_GBOX", "com.example.gbox").strip(),
    "scarlet": os.getenv("BUNDLE_SCARLET", "com.example.scarlet").strip(),
}

APP_TITLE_MAP = {
    "esign": os.getenv("TITLE_ESIGN", "ESign").strip(),
    "gbox": os.getenv("TITLE_GBOX", "GBox").strip(),
    "scarlet": os.getenv("TITLE_SCARLET", "Scarlet").strip(),
}

# Production: require real public base URL for OTA links
PUBLIC_BASE_URL = _require_env("PUBLIC_BASE_URL").rstrip("/")
if not PUBLIC_BASE_URL.lower().startswith("https://"):
    raise RuntimeError("PUBLIC_BASE_URL must start with https://")

PUBLIC_DIR = Path(os.getenv("PUBLIC_DIR", "/root/signbot-local/public")).expanduser().resolve()
if PUBLIC_DIR.exists() and not PUBLIC_DIR.is_dir():
    raise RuntimeError(f"PUBLIC_DIR must be a directory: {PUBLIC_DIR}")

PUBLIC_FILES_DIR = (PUBLIC_DIR / "files").resolve()
PUBLIC_META_DIR = (PUBLIC_DIR / "meta").resolve()

# Create public dirs if missing (production-safe)
PUBLIC_FILES_DIR.mkdir(parents=True, exist_ok=True)
PUBLIC_META_DIR.mkdir(parents=True, exist_ok=True)

# TTL bounds: min 10 minutes, max 7 days (disk safety)
SIGNED_TTL_SECONDS = int(os.getenv("SIGNED_TTL_SECONDS", str(12 * 60 * 60)).strip() or "43200")
SIGNED_TTL_SECONDS = max(600, min(SIGNED_TTL_SECONDS, 7 * 24 * 60 * 60))

# =============================================================================
# VALIDATION / REGEX
# =============================================================================
COUPON_RE = re.compile(r"^(Vinh|Certify)-[a-f0-9]{8}$", re.IGNORECASE)
UDID_RE = re.compile(r"^[A-Za-z0-9\-_.:]{5,200}$")
SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9._-]{6,128}$")

# =============================================================================
# RATE LIMIT (DEV/OPTIONAL)
# =============================================================================
WINDOW_SECONDS = max(1, int(os.getenv("WINDOW_SECONDS", "20")))
MAX_MSGS_PER_WINDOW = max(1, int(os.getenv("MAX_MSGS_PER_WINDOW", "10")))
