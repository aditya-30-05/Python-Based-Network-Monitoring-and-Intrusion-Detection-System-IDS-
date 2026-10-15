"""
config.py  -  Centralised configuration loader for NetSentinel IDS.

Reads settings from environment variables (populated from .env via python-dotenv).
Never exposes secrets to logs or HTTP responses.
"""

import os
import logging
from dotenv import load_dotenv

# Load .env from project root (the folder that contains app.py)
_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(_ENV_PATH, override=False)

log = logging.getLogger(__name__)


def _safe_int(env_name: str, default: int) -> int:
    """
    Read an environment variable as an integer.
    If the value cannot be parsed (e.g. a stray comment was appended to it in
    .env), log a warning and return the default instead of crashing.
    """
    raw = os.getenv(env_name, str(default)).strip()
    try:
        return int(raw)
    except ValueError:
        log.warning(
            "[Config] %s='%s' is not a valid integer; using default %d.",
            env_name, raw, default,
        )
        return default


# ---------------------------------------------------------------------------
# ntfy push notifications
# ---------------------------------------------------------------------------
NTFY_TOPIC: str   = os.getenv("NTFY_TOPIC", "")
NTFY_SERVER: str  = os.getenv("NTFY_SERVER", "https://ntfy.sh")
NTFY_NOTIFICATIONS_ENABLED: bool = (
    os.getenv("NTFY_NOTIFICATIONS_ENABLED", "true").lower() == "true"
)
NTFY_MIN_SEVERITY: str        = os.getenv("NTFY_MIN_SEVERITY", "LOW").upper()
NTFY_REQUEST_TIMEOUT: int     = _safe_int("NTFY_REQUEST_TIMEOUT", 5)
NTFY_MAX_RETRIES: int         = _safe_int("NTFY_MAX_RETRIES", 3)
# Optional: bearer token for access-controlled topics
NTFY_ACCESS_TOKEN: str        = os.getenv("NTFY_ACCESS_TOKEN", "")
# Optional: URL opened when the user taps the notification
NTFY_CLICK_URL: str           = os.getenv("NTFY_CLICK_URL", "")

# Notification queue capacity - drop oldest if full to protect memory
NOTIFICATION_QUEUE_SIZE: int = _safe_int("NOTIFICATION_QUEUE_SIZE", 100)

# ---------------------------------------------------------------------------
# Severity ordering (lower index = lower severity)
# ---------------------------------------------------------------------------
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_meets_minimum(severity: str, minimum: str) -> bool:
    """Return True if *severity* is >= *minimum* in the severity ladder."""
    sev = severity.upper()
    min_sev = minimum.upper()
    try:
        return SEVERITY_ORDER.index(sev) >= SEVERITY_ORDER.index(min_sev)
    except ValueError:
        return True  # Unknown severity - send it


def ntfy_configured() -> bool:
    """Return True only when NTFY_TOPIC is non-empty."""
    return bool(NTFY_TOPIC)


def validate_startup() -> list:
    """
    Return a list of human-readable warning strings about missing/invalid
    configuration.  An empty list means everything is fine.
    """
    warnings: list = []
    if NTFY_NOTIFICATIONS_ENABLED and not ntfy_configured():
        warnings.append(
            "NTFY_NOTIFICATIONS_ENABLED=true but NTFY_TOPIC is missing.  "
            "Push notifications will be disabled.  Add NTFY_TOPIC to .env."
        )
    if NTFY_MIN_SEVERITY not in SEVERITY_ORDER:
        warnings.append(
            f"NTFY_MIN_SEVERITY='{NTFY_MIN_SEVERITY}' is not valid. "
            f"Valid values: {SEVERITY_ORDER}.  Defaulting to LOW."
        )
    return warnings
