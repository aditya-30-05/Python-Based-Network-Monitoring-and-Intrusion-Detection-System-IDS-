"""
logger.py  –  Persistent CSV event logger for NetSentinel IDS.

Changes vs original
────────────────────
• log_event() remains for backward compatibility (not called by any module
  but kept so no import error can occur if anything else references it).

• NEW: log_alert(alert) persists IDS security alerts with extended fields:
    Event ID, Severity, Alert Type, Source IP, Dst IP, Dst Port,
    Description, Notification Status.

• CSV file is created with headers if it doesn't exist (idempotent).

• A threading.Lock protects writes so concurrent callers cannot interleave.

• All exceptions are caught and logged rather than propagated, so a logging
  failure never stops packet capture or detection.
"""

import csv
import logging
import os
import threading
from datetime import datetime

log = logging.getLogger(__name__)

LOG_FOLDER = "logs"
LOG_FILE   = os.path.join(LOG_FOLDER, "network_events.csv")

_ALERT_HEADERS = [
    "Timestamp",
    "Event ID",
    "Severity",
    "Alert Type",
    "Source IP",
    "Destination IP",
    "Destination Port",
    "Description",
    "Notification Status",
]

_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════════
# Initialisation
# ═══════════════════════════════════════════════════════════════════════════

def initialize_log() -> None:
    """Create log directory and CSV file with headers (idempotent)."""
    try:
        os.makedirs(LOG_FOLDER, exist_ok=True)

        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(_ALERT_HEADERS)
            log.info("[Logger] Created new log file: %s", LOG_FILE)

    except OSError as exc:
        log.error("[Logger] Could not initialise log file: %s", exc)


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def log_alert(alert: dict) -> None:
    """
    Append one IDS alert to the CSV log.

    Fields written: Timestamp, Event ID, Severity, Alert Type, Source IP,
    Destination IP, Destination Port, Description, Notification Status.
    """
    try:
        initialize_log()

        row = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            alert.get("event_id",             ""),
            alert.get("severity",             ""),
            alert.get("type",                 ""),
            alert.get("source_ip",            ""),
            alert.get("dst_ip",               ""),
            alert.get("dst_port",             ""),
            alert.get("description",          ""),
            alert.get("notification_status",  ""),
        ]

        with _lock:
            with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(row)

    except Exception as exc:  # pylint: disable=broad-except
        log.error("[Logger] Failed to log alert: %s", exc)


def log_event(packet: dict, event: str = "Normal Traffic") -> None:
    """
    Legacy packet-level logger (kept for backward compatibility).
    Not wired to the main pipeline – call log_alert() for IDS events.
    """
    try:
        initialize_log()

        row = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "",               # event_id
            "INFO",           # severity
            event,            # alert_type
            packet.get("src_ip",   ""),
            packet.get("dst_ip",   ""),
            packet.get("dst_port", ""),
            "",               # description
            "",               # notification_status
        ]

        with _lock:
            with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(row)

    except Exception as exc:  # pylint: disable=broad-except
        log.error("[Logger] log_event failed: %s", exc)