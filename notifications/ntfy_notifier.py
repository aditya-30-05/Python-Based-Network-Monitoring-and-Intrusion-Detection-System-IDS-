"""
notifications/ntfy_notifier.py
───────────────────────────────
Background ntfy push-notification worker for NetSentinel IDS.

How ntfy works
──────────────
The app sends a plain HTTP POST to:
    https://ntfy.sh/<your-topic>

The ntfy Android app (subscribed to the same topic) shows the message as a
push notification instantly – no account, no bot token, no Firebase,
no Telegram required.

Responsibilities
────────────────
- Accept structured alert dicts via a thread-safe bounded queue.
- Format readable ntfy messages with title, priority, and tags.
- POST using the ntfy REST API with timeout + exponential-backoff retries.
- Handle network errors gracefully; never block packet capture.
- Deduplicate alerts (same IP + alert type within a configurable window).
- Record delivery status so the dashboard can display it.
"""

import logging
import queue
import threading
import time
import uuid
from typing import Optional

import requests

import config

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal notification queue  (bounded so memory stays capped)
# ---------------------------------------------------------------------------
_notify_queue: queue.Queue = queue.Queue(maxsize=config.NOTIFICATION_QUEUE_SIZE)

_worker_thread: Optional[threading.Thread] = None
_worker_lock = threading.Lock()

_stats: dict = {
    "enabled":             False,
    "configured":          False,
    "worker_alive":        False,
    "sent_ok":             0,
    "failed":              0,
    "pending":             0,
    "last_attempt":        None,
    "last_success":        None,
    "last_failure_reason": None,
}
_stats_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Deduplication cache  (src_ip, alert_type) -> last-sent epoch
# ---------------------------------------------------------------------------
_DEDUP_WINDOW_SECONDS = 60
_dedup_cache: dict = {}
_dedup_lock = threading.Lock()

# ---------------------------------------------------------------------------
# ntfy priority and tag mapping from severity
# ---------------------------------------------------------------------------
_SEVERITY_PRIORITY = {
    "CRITICAL": "urgent",
    "HIGH":     "high",
    "MEDIUM":   "default",
    "LOW":      "low",
    "INFO":     "min",
}

_SEVERITY_TAGS = {
    "CRITICAL": "rotating_light",
    "HIGH":     "warning",
    "MEDIUM":   "small_orange_diamond",
    "LOW":      "information_source",
    "INFO":     "white_check_mark",
}


# ===========================================================================
# Public API
# ===========================================================================

def start_worker() -> None:
    """Start the background notification worker (idempotent)."""
    global _worker_thread
    with _worker_lock:
        _configured = config.ntfy_configured()
        _enabled    = config.NTFY_NOTIFICATIONS_ENABLED and _configured

        with _stats_lock:
            _stats["configured"] = _configured
            _stats["enabled"]    = _enabled

        if not _enabled:
            if not _configured:
                log.info(
                    "[Notifier] ntfy topic not set - notifications disabled. "
                    "Add NTFY_TOPIC to .env to enable."
                )
            else:
                log.info("[Notifier] NTFY_NOTIFICATIONS_ENABLED=false")
            return

        if _worker_thread and _worker_thread.is_alive():
            return

        _worker_thread = threading.Thread(
            target=_notification_worker,
            name="ntfy-notifier",
            daemon=True,
        )
        _worker_thread.start()
        log.info("[Notifier] ntfy notification worker started.")


def enqueue_alert(alert: dict) -> bool:
    """
    Queue an alert for ntfy delivery.  Returns True if accepted.
    Never blocks the caller (packet capture thread).
    """
    if not (config.NTFY_NOTIFICATIONS_ENABLED and config.ntfy_configured()):
        return False

    if not config.severity_meets_minimum(
        alert.get("severity", "LOW"), config.NTFY_MIN_SEVERITY
    ):
        return False

    dedup_key = (alert.get("source_ip", ""), alert.get("type", ""))
    now = time.time()
    with _dedup_lock:
        last_sent = _dedup_cache.get(dedup_key, 0)
        if now - last_sent < _DEDUP_WINDOW_SECONDS:
            log.debug(
                "[Notifier] Suppressing duplicate %s from %s (%.0fs ago)",
                dedup_key[1], dedup_key[0], now - last_sent,
            )
            return False
        _dedup_cache[dedup_key] = now

    alert_copy = dict(alert)
    if "event_id" not in alert_copy:
        alert_copy["event_id"] = str(uuid.uuid4())[:8].upper()

    try:
        _notify_queue.put_nowait(alert_copy)
        with _stats_lock:
            _stats["pending"] = _notify_queue.qsize()
        return True
    except queue.Full:
        log.warning(
            "[Notifier] Queue full (%d) - alert dropped.",
            config.NOTIFICATION_QUEUE_SIZE,
        )
        return False


def get_status() -> dict:
    """Return a copy of delivery statistics safe for JSON."""
    with _stats_lock:
        status = dict(_stats)
    with _worker_lock:
        status["worker_alive"] = bool(
            _worker_thread and _worker_thread.is_alive()
        )
    status["pending"] = _notify_queue.qsize()
    return status


# ===========================================================================
# Internal helpers
# ===========================================================================

def _notification_worker() -> None:
    """Long-running thread: dequeue alerts and POST to ntfy."""
    log.info("[Notifier] Worker thread running.")
    while True:
        try:
            alert = _notify_queue.get(timeout=5)
        except queue.Empty:
            continue

        _send_with_retry(alert)

        with _stats_lock:
            _stats["pending"] = _notify_queue.qsize()

        _notify_queue.task_done()


def _send_with_retry(alert: dict) -> None:
    """POST the alert to ntfy with exponential-backoff retries."""
    url     = _build_url()
    headers = _build_headers(alert)
    body    = _format_body(alert)

    attempt    = 0
    last_error = None

    while attempt < config.NTFY_MAX_RETRIES:
        attempt += 1
        ts_str = time.strftime("%Y-%m-%dT%H:%M:%S")
        with _stats_lock:
            _stats["last_attempt"] = ts_str

        try:
            resp = requests.post(
                url,
                data=body.encode("utf-8"),
                headers=headers,
                timeout=config.NTFY_REQUEST_TIMEOUT,
            )

            if resp.status_code in (200, 201):
                with _stats_lock:
                    _stats["sent_ok"]     += 1
                    _stats["last_success"] = ts_str
                log.info(
                    "[Notifier] Alert '%s' delivered via ntfy (event_id=%s).",
                    alert.get("type"), alert.get("event_id"),
                )
                return

            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "5"))
                log.warning("[Notifier] ntfy rate-limited. Waiting %ss.", retry_after)
                time.sleep(retry_after)
                continue

            last_error = f"HTTP {resp.status_code}: {resp.text[:120]}"
            log.error("[Notifier] ntfy error: %s", last_error)
            break

        except requests.exceptions.Timeout:
            last_error = "Request timed out"
            log.warning(
                "[Notifier] Attempt %d/%d timed out for '%s'.",
                attempt, config.NTFY_MAX_RETRIES, alert.get("type"),
            )
        except requests.exceptions.ConnectionError:
            last_error = "Connection error (no internet?)"
            log.warning(
                "[Notifier] No network - attempt %d/%d.",
                attempt, config.NTFY_MAX_RETRIES,
            )
        except Exception as exc:  # pylint: disable=broad-except
            last_error = str(exc)
            log.exception("[Notifier] Unexpected error on attempt %d.", attempt)

        if attempt < config.NTFY_MAX_RETRIES:
            delay = 2.0 * (2 ** (attempt - 1))
            time.sleep(delay)

    with _stats_lock:
        _stats["failed"]             += 1
        _stats["last_failure_reason"] = last_error or "Unknown error"
    log.error(
        "[Notifier] Failed to deliver '%s' after %d attempts: %s",
        alert.get("type"), attempt, last_error,
    )


def _build_url() -> str:
    server = config.NTFY_SERVER.rstrip("/")
    topic  = config.NTFY_TOPIC.strip("/")
    return f"{server}/{topic}"


def _build_headers(alert: dict) -> dict:
    sev = alert.get("severity", "LOW").upper()

    title    = f"[{sev}] {alert.get('type', 'IDS Alert')} - NetSentinel"
    priority = _SEVERITY_PRIORITY.get(sev, "default")
    tag      = _SEVERITY_TAGS.get(sev, "bell")

    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Title":        title,
        "Priority":     priority,
        "Tags":         tag,
    }

    if config.NTFY_CLICK_URL:
        headers["Click"] = config.NTFY_CLICK_URL

    if config.NTFY_ACCESS_TOKEN:
        headers["Authorization"] = f"Bearer {config.NTFY_ACCESS_TOKEN}"

    return headers


def _format_body(alert: dict) -> str:
    """Render a plain-text body for the ntfy notification."""
    lines = []

    if alert.get("source_ip"):
        lines.append(f"Source IP : {alert['source_ip']}")
    if alert.get("dst_ip"):
        lines.append(f"Dest IP   : {alert['dst_ip']}")
    if alert.get("dst_port") and str(alert.get("dst_port")) not in ("-", ""):
        lines.append(f"Dest Port : {alert['dst_port']}")

    detected_at = alert.get("time", time.strftime("%H:%M:%S"))
    lines.append(f"Detected  : {detected_at}")

    if alert.get("description"):
        lines.append(f"Details   : {alert['description']}")

    if alert.get("event_id"):
        lines.append(f"Event ID  : {alert['event_id']}")

    return "\n".join(lines) if lines else "NetSentinel IDS alert."
