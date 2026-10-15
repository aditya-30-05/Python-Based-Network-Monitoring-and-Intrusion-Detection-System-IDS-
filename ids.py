"""
ids.py  -  Real-time Intrusion Detection Engine for NetSentinel IDS.

Design notes
─────────────
1. Detection is driven by process_packet() on every captured packet,
   independent of Flask polling.

2. Port-scan tracking uses a timed window so stale counts never accumulate.

3. All shared state is protected by a threading.Lock.

4. Alert deduplication uses (source_ip, alert_type) + a time window.

5. Alerts are logged to CSV via logger.log_alert().

6. New alerts are forwarded to the ntfy notification worker via a
   non-blocking enqueue so packet capture is never delayed.
"""

import logging
import threading
import time
import uuid
from collections import defaultdict
from typing import Optional

import logger
from notifications import ntfy_notifier

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detection thresholds (tune via environment or here for lab use)
# ---------------------------------------------------------------------------
SUSPICIOUS_PORTS = {4444, 5555, 6666}

PORT_SCAN_THRESHOLD       = 10      # unique ports within PORT_SCAN_WINDOW_SECONDS
PORT_SCAN_WINDOW_SECONDS  = 30      # sliding window for port-scan detection

HIGH_TRAFFIC_THRESHOLD    = 100     # packets per HIGH_TRAFFIC_WINDOW_SECONDS
HIGH_TRAFFIC_WINDOW_SECONDS = 5

# How long (seconds) to suppress a repeat alert for the same (ip, type) pair
ALERT_DEDUP_WINDOW = 30

MAX_ALERTS = 50   # maximum alerts kept in memory

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
_lock = threading.Lock()

# { src_ip: [(port, timestamp), ...] }  – timed port history per IP
_ip_port_history: dict = defaultdict(list)

# { src_ip: [timestamp, ...] }  – packet timestamps per IP
_ip_packets: dict = defaultdict(list)

# { (src_ip, alert_type): last_created_epoch }
_alert_dedup: dict = {}

# Alert list (newest first)
alerts: list = []


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def check_packet(packet: dict) -> None:
    """
    Evaluate one packet dict against all IDS rules.

    Called from packet_monitor.process_packet() on EVERY captured packet –
    independent of browser polling.
    """
    now = time.time()
    src_ip: str = packet.get("src_ip", "")
    dst_port = packet.get("dst_port", "-")
    dst_ip: str = packet.get("dst_ip", "")

    with _lock:
        _rule_suspicious_port(now, src_ip, dst_ip, dst_port, packet)
        _rule_port_scan(now, src_ip, dst_ip, dst_port)
        _rule_high_traffic(now, src_ip)


def get_alerts() -> list:
    """Return a snapshot of the current alert list (thread-safe copy)."""
    with _lock:
        return list(alerts)


# ═══════════════════════════════════════════════════════════════════════════
# Detection rules  (must be called while _lock is held)
# ═══════════════════════════════════════════════════════════════════════════

def _rule_suspicious_port(
    now: float,
    src_ip: str,
    dst_ip: str,
    dst_port,
    packet: dict,
) -> None:
    try:
        port = int(dst_port)
    except (ValueError, TypeError):
        return

    if port in SUSPICIOUS_PORTS:
        _create_alert(
            now=now,
            source_ip=src_ip,
            alert_type="Suspicious Port Activity",
            description=f"Connection to suspicious port {port} (possible backdoor/C2)",
            severity="HIGH",
            extra={"dst_ip": dst_ip, "dst_port": str(port)},
        )


def _rule_port_scan(
    now: float,
    src_ip: str,
    dst_ip: str,
    dst_port,
) -> None:
    try:
        port = int(dst_port)
    except (ValueError, TypeError):
        return

    # Append current (port, timestamp) and prune entries older than window
    history = _ip_port_history[src_ip]
    history.append((port, now))
    cutoff = now - PORT_SCAN_WINDOW_SECONDS
    _ip_port_history[src_ip] = [(p, t) for p, t in history if t >= cutoff]

    unique_ports = {p for p, _ in _ip_port_history[src_ip]}

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:
        _create_alert(
            now=now,
            source_ip=src_ip,
            alert_type="Port Scan",
            description=(
                f"Probed {len(unique_ports)} unique ports in "
                f"{PORT_SCAN_WINDOW_SECONDS}s"
            ),
            severity="HIGH",
            extra={"dst_ip": dst_ip},
        )
        # Reset so the same host can re-trigger after the window
        _ip_port_history[src_ip] = []


def _rule_high_traffic(now: float, src_ip: str) -> None:
    # Append current timestamp and prune old entries
    ts_list = _ip_packets[src_ip]
    ts_list.append(now)
    cutoff = now - HIGH_TRAFFIC_WINDOW_SECONDS
    _ip_packets[src_ip] = [t for t in ts_list if t >= cutoff]

    if len(_ip_packets[src_ip]) >= HIGH_TRAFFIC_THRESHOLD:
        _create_alert(
            now=now,
            source_ip=src_ip,
            alert_type="High Traffic",
            description=(
                f"≥{HIGH_TRAFFIC_THRESHOLD} packets from this host "
                f"in {HIGH_TRAFFIC_WINDOW_SECONDS}s (possible flood/DoS)"
            ),
            severity="MEDIUM",
        )
        _ip_packets[src_ip] = []


# ═══════════════════════════════════════════════════════════════════════════
# Alert creation  (must be called while _lock is held)
# ═══════════════════════════════════════════════════════════════════════════

def _create_alert(
    now: float,
    source_ip: str,
    alert_type: str,
    description: str,
    severity: str,
    extra: Optional[dict] = None,
) -> None:
    """
    Create a new alert, deduplicate it, persist it, and forward to notifier.
    Called while _lock is held – no further locking needed here.
    """
    dedup_key = (source_ip, alert_type)
    last_seen = _alert_dedup.get(dedup_key, 0)

    if now - last_seen < ALERT_DEDUP_WINDOW:
        return  # Suppress: same event within dedup window

    _alert_dedup[dedup_key] = now

    event_id = str(uuid.uuid4())[:8].upper()
    alert = {
        "event_id":   event_id,
        "time":       time.strftime("%H:%M:%S"),
        "source_ip":  source_ip,
        "type":       alert_type,
        "description": description,
        "severity":   severity,
        "notification_status": "pending",
    }
    if extra:
        alert.update(extra)

    alerts.insert(0, alert)
    if len(alerts) > MAX_ALERTS:
        alerts.pop()

    log.warning(
        "[IDS] %s | src=%s | %s | event_id=%s",
        severity, source_ip, alert_type, event_id,
    )

    # Persist to CSV log (fire-and-forget; errors logged, not raised)
    try:
        logger.log_alert(alert)
    except Exception as exc:  # pylint: disable=broad-except
        log.error("[IDS] Failed to write alert to log: %s", exc)

    # Forward to ntfy (non-blocking - the notifier uses its own queue).
    # We pass a copy because _lock is still held here.
    alert_snapshot = dict(alert)
    # Schedule the enqueue outside the lock via a micro-thread so we never
    # wait on queue.put inside the packet-capture critical section.
    _fire_notify(alert_snapshot)


def _fire_notify(alert_snapshot: dict) -> None:
    """
    Enqueue an alert notification without blocking the capture thread.
    Spawning a tiny thread costs ~1 us; the notifier thread does all I/O.
    """
    def _enqueue():
        delivered = ntfy_notifier.enqueue_alert(alert_snapshot)
        # Update notification_status in the live alerts list
        with _lock:
            for a in alerts:
                if a.get("event_id") == alert_snapshot.get("event_id"):
                    a["notification_status"] = "queued" if delivered else "skipped"
                    break

    t = threading.Thread(target=_enqueue, daemon=True)
    t.start()