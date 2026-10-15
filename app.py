"""
app.py  -  Flask web server for NetSentinel IDS.

Key design points
─────────────────
- IDS detection runs in packet_monitor.py on every captured packet,
  independent of whether the dashboard is open.
- /api/data is read-only: returns statistics and alerts.
- /api/notification_status returns ntfy delivery stats (no secrets exposed).
- /api/test_alert sends a synthetic alert so you can verify ntfy setup
  without generating a real intrusion.
- ntfy notification worker is started at startup.
"""

import logging
import time

from flask import Flask, render_template, jsonify

import config
import ids
import logger
import packet_monitor
from notifications import ntfy_notifier

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Initialise persistent CSV log
logger.initialize_log()

# Validate configuration and print any warnings
for warning in config.validate_startup():
    log.warning("[Config] %s", warning)

# Start the ntfy notification background worker
ntfy_notifier.start_worker()


# ===========================================================================
# Routes
# ===========================================================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/data")
def get_data():
    """
    Read-only endpoint: returns current network statistics and IDS alerts.
    IDS detection is NOT triggered here (it runs in packet_monitor).
    """
    stats  = packet_monitor.get_statistics()
    alerts = ids.get_alerts()

    return jsonify({
        "total":   stats["total"],
        "tcp":     stats["tcp"],
        "udp":     stats["udp"],
        "icmp":    stats["icmp"],
        "other":   stats["other"],
        "packets": stats["packets"],
        "alerts":  alerts,
    })


@app.route("/api/notification_status")
def notification_status():
    """
    Returns ntfy notification worker status.
    Secrets (topic name) are NEVER included in this response.
    """
    status = ntfy_notifier.get_status()
    return jsonify(status)


@app.route("/api/test_alert")
def test_alert():
    """
    Sends a synthetic test alert so you can verify ntfy setup on your phone.
    Safe: does not require real network attacks.
    """
    synthetic = {
        "type":        "Test Alert",
        "severity":    "INFO",
        "source_ip":   "127.0.0.1",
        "dst_ip":      "127.0.0.1",
        "dst_port":    "0",
        "description": "NetSentinel test notification - ntfy setup verified.",
        "time":        time.strftime("%H:%M:%S"),
    }
    queued = ntfy_notifier.enqueue_alert(synthetic)
    return jsonify({
        "queued": queued,
        "message": (
            "Test alert queued for ntfy delivery."
            if queued
            else "Notifications disabled or not configured (check NTFY_TOPIC in .env)."
        ),
    })


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":

    print("=" * 40)
    print("  NetSentinel -- Network IDS")
    print("=" * 40)
    print(f"  Dashboard : http://127.0.0.1:5000")
    print(f"  ntfy      : {'enabled' if config.ntfy_configured() else 'disabled (see .env)'}")
    print("=" * 40)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
