"""
packet_monitor.py  –  Background packet-capture engine for NetSentinel IDS.

Changes vs original
────────────────────
• ids.check_packet() is now called on EVERY captured packet from within
  process_packet(), not from the Flask polling endpoint.  This means
  intrusion detection runs whether or not the dashboard is open.

• The recent_packets buffer (max 20) is still maintained for the dashboard's
  "Live traffic" table – it is NOT used for IDS processing.

• The Flask /api/data route must NOT call ids.check_packet() anymore.

• Thread-safety is preserved: all shared counters are updated under _lock.
"""

import logging
import threading
import time

from scapy.all import sniff, IP, TCP, UDP, ICMP

import ids   # IDS engine – imported here to break the old polling coupling

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared state (protected by _lock)
# ---------------------------------------------------------------------------
_lock = threading.Lock()

packet_count: int = 0
protocol_count: dict = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
recent_packets: list = []    # last 20 packets for the dashboard

RECENT_BUFFER_SIZE = 20


# ═══════════════════════════════════════════════════════════════════════════
# Packet processing callback  (runs in the Scapy sniff thread)
# ═══════════════════════════════════════════════════════════════════════════

def process_packet(packet) -> None:
    global packet_count

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "OTHER"
    src_port = "-"
    dst_port  = "-"

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port  = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port  = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    packet_info = {
        "time":     time.strftime("%H:%M:%S"),
        "src_ip":   src_ip,
        "dst_ip":   dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
    }

    with _lock:
        packet_count += 1
        protocol_count[protocol] = protocol_count.get(protocol, 0) + 1

        recent_packets.insert(0, packet_info)
        if len(recent_packets) > RECENT_BUFFER_SIZE:
            recent_packets.pop()

    # ── Real-time IDS evaluation ────────────────────────────────────────────
    # Called OUTSIDE the lock so ids.py can also acquire _lock internally
    # without deadlock.  ids.check_packet has its own lock.
    try:
        ids.check_packet(packet_info)
    except Exception as exc:  # pylint: disable=broad-except
        log.error("[Monitor] IDS check_packet raised: %s", exc)


# ═══════════════════════════════════════════════════════════════════════════
# Statistics read by Flask /api/data
# ═══════════════════════════════════════════════════════════════════════════

def get_statistics() -> dict:
    """Return a consistent snapshot of counters and recent packets."""
    with _lock:
        return {
            "total": packet_count,
            "tcp":   protocol_count.get("TCP",   0),
            "udp":   protocol_count.get("UDP",   0),
            "icmp":  protocol_count.get("ICMP",  0),
            "other": protocol_count.get("OTHER", 0),
            "packets": list(recent_packets),
        }


def get_packets() -> list:
    with _lock:
        return list(recent_packets)


# ═══════════════════════════════════════════════════════════════════════════
# Background monitoring thread
# ═══════════════════════════════════════════════════════════════════════════

def start_monitoring() -> None:
    log.info("[Monitor] Starting network monitoring...")
    print("Starting network monitoring...")
    sniff(prn=process_packet, store=False)


_monitor_thread = threading.Thread(
    target=start_monitoring,
    name="packet-monitor",
    daemon=True,
)
_monitor_thread.start()