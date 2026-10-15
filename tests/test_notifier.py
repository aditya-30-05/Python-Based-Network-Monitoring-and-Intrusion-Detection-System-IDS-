"""
tests/test_notifier.py
───────────────────────
Automated tests for the ntfy notification module and IDS engine.

All tests use mocked network requests - no real ntfy topic, real Scapy
sniffing, or real attacks are needed.

Run with:
    python -m pytest tests/ -v
"""

import importlib
import os
import queue
import sys
import threading
import time
import types
import unittest
from unittest.mock import MagicMock, patch

# ── Bootstrap: make the project root importable ───────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Stub scapy so tests run without Npcap installed
_scapy_stub     = types.ModuleType("scapy")
_scapy_all_stub = types.ModuleType("scapy.all")
for _name in ("sniff", "IP", "TCP", "UDP", "ICMP"):
    setattr(_scapy_all_stub, _name, MagicMock())
sys.modules.setdefault("scapy",     _scapy_stub)
sys.modules.setdefault("scapy.all", _scapy_all_stub)


# ===========================================================================
# Helpers
# ===========================================================================

def _make_packet(src_ip="1.2.3.4", dst_ip="5.6.7.8",
                 protocol="TCP", src_port=12345, dst_port=80) -> dict:
    return {
        "time":     "12:00:00",
        "src_ip":   src_ip,
        "dst_ip":   dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
    }


def _setup_ntfy_env(topic="test-topic-abc123", enabled="true",
                    server="https://ntfy.sh", min_sev="LOW",
                    token="", click_url=""):
    os.environ.update({
        "NTFY_TOPIC":                   topic,
        "NTFY_SERVER":                  server,
        "NTFY_NOTIFICATIONS_ENABLED":   enabled,
        "NTFY_MIN_SEVERITY":            min_sev,
        "NTFY_REQUEST_TIMEOUT":         "5",
        "NTFY_MAX_RETRIES":             "3",
        "NTFY_ACCESS_TOKEN":            token,
        "NTFY_CLICK_URL":               click_url,
        "NOTIFICATION_QUEUE_SIZE":      "100",
    })


# ===========================================================================
# 1.  ntfy message formatting
# ===========================================================================

class TestMessageFormatting(unittest.TestCase):

    def setUp(self):
        _setup_ntfy_env()
        import config
        importlib.reload(config)
        from notifications import ntfy_notifier
        importlib.reload(ntfy_notifier)
        self.notifier = ntfy_notifier

    def test_body_contains_source_ip(self):
        alert = _make_packet()
        alert.update({"type": "Port Scan", "severity": "HIGH",
                      "description": "10 ports in 30s", "source_ip": "1.2.3.4",
                      "event_id": "ABCD1234"})
        body = self.notifier._format_body(alert)
        self.assertIn("1.2.3.4", body)
        self.assertIn("ABCD1234", body)

    def test_body_contains_description(self):
        alert = {"type": "High Traffic", "severity": "MEDIUM",
                 "source_ip": "9.9.9.9", "description": "flood detected",
                 "event_id": "EV02", "time": "12:00:00"}
        body = self.notifier._format_body(alert)
        self.assertIn("flood detected", body)

    def test_body_omits_missing_dst(self):
        alert = {"type": "Suspicious Port Activity", "severity": "HIGH",
                 "source_ip": "2.2.2.2", "description": "port 4444",
                 "event_id": "EV04", "time": "12:00:00"}
        body = self.notifier._format_body(alert)
        self.assertNotIn("Dest IP", body)

    def test_headers_priority_high(self):
        alert = {"type": "Port Scan", "severity": "HIGH",
                 "source_ip": "1.1.1.1", "event_id": "EV01"}
        headers = self.notifier._build_headers(alert)
        self.assertEqual(headers["Priority"], "high")
        self.assertIn("HIGH", headers["Title"])

    def test_headers_priority_critical(self):
        alert = {"type": "DDoS", "severity": "CRITICAL",
                 "source_ip": "1.1.1.1", "event_id": "EV05"}
        headers = self.notifier._build_headers(alert)
        self.assertEqual(headers["Priority"], "urgent")

    def test_headers_priority_medium(self):
        alert = {"type": "High Traffic", "severity": "MEDIUM",
                 "source_ip": "1.1.1.1", "event_id": "EV06"}
        headers = self.notifier._build_headers(alert)
        self.assertEqual(headers["Priority"], "default")

    def test_headers_include_bearer_token(self):
        _setup_ntfy_env(token="mytoken123")
        import config
        importlib.reload(config)
        from notifications import ntfy_notifier
        importlib.reload(ntfy_notifier)
        alert = {"type": "Test", "severity": "LOW",
                 "source_ip": "1.1.1.1", "event_id": "EV07"}
        headers = ntfy_notifier._build_headers(alert)
        self.assertEqual(headers["Authorization"], "Bearer mytoken123")

    def test_headers_include_click_url(self):
        _setup_ntfy_env(click_url="http://192.168.1.10:5000")
        import config
        importlib.reload(config)
        from notifications import ntfy_notifier
        importlib.reload(ntfy_notifier)
        alert = {"type": "Test", "severity": "LOW",
                 "source_ip": "1.1.1.1", "event_id": "EV08"}
        headers = ntfy_notifier._build_headers(alert)
        self.assertEqual(headers["Click"], "http://192.168.1.10:5000")

    def test_build_url_combines_server_and_topic(self):
        _setup_ntfy_env(server="https://ntfy.sh", topic="myids-secret")
        import config
        importlib.reload(config)
        from notifications import ntfy_notifier
        importlib.reload(ntfy_notifier)
        url = ntfy_notifier._build_url()
        self.assertEqual(url, "https://ntfy.sh/myids-secret")


# ===========================================================================
# 2.  Configuration validation
# ===========================================================================

class TestConfig(unittest.TestCase):

    def _reload_config(self, env: dict):
        os.environ.update(env)
        import config
        importlib.reload(config)
        return config

    def test_not_configured_when_topic_empty(self):
        cfg = self._reload_config({"NTFY_TOPIC": ""})
        self.assertFalse(cfg.ntfy_configured())

    def test_configured_when_topic_present(self):
        cfg = self._reload_config({"NTFY_TOPIC": "my-secret-topic"})
        self.assertTrue(cfg.ntfy_configured())

    def test_severity_meets_minimum_logic(self):
        cfg = self._reload_config({})
        self.assertTrue(cfg.severity_meets_minimum("HIGH",     "LOW"))
        self.assertTrue(cfg.severity_meets_minimum("MEDIUM",   "MEDIUM"))
        self.assertFalse(cfg.severity_meets_minimum("LOW",     "HIGH"))
        self.assertFalse(cfg.severity_meets_minimum("INFO",    "MEDIUM"))
        self.assertTrue(cfg.severity_meets_minimum("CRITICAL", "CRITICAL"))

    def test_validate_startup_warns_on_missing_topic(self):
        cfg = self._reload_config({
            "NTFY_TOPIC":                 "",
            "NTFY_NOTIFICATIONS_ENABLED": "true",
            "NTFY_MIN_SEVERITY":          "LOW",
        })
        warnings = cfg.validate_startup()
        self.assertTrue(len(warnings) > 0)
        self.assertTrue(any("NTFY_TOPIC" in w for w in warnings))

    def test_validate_startup_clean_when_configured(self):
        cfg = self._reload_config({
            "NTFY_TOPIC":                 "my-topic",
            "NTFY_NOTIFICATIONS_ENABLED": "true",
            "NTFY_MIN_SEVERITY":          "LOW",
        })
        warnings = cfg.validate_startup()
        self.assertEqual(warnings, [])


# ===========================================================================
# 3.  Enqueue behaviour
# ===========================================================================

class TestEnqueue(unittest.TestCase):

    def _setup_notifier(self, topic="test-topic", enabled="true", min_sev="LOW"):
        _setup_ntfy_env(topic=topic, enabled=enabled, min_sev=min_sev)
        import config
        importlib.reload(config)
        from notifications import ntfy_notifier
        importlib.reload(ntfy_notifier)
        return ntfy_notifier

    def test_enqueue_returns_false_when_disabled(self):
        notifier = self._setup_notifier(enabled="false")
        result = notifier.enqueue_alert({"type": "X", "severity": "HIGH",
                                         "source_ip": "1.1.1.1", "description": ""})
        self.assertFalse(result)

    def test_enqueue_returns_false_when_no_topic(self):
        notifier = self._setup_notifier(topic="")
        result = notifier.enqueue_alert({"type": "X", "severity": "HIGH",
                                         "source_ip": "1.1.1.1", "description": ""})
        self.assertFalse(result)

    def test_severity_filtering_blocks_low_when_min_is_high(self):
        notifier = self._setup_notifier(min_sev="HIGH")
        result = notifier.enqueue_alert({"type": "Test", "severity": "LOW",
                                         "source_ip": "1.1.1.1", "description": ""})
        self.assertFalse(result)

    def test_severity_filtering_allows_critical_when_min_is_medium(self):
        notifier = self._setup_notifier(min_sev="MEDIUM")
        from notifications import ntfy_notifier as tn
        tn._dedup_cache.clear()
        result = notifier.enqueue_alert({"type": "Critical Test", "severity": "CRITICAL",
                                         "source_ip": "2.2.2.2", "description": ""})
        self.assertTrue(result)

    def test_deduplication_suppresses_repeat(self):
        notifier = self._setup_notifier()
        from notifications import ntfy_notifier as tn
        tn._dedup_cache.clear()
        alert = {"type": "Port Scan", "severity": "HIGH",
                 "source_ip": "3.3.3.3", "description": ""}
        first  = notifier.enqueue_alert(alert)
        second = notifier.enqueue_alert(alert)
        self.assertTrue(first)
        self.assertFalse(second)  # same ip+type within dedup window

    def test_queue_full_returns_false(self):
        notifier = self._setup_notifier()
        from notifications import ntfy_notifier as tn
        tn._dedup_cache.clear()
        while True:
            try:
                tn._notify_queue.put_nowait({"dummy": True})
            except queue.Full:
                break
        result = notifier.enqueue_alert({"type": "Overflow", "severity": "HIGH",
                                          "source_ip": "4.4.4.4", "description": ""})
        self.assertFalse(result)
        # Drain for other tests
        while not tn._notify_queue.empty():
            tn._notify_queue.get_nowait()


# ===========================================================================
# 4.  HTTP send - success, errors, rate-limit, network failure
# ===========================================================================

class TestHTTPSend(unittest.TestCase):

    def _get_notifier(self):
        _setup_ntfy_env()
        import config
        importlib.reload(config)
        from notifications import ntfy_notifier
        importlib.reload(ntfy_notifier)
        return ntfy_notifier

    def test_successful_delivery_increments_sent_ok(self):
        tn = self._get_notifier()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.post", return_value=mock_resp):
            tn._send_with_retry({"type": "X", "severity": "HIGH",
                                  "source_ip": "1.1.1.1", "description": "",
                                  "event_id": "TST1", "time": "12:00:00"})
        self.assertEqual(tn._stats["sent_ok"], 1)

    def test_201_also_counts_as_success(self):
        tn = self._get_notifier()
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        with patch("requests.post", return_value=mock_resp):
            tn._send_with_retry({"type": "X", "severity": "HIGH",
                                  "source_ip": "1.1.1.1", "description": "",
                                  "event_id": "TST6", "time": "12:00:00"})
        self.assertEqual(tn._stats["sent_ok"], 1)

    def test_api_error_increments_failed(self):
        tn = self._get_notifier()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"
        with patch("requests.post", return_value=mock_resp):
            tn._send_with_retry({"type": "X", "severity": "HIGH",
                                  "source_ip": "1.1.1.1", "description": "",
                                  "event_id": "TST2", "time": "12:00:00"})
        self.assertEqual(tn._stats["failed"], 1)

    def test_timeout_retries_then_fails(self):
        import requests as req
        tn = self._get_notifier()
        with patch("requests.post", side_effect=req.exceptions.Timeout):
            with patch("time.sleep"):
                tn._send_with_retry({"type": "X", "severity": "HIGH",
                                      "source_ip": "1.1.1.1", "description": "",
                                      "event_id": "TST3", "time": "12:00:00"})
        self.assertEqual(tn._stats["failed"], 1)

    def test_rate_limit_waits_and_retries(self):
        import requests as req
        tn = self._get_notifier()
        rate_resp = MagicMock()
        rate_resp.status_code = 429
        rate_resp.headers = {"Retry-After": "1"}
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        with patch("requests.post", side_effect=[rate_resp, ok_resp]):
            with patch("time.sleep"):
                tn._send_with_retry({"type": "X", "severity": "HIGH",
                                      "source_ip": "1.1.1.1", "description": "",
                                      "event_id": "TST4", "time": "12:00:00"})
        self.assertEqual(tn._stats["sent_ok"], 1)

    def test_connection_error_retries_then_fails(self):
        import requests as req
        tn = self._get_notifier()
        with patch("requests.post", side_effect=req.exceptions.ConnectionError):
            with patch("time.sleep"):
                tn._send_with_retry({"type": "X", "severity": "HIGH",
                                      "source_ip": "1.1.1.1", "description": "",
                                      "event_id": "TST5", "time": "12:00:00"})
        self.assertEqual(tn._stats["failed"], 1)


# ===========================================================================
# 5.  IDS detection rules
# ===========================================================================

class TestIDSRules(unittest.TestCase):

    def setUp(self):
        _setup_ntfy_env()
        import config
        importlib.reload(config)
        import ids
        importlib.reload(ids)
        self.ids = ids

    def test_suspicious_port_creates_alert(self):
        pkt = _make_packet(src_ip="10.0.0.1", dst_port=4444)
        self.ids.check_packet(pkt)
        alerts = self.ids.get_alerts()
        self.assertTrue(any(a["type"] == "Suspicious Port Activity" for a in alerts))

    def test_normal_port_no_alert(self):
        pkt = _make_packet(src_ip="10.0.0.2", dst_port=443)
        self.ids.check_packet(pkt)
        alerts = self.ids.get_alerts()
        self.assertFalse(any(a["type"] == "Suspicious Port Activity" for a in alerts))

    def test_port_scan_triggers_after_threshold(self):
        src = "10.0.0.3"
        for port in range(8000, 8000 + self.ids.PORT_SCAN_THRESHOLD):
            self.ids.check_packet(_make_packet(src_ip=src, dst_port=port))
        alerts = self.ids.get_alerts()
        self.assertTrue(any(a["type"] == "Port Scan" for a in alerts))

    def test_port_scan_requires_different_ports(self):
        src = "10.0.0.4"
        importlib.reload(self.ids)
        for _ in range(20):
            self.ids.check_packet(_make_packet(src_ip=src, dst_port=80))
        alerts = self.ids.get_alerts()
        self.assertFalse(any(a["type"] == "Port Scan" for a in alerts))

    def test_alert_deduplication(self):
        importlib.reload(self.ids)
        pkt = _make_packet(src_ip="10.0.0.5", dst_port=5555)
        self.ids.check_packet(pkt)
        self.ids.check_packet(pkt)
        suspicious = [a for a in self.ids.get_alerts()
                      if a["type"] == "Suspicious Port Activity"
                      and a["source_ip"] == "10.0.0.5"]
        self.assertEqual(len(suspicious), 1)

    def test_high_traffic_rule(self):
        importlib.reload(self.ids)
        src = "10.0.0.6"
        frozen = time.time()
        with patch("time.time", return_value=frozen):
            for _ in range(self.ids.HIGH_TRAFFIC_THRESHOLD):
                self.ids.check_packet(_make_packet(src_ip=src, dst_port=80))
        alerts = self.ids.get_alerts()
        self.assertTrue(any(a["type"] == "High Traffic" for a in alerts))

    def test_alert_has_required_fields(self):
        importlib.reload(self.ids)
        self.ids.check_packet(_make_packet(src_ip="10.0.0.7", dst_port=6666))
        alerts = self.ids.get_alerts()
        self.assertTrue(len(alerts) > 0)
        a = alerts[0]
        for field in ("event_id", "time", "source_ip", "type",
                      "description", "severity", "notification_status"):
            self.assertIn(field, a, f"Missing field: {field}")


# ===========================================================================
# 6.  Logger
# ===========================================================================

class TestLogger(unittest.TestCase):

    def setUp(self):
        import logger
        importlib.reload(logger)
        self.logger = logger
        self.logger.LOG_FILE = "/tmp/test_netsentinel.csv"

    def test_log_alert_writes_row(self):
        import unittest.mock
        alert = {
            "event_id": "EV01", "severity": "HIGH", "type": "Port Scan",
            "source_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "dst_port": "80",
            "description": "test", "notification_status": "queued",
        }
        with patch("builtins.open", unittest.mock.mock_open()) as m:
            with patch("os.path.exists", return_value=True):
                with patch("os.makedirs"):
                    self.logger.log_alert(alert)
        calls = [str(c) for c in m.call_args_list]
        self.assertTrue(any("a" in c for c in calls))


# ===========================================================================
# 7.  Flask API endpoints
# ===========================================================================

class TestFlaskEndpoints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _setup_ntfy_env(topic="test-topic-abc123")
        import config
        importlib.reload(config)
        with patch("scapy.all.sniff"):
            import app as flask_app
            importlib.reload(flask_app)
            cls.client = flask_app.app.test_client()

    def test_home_returns_200(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)

    def test_api_data_returns_json(self):
        r = self.client.get("/api/data")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        for key in ("total", "tcp", "udp", "icmp", "other", "packets", "alerts"):
            self.assertIn(key, data)

    def test_notification_status_returns_json(self):
        r = self.client.get("/api/notification_status")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("enabled", data)
        self.assertIn("configured", data)

    def test_notification_status_does_not_expose_topic(self):
        r = self.client.get("/api/notification_status")
        body = r.data.decode()
        topic = os.environ.get("NTFY_TOPIC", "")
        if topic:
            self.assertNotIn(topic, body)

    def test_test_alert_endpoint_exists(self):
        r = self.client.get("/api/test_alert")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("queued", data)
        self.assertIn("message", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
