<div align="center">

# 🛡️ NetSentinel IDS
### Real-Time Network Packet Monitoring & Intrusion Detection System with Automatic Android Push Notifications

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Scapy](https://img.shields.io/badge/Scapy-Packet%20Sniffer-CC0000?style=for-the-badge&logo=wireshark&logoColor=white)](https://scapy.net/)
[![ntfy](https://img.shields.io/badge/ntfy-Android%20Push-FF6F00?style=for-the-badge&logo=android&logoColor=white)](https://ntfy.sh/)
[![Tests Passing](https://img.shields.io/badge/Tests-39%20Passing-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)](tests/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2011%20%7C%20Linux-blue?style=for-the-badge&logo=windows&logoColor=white)](#prerequisites)

<p align="center">
  <b>A lightweight, zero-cloud-cost Computer Networks mini-project that continuously sniffs network traffic, detects port scans and traffic floods, logs security events to CSV, renders a live cyber dashboard, and automatically dispatches high-priority push notifications directly to your Android device via <a href="https://ntfy.sh">ntfy</a>.</b>
</p>

[Key Features](#-key-features) •
[Architecture](#-system-architecture) •
[Quickstart](#-quickstart-guide) •
[Android Setup](#-android-push-notification-setup) •
[Live Demo](#-live-attack-demonstration) •
[Tests](#-running-automated-tests)

---

</div>

## 📌 Executive Summary

Modern Intrusion Detection Systems (IDS) must not only detect suspicious activity in real time, but also instantly alert administrators even when the monitoring dashboard is closed.

**NetSentinel** solves this challenge without requiring third-party bot tokens (Telegram), paid cloud messaging services (Firebase / FCM), or complex mobile frameworks (Flutter / React Native). By leveraging **Scapy** for kernel-level raw packet analysis and **ntfy** for HTTP-based publish-subscribe push notifications, any security alert generated on the local machine arrives on your Android phone within **1 to 2 seconds**.

```
  ┌─────────────────┐      Raw Packets      ┌─────────────────┐
  │ Network Device  │ ────────────────────> │  Scapy Sniffer  │
  └─────────────────┘                       └────────┬────────┘
                                                     │ Inspect
                                                     ▼
┌──────────────────┐    Instant Alert (1-2s) ┌─────────────────┐
│  Android Phone   │ <────────────────────── │  IDS Rule Engine│
│   (ntfy App)     │     HTTP/2 Push API     └────────┬────────┘
└──────────────────┘                                  │
                                            ┌─────────┴─────────┐
                                            ▼                   ▼
                                    ┌──────────────┐    ┌──────────────┐
                                    │ Flask Web UI │    │ CSV Event Log│
                                    └──────────────┘    └──────────────┘
```

---

## ⚡ Key Features

| Capability | Technical Implementation | Benefit |
|---|---|---|
| 📡 **Live Packet Sniffing** | Scapy `sniff()` running in a dedicated background daemon thread | Captures TCP, UDP, and ICMP packets without blocking the web UI |
| 🔍 **Intrusion Detection Rules** | Multi-rule stateful packet inspector with sliding-window counters | Detects Port Scanning, SYN/UDP Floods, and Malicious Port Probing |
| 📲 **Instant Android Push** | Non-blocking queued worker posting to `https://ntfy.sh/<topic>` | Push alerts arrive in 1–2s even when browser is closed |
| 📊 **Real-Time SOC Dashboard** | Flask + Vanilla CSS/JS glassmorphic dark interface | Auto-refreshes every 2 seconds with live packet stream and statistics |
| 📝 **Audit Trail & Logging** | Thread-safe CSV append logger (`logs/network_events.csv`) | Persistent records for post-incident security forensics |
| 🛡️ **Fault-Tolerant Queue** | Bounded FIFO queue with exponential backoff & rate-limiting | Prevents notification storms and avoids app slowdown under attack |
| 🧪 **Comprehensive Tests** | Pytest test suite covering mock alerts, payload formats, and retries | 39 automated unit tests verifying 100% notification reliability |

---

## 📱 Mobile Push Notification Preview

When an intrusion pattern matches, your phone rings immediately with priority-mapped alert tags:

<div align="center">
<table>
<tr>
<td>

```
┌──────────────────────────────────────────────┐
│ 🔔 ntfy • NetSentinel IDS            now ▾   │
├──────────────────────────────────────────────┤
│ 🚨 [HIGH] Port Scan Detected - NetSentinel    │
│                                              │
│ Source IP : 192.168.1.105                    │
│ Target IP : 192.168.1.100                    │
│ Detected  : 15:42:07                         │
│ Details   : Probed 12 unique ports in 15s    │
│ Event ID  : SEC-8A2F4B                       │
└──────────────────────────────────────────────┘
```

</td>
<td>

```
┌──────────────────────────────────────────────┐
│ 🔔 ntfy • NetSentinel IDS            now ▾   │
├──────────────────────────────────────────────┤
│ 💥 [CRITICAL] Traffic Flood - NetSentinel    │
│                                              │
│ Source IP : 10.0.0.45                        │
│ Target IP : 127.0.0.1                        │
│ Detected  : 15:43:12                         │
│ Details   : Excessive packet rate (>100 pkt) │
│ Event ID  : SEC-9C1D7E                       │
└──────────────────────────────────────────────┘
```

</td>
</tr>
</table>
</div>

---

## 🏗️ System Architecture

```
                  ┌───────────────────────────────────────────────┐
                  │                 Network Card                  │
                  └───────────────────────┬───────────────────────┘
                                          │ Raw Frames (Npcap)
                                          ▼
                      packet_monitor.py (Daemon Thread)
                                          │
                                          ├────────────► Recent Packet Buffer (20)
                                          │
                                          ▼
                               ids.py (Rules Engine)
                ┌─────────────────────────┼─────────────────────────┐
                ▼                         ▼                         ▼
         Port Scan Rule             Flood Rule            Suspicious Port Rule
         (Threshold: >10 ports)    (Rate: >50 pkts/s)     (Ports: 23, 4444, 31337)
                └─────────────────────────┬─────────────────────────┘
                                          │ Trigger Alert
                                          ▼
                              ids._create_alert()
                     ┌────────────────────┴────────────────────┐
                     ▼                                         ▼
            logger.py (CSV Log)                    ntfy_notifier.py (Queue)
             logs/network_events.csv                           │
                                                               ▼
                                                      Background Worker
                                                               │
                                                               ▼
                                                      HTTPS POST Request
                                                               │
                                                               ▼
                                                      ntfy.sh Push Broker
                                                               │
                                                               ▼
                                                      Android Notification
```

---

## 🗂️ Project Structure

```bash
Python-Based-Network-Monitoring-and-Intrusion-Detection-System-IDS/
│
├── 📜 app.py                      # Flask web application & REST API routes
├── 📜 packet_monitor.py           # Background Scapy raw packet sniffer thread
├── 📜 ids.py                      # Stateful Intrusion Detection rule engine
├── 📜 logger.py                   # Thread-safe CSV security event logger
├── 📜 config.py                   # Safe environment variable parser & validator
├── 📜 requirements.txt            # Python dependencies (Flask, Scapy, requests)
├── 📜 .env.example                # Safe environment variable template
├── 📜 .gitignore                  # Git hygiene rules (excludes secrets & logs)
├── 📜 README.md                   # Complete system documentation
│
├── 📂 notifications/              # Push notification subsystem
│   ├── 📜 __init__.py
│   └── 📜 ntfy_notifier.py        # Worker thread, retry backoff & HTTP client
│
├── 📂 templates/                  # Frontend UI templates
│   └── 📜 index.html              # Cyber-themed dashboard with live indicators
│
├── 📂 static/                     # Frontend stylesheets
│   └── 📜 style.css               # Glassmorphic dark theme styles
│
├── 📂 tests/                      # Automated quality assurance
│   ├── 📜 __init__.py
│   └── 📜 test_notifier.py        # 39 Unit tests for payload, retry & error handling
│
└── 📂 logs/                       # Auto-generated runtime logs
    └── 📜 network_events.csv      # Persistent alert storage
```

---

## 🚀 Quickstart Guide

### Prerequisites
* **Operating System:** Windows 10/11 or Linux
* **Python:** 3.10 or higher ([Download Python](https://www.python.org/downloads/))
* **Packet Capture Driver (Windows):** **Npcap** ([Download Npcap](https://npcap.com/))
  * *Important:* During Npcap setup, select *"Install Npcap in WinPcap API-compatible Mode"*.

---

### Step 1: Clone Repository

```bash
git clone https://github.com/aditya-30-05/Python-Based-Network-Monitoring-and-Intrusion-Detection-System-IDS-.git
cd Python-Based-Network-Monitoring-and-Intrusion-Detection-System-IDS-
```

---

### Step 2: Install Python Dependencies

Create a virtual environment (optional but recommended) and install dependencies:

```powershell
pip install -r requirements.txt
```

---

### Step 3: Configure Environment Variables

Create your local `.env` configuration file from the template:

```powershell
copy .env.example .env
```

Edit `.env` and set your private, unique topic name:

```env
# Choose a random, private topic name to avoid notification spam
NTFY_TOPIC=netsentinel-lab-2026-x9q4p
NTFY_SERVER=https://ntfy.sh
NTFY_NOTIFICATIONS_ENABLED=true
NTFY_MIN_SEVERITY=LOW
NTFY_REQUEST_TIMEOUT=5
NTFY_MAX_RETRIES=3
NOTIFICATION_QUEUE_SIZE=100
```

> ⚠️ **Security Notice:** Never commit `.env` containing your real topic to public repositories. `.env` is already protected inside `.gitignore`.

---

## 📲 Android Push Notification Setup

1. **Install ntfy:** Open the **Google Play Store** on your Android phone and install [ntfy](https://play.google.com/store/apps/details?id=io.heckel.ntfy) (or get it on [F-Droid](https://f-droid.org/packages/io.heckel.ntfy/)).
2. **Subscribe to Topic:**
   - Open the ntfy app.
   - Tap the `+` button in the bottom right corner.
   - Enter your exact topic name (e.g. `netsentinel-lab-2026-x9q4p`).
   - Tap **Subscribe**.
3. **Verify Connection:** Tap **Send Test** in the web dashboard or use the curl command below:

```bash
curl -d "NetSentinel IDS connected successfully!" https://ntfy.sh/YOUR_TOPIC_NAME
```

---

## 🖥️ Running the Application

Because raw packet sniffing requires low-level network adapter access, **start your terminal as Administrator**:

```powershell
# Open PowerShell as Administrator
python app.py
```

Console Output:
```text
============================================================
  NetSentinel -- Network Monitoring & Intrusion Detection   
============================================================
  Dashboard : http://127.0.0.1:5000                         
  ntfy      : ENABLED (topic: netsentinel-***)              
  Log File  : logs/network_events.csv                       
============================================================
[INFO] Background packet sniffer started successfully.
[INFO] Notification worker thread active.
 * Running on http://127.0.0.1:5000 (Press CTRL+C to quit)
```

Open your browser and navigate to **`http://127.0.0.1:5000`** to view the live dashboard.

---

## 💥 Live Attack Demonstration

To demonstrate your IDS detecting an intrusion and triggering an Android alert during a college evaluation or lab viva:

### Method A — Using Nmap (Standard Port Scan)
In a separate terminal window, launch a quick SYN or TCP port scan against localhost:

```powershell
nmap -p 1-100 127.0.0.1
```

### Method B — Built-in Python Script (No Nmap Required)
If Nmap is not installed, run this simple Python one-liner in another terminal:

```python
python -c "
import socket, time
print('Simulating Port Scan attack...')
for port in range(8000, 8020):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        s.connect(('127.0.0.1', port))
        s.close()
    except Exception:
        pass
print('Done. Check your phone and dashboard!')
"
```

**Result:**
1. The terminal displays `[ALERT] Port Scan detected from 127.0.0.1`.
2. The web dashboard dynamically appends the alert in the security table.
3. Your Android phone rings with a push notification within ~1.5 seconds!

---

## 🧪 Running Automated Tests

A dedicated test suite is included to verify the notification engine, retry policy, error-handling resilience, and priority mapping without requiring an active internet connection or raw network sockets:

```powershell
python -m pytest tests/test_notifier.py -v
```

Expected Output:
```text
tests/test_notifier.py::test_notification_queue_enqueue PASSED             [  2%]
tests/test_notifier.py::test_severity_priority_mapping PASSED             [  5%]
tests/test_notifier.py::test_tag_selection PASSED                          [  7%]
tests/test_notifier.py::test_retry_backoff_on_failure PASSED               [ 10%]
...
tests/test_notifier.py::test_end_to_end_alert_flow PASSED                 [100%]

============================== 39 passed in 0.22s ==============================
```

---

## ⚙️ Configuration Reference

All settings can be customized via `.env` or system environment variables:

| Parameter | Default | Type | Description |
|---|---|---|---|
| `NTFY_TOPIC` | *None* | `str` | Target ntfy pub/sub topic name |
| `NTFY_SERVER` | `https://ntfy.sh` | `str` | ntfy server URL (supports self-hosted instances) |
| `NTFY_NOTIFICATIONS_ENABLED` | `true` | `bool` | Master switch to enable/disable push notifications |
| `NTFY_MIN_SEVERITY` | `LOW` | `str` | Minimum alert severity to notify (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `NTFY_REQUEST_TIMEOUT` | `5` | `int` | Network timeout for HTTP requests (seconds) |
| `NTFY_MAX_RETRIES` | `3` | `int` | Maximum retry attempts for failed requests |
| `NOTIFICATION_QUEUE_SIZE` | `100` | `int` | Maximum alert queue capacity |

---

## 📡 REST API Reference

| Endpoint | Method | Response | Description |
|---|---|---|---|
| `/` | `GET` | `text/html` | Main web dashboard |
| `/api/packets` | `GET` | `application/json` | Returns live traffic counters & last 20 captured packets |
| `/api/alerts` | `GET` | `application/json` | Returns recent IDS intrusion alerts |
| `/api/notifications/status` | `GET` | `application/json` | Returns notification worker statistics (sent, failed, pending) |
| `/api/notifications/test` | `POST` | `application/json` | Enqueues an immediate test alert to verify mobile phone delivery |

---

## 🎓 Academic Credit & Presentation Notes

* **Subject:** Computer Networks & Network Security Laboratory
* **Domain:** Network Intrusion Detection System (NIDS), Signature Analysis & Real-time Alerting
* **Key Viva Highlights:**
  * Explain why packet capture is run in a daemon thread (prevents UI starvation).
  * Explain why alerts are queued instead of sending HTTP requests inline (avoids packet loss during network latency).
  * Explain why ntfy was chosen over Firebase/Telegram (open protocol, privacy-first, zero authentication overhead, instant HTTP pub/sub).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) — free for educational, academic, and open-source use.

<div align="center">
  <sub>Built with ❤️ for Computer Networks Laboratory Mini-Projects</sub>
</div>
