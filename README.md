# Python-Based Network Monitoring and Intrusion Detection System (IDS)

## Project Overview

The **Network Monitoring and Intrusion Detection System (IDS)** is a Python-based
application that monitors network traffic in real time, detects suspicious
activities, and sends **instant push notifications to your Android phone** via ntfy.

Built for a Computer Networks college mini-project.

## Features

| Feature | Description |
|---|---|
| Live Packet Monitoring | Captures packets and shows source IP, destination IP, protocol, and port |
| Traffic Statistics | Displays total packets and TCP / UDP / ICMP counts |
| Intrusion Detection | Port scan, high-traffic flood, and suspicious-port rules |
| Real-Time Alerts | Alerts shown on the web dashboard with severity, IP, and timestamp |
| Push Notifications | Instant Android push via **ntfy** (no Telegram, no Firebase) |
| Event Logging | All alerts saved to `logs/network_events.csv` |
| Web Dashboard | Flask dashboard auto-refreshes every 2 seconds |
| Background Detection | IDS runs even when the browser tab is closed |

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.10+ | Main programming language |
| Flask | Web dashboard |
| Scapy | Packet capture and analysis |
| ntfy | Android push notifications via HTTPS |
| python-dotenv | Environment-variable configuration |
| requests | HTTP client for ntfy API |
| HTML / CSS / JS | Dashboard frontend |
| CSV | Alert log storage |

## Project Structure

```
Python-Based-Network-Monitoring-and-Intrusion-Detection-System-IDS-/
|
|-- app.py                      Flask application and routes
|-- packet_monitor.py           Background Scapy packet capture thread
|-- ids.py                      Intrusion detection rules engine
|-- logger.py                   CSV alert logger
|-- config.py                   Environment-variable loader
|
|-- notifications/
|   |-- __init__.py
|   |-- ntfy_notifier.py        ntfy push-notification worker
|
|-- templates/
|   `-- index.html              Dashboard HTML
|
|-- static/
|   `-- style.css               Dashboard CSS
|
|-- tests/
|   `-- test_notifier.py        Automated test suite (39 tests)
|
|-- logs/
|   `-- network_events.csv      Alert log (created automatically)
|
|-- .env                        Your local secrets (never commit this)
|-- .env.example                Template for .env
|-- requirements.txt            Python dependencies
`-- README.md
```

---

## Windows 11 Setup (Step-by-Step)

### Prerequisites

- Windows 11
- Python 3.10 or later (from https://python.org – tick "Add to PATH")
- Visual Studio Code or any terminal
- Administrator privileges (required for packet capture)

---

### Step 1 — Install Npcap

Npcap enables raw packet capture on Windows.

1. Download the installer from **https://npcap.com/**
2. Run the installer as Administrator.
3. Accept the defaults (tick "WinPcap API-compatible Mode" if asked).
4. Restart your PC or open a new terminal after installing.

---

### Step 2 — Clone or Open the Project

Open the project folder in VS Code or navigate to it in PowerShell:

```powershell
cd "C:\Users\ACER\Desktop\mini project CN\Python-Based-Network-Monitoring-and-Intrusion-Detection-System-IDS-"
```

---

### Step 3 — Install Python Dependencies

Run this in the project folder (inside the VS Code terminal or PowerShell):

```powershell
pip install -r requirements.txt
```

`requirements.txt` contains:

```
flask>=3.0.0
scapy>=2.5.0
python-dotenv>=1.0.0
requests>=2.31.0
```

---

### Step 4 — Install the ntfy Android App

1. Open the **Google Play Store** on your Android phone.
2. Search for **ntfy** or go to:
   `https://play.google.com/store/apps/details?id=io.heckel.ntfy`
3. Install and open the app.
4. Tap the **+** (plus) button to subscribe to a topic.
5. **Choose a unique, hard-to-guess topic name**, for example:
   ```
   netsentinel-lab-2026-abc7k
   ```
   > Anyone who knows your topic name can send you notifications, so keep it
   > random and private. Do not use your name or a dictionary word alone.
6. Tap **Subscribe** — your phone is now listening.

---

### Step 5 — Configure the .env File

Copy the example file and add your topic:

```powershell
copy .env.example .env
```

Open `.env` in VS Code (or Notepad) and set your topic:

```env
NTFY_TOPIC=netsentinel-lab-2026-abc7k
NTFY_SERVER=https://ntfy.sh
NTFY_NOTIFICATIONS_ENABLED=true
NTFY_MIN_SEVERITY=LOW
NTFY_REQUEST_TIMEOUT=5
NTFY_MAX_RETRIES=3
NTFY_ACCESS_TOKEN=
NTFY_CLICK_URL=
NOTIFICATION_QUEUE_SIZE=100
```

> **Important:** Never commit `.env` to Git.
> It is already listed in `.gitignore`.

---

### Step 6 — Run the Application (as Administrator)

Scapy needs Administrator privileges to capture packets on Windows.

**Option A – VS Code (recommended for demo):**

Right-click VS Code in the Start Menu → **Run as administrator**,
then open a terminal inside VS Code and run:

```powershell
python app.py
```

**Option B – PowerShell as Administrator:**

```powershell
# Right-click PowerShell > "Run as Administrator"
cd "C:\Users\ACER\Desktop\mini project CN\Python-Based-Network-Monitoring-and-Intrusion-Detection-System-IDS-"
python app.py
```

You should see:

```
========================================
  NetSentinel -- Network IDS
========================================
  Dashboard : http://127.0.0.1:5000
  ntfy      : enabled
========================================
Starting network monitoring...
```

---

### Step 7 — Open the Dashboard

Open your browser and visit:

```
http://127.0.0.1:5000
```

The dashboard will:
- Show live packet counts (TCP, UDP, ICMP).
- Show the last 20 captured packets.
- Show all IDS security alerts.
- Show ntfy notification status (Sent / Failed / Pending).

---

### Step 8 — Send a Test Notification

1. On the dashboard, find the **ntfy Notifications** bar at the top.
2. Click **Send Test**.
3. Your phone should receive a notification within 1–3 seconds.

If it does not arrive:
- Check that your topic in `.env` matches the topic in the ntfy app.
- Check your internet connection.
- Run the manual curl test below.

**Manual curl test (PowerShell):**

```powershell
curl -X POST "https://ntfy.sh/YOUR-TOPIC-HERE" `
     -H "Title: NetSentinel Test" `
     -d "Test message from NetSentinel IDS"
```

Replace `YOUR-TOPIC-HERE` with your actual topic name.

---

## How Push Notifications Work

```
IDS detects alert
      |
      v
ids.py  _create_alert()
      |
      v
ntfy_notifier.enqueue_alert()   <-- non-blocking, returns immediately
      |
      v
Background worker thread
      |
      v
HTTPS POST to https://ntfy.sh/<topic>
      |
      v
ntfy app on Android phone  -->  push notification
```

The notification includes:
- **Title:** `[HIGH] Port Scan - NetSentinel`
- **Priority:** mapped from severity (urgent/high/default/low/min)
- **Body:** Source IP, detected time, description, event ID
- **Tag emoji:** matching severity level

---

## Example Push Notification (on your phone)

```
[HIGH] Port Scan - NetSentinel

Source IP : 192.168.1.105
Detected  : 14:22:07
Details   : Probed 10 unique ports in 30s
Event ID  : A3F1B2C4
```

---

## Triggering a Test Intrusion (Safe Demo)

To demonstrate a port scan alert during a college presentation, open a second
PowerShell window and run:

```powershell
# Windows: scan using nmap (install from https://nmap.org)
nmap -p 1-100 127.0.0.1
```

Or use Python (no extra install):

```python
import socket, time
for port in range(8000, 8015):
    try:
        s = socket.socket()
        s.settimeout(0.1)
        s.connect(("127.0.0.1", port))
        s.close()
    except:
        pass
    time.sleep(0.05)
print("Port scan simulation complete")
```

Save as `simulate_scan.py` and run:

```powershell
python simulate_scan.py
```

Within a few seconds you should see a "Port Scan" alert on the dashboard and
receive a push notification on your phone.

---

## Running the Test Suite

```powershell
python -m pytest tests/ -v
```

Expected output: **39 passed** — no real network access or Npcap required.

The tests cover:
- ntfy message body and header formatting
- Configuration validation
- Enqueue behaviour (disabled, missing topic, severity filter, dedup, queue full)
- HTTP send: success, 201, error, rate-limit, timeout, connection error
- IDS rules: suspicious port, port scan, high traffic, deduplication
- Logger: CSV append
- Flask endpoints: home, /api/data, /api/notification_status, /api/test_alert

---

## Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| Suspicious Port Activity | Traffic to port 4444, 5555, or 6666 | HIGH |
| Port Scan | >= 10 unique destination ports from one IP in 30 seconds | HIGH |
| High Traffic | >= 100 packets from one IP within 5 seconds | MEDIUM |

---

## Log File

Alerts are appended to:

```
logs/network_events.csv
```

Columns: Timestamp, Event ID, Severity, Alert Type, Source IP,
Destination IP, Destination Port, Description, Notification Status.

Open with Excel or any CSV viewer.

---

## Known Limitations

- **ntfy.sh is a public service** — anyone who discovers your topic name can
  send messages to it. Use a random, hard-to-guess topic.
- **Windows Defender / firewall** may interfere with Scapy packet capture.
  Running as Administrator usually resolves this.
- **No real-time graphs** — statistics are polled every 2 seconds.
- **Detection rules are simple** — this is an educational prototype, not an
  enterprise IDS. Expect false positives on busy networks.
- **Flask development server** is for local/demo use only.
- **If the internet is unavailable**, the ntfy worker retries with
  exponential back-off and logs failures, but local monitoring and
  the dashboard continue working.
- **ntfy free tier** has no authentication by default. For real use,
  consider a self-hosted ntfy instance with access control.

---

## Security Notes

- Never commit `.env` to Git.
- The `/api/notification_status` endpoint intentionally omits your topic name.
- Run packet monitoring only on networks you are authorised to monitor.
- Captured traffic may contain sensitive data. Protect your log files.

---

## Project Information

**Project Name:** Python-Based Network Monitoring and Intrusion Detection System (IDS)

**Domain:** Computer Networks and Cybersecurity

**Project Type:** Educational / Academic

---

## License

Educational use. Add a license file if you plan to distribute publicly.
