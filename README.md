# UniDetect - Passive Network Traffic Analysis & Threat Detection Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.0+-61DAFB.svg)](https://react.dev)
[![Architecture](https://img.shields.io/badge/Architecture-Passive%20Telemetry-orange.svg)]()
[![Security](https://img.shields.io/badge/Security-Zero%20Active%20Probing-green.svg)]()

**UniDetect** is an end-to-end cybersecurity prototype designed for **passive network traffic monitoring, calibrated machine learning threat detection, and real-time Security Operations Center (SOC) visualization** (developed for Smart India Hackathon - Problem Statement 145).

UniDetect ingests raw Zeek network logs from disk, correlates auxiliary network protocols (DNS, SSL/TLS, Weird, QUIC), aggregates causal sliding-window behaviors, extracts a 78-dimensional behavioral feature vector, applies a calibrated multi-class machine learning detector with selective abstention, and streams threat telemetry live to an interactive web dashboard over WebSockets.

---

## 🔒 Passive Security Guarantees

UniDetect adheres strictly to **passive-only security invariants**:
- **Zero Active Transmissions**: UniDetect **never** transmits packets onto the monitored network.
- **Zero Host Probing / Scanning**: UniDetect **never** initiates TCP handshakes, ICMP pings, or port scans.
- **Zero Inline Disruption**: Traffic is monitored out-of-band via log files or tap/mirror interfaces without inline filtering, delay, or packet modification.
- **Zero Payload Decryption**: Analysis relies entirely on statistical, volumetric, temporal, and metadata features; encrypted payloads are never decrypted.

---

## 🏗️ System Architecture

```
                                  PASSIVE TELEMETRY PIPELINE
                                  
   +--------------------+     +------------------------------------------------------+
   | Live Network Tap / | --> | Zeek Network Monitor (Passive Engine)                |
   | Recorded PCAP Logs |     | Generates: conn.log, dns.log, ssl.log, weird.log     |
   +--------------------+     +------------------------------------------------------+
                                                         |
                                                         v
                              +------------------------------------------------------+
                              | RealtimeInferencePipeline (src/inference/pipeline.py) |
                              | 1. LogCorrelator (DNS/SSL/Weird event indexing)       |
                              | 2. WindowAggregator (Causal temporal sliding windows) |
                              | 3. FeatureVectorAssembler (78-D float vector)        |
                              +------------------------------------------------------+
                                                         |
                                                         v
                              +------------------------------------------------------+
                              | Frozen Calibrated ML Detector (models/phase6e)       |
                              | CalibratedClassifierCV(HistGradientBoosting)         |
                              | Classes: BENIGN, DDOS, RECON, SLOW_HTTP,             |
                              |          DNS_TUNNEL, C2_BEACON                       |
                              | Policy: AUTOMATED_DETECTION vs ANALYST_REVIEW        |
                              +------------------------------------------------------+
                                                         |
                                                         v
                              +------------------------------------------------------+
                              | FastAPI Backend Server (src/api/app.py)              |
                              | - Thread-Safe Bounded AlertStore                     |
                              | - REST API Endpoints (/api/v1/alerts, /metrics)     |
                              | - WebSocket Alert Streaming (/ws/alerts)             |
                              +------------------------------------------------------+
                                         |                                |
                                   REST  |                          WS    |
                                         v                                v
                              +------------------------------------------------------+
                              | React SOC Web Dashboard (http://127.0.0.1:8000)      |
                              | - Real-time Streaming Alert Feed                     |
                              | - Telemetry Metric Cards & Latency Gauges            |
                              | - Threat Distribution & Activity Timeline Charts     |
                              | - Forensic Alert Inspector Modal                     |
                              | - Model Architecture & Feature Contract Drawer       |
                              +------------------------------------------------------+
```

---

## 📋 Prerequisites & Installation

### Requirements
- **Operating System**: Windows, Linux, or macOS
- **Python**: Version 3.10, 3.11, 3.12, or 3.13+
- **Browser**: Chrome, Firefox, Edge, or Safari

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/adiistic/UniDetect.git
   cd unidetectml
   ```

2. **Create and activate a virtual environment (recommended)**:
   ```bash
   # Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

*(Note: The React SOC dashboard is already pre-compiled into `frontend/dist` and is automatically served by FastAPI out of the box — no separate Node.js build step is required for demonstration).*

---

## 🎯 How to Show This Idea Working (Demonstration Guide)

Follow this 3-step walkthrough to demonstrate the full end-to-end UniDetect pipeline to evaluators or stakeholders:

### Step 1: Start the Backend & React SOC Dashboard

Open **Terminal 1** and launch the UniDetect FastAPI backend:

```powershell
python src/main.py --dashboard --port 8000
```

You will see:
```text
================================================================================
Launching UniDetect SOC Dashboard & FastAPI Streaming Backend
  Dashboard UI:           http://127.0.0.1:8000
  REST API:               http://127.0.0.1:8000/api/v1/alerts
  WebSocket Stream:       ws://127.0.0.1:8000/ws/alerts
  Interactive OpenAPI:    http://127.0.0.1:8000/docs
================================================================================
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

### Step 2: Open the Dashboard in Your Browser

Open your browser and navigate to:
```text
http://127.0.0.1:8000
```

- Notice the clean SOC dashboard UI with connection indicator `CONNECTED` in green.
- Initially, counters will read `0 Observed Flows`, `0 Confirmed Threats`, and the alert table will be awaiting traffic.

### Step 3: Run the Multi-Class Threat Replay Demo

Open a second terminal (**Terminal 2**) and execute the replay demonstration script:

```powershell
python scripts/run_phase8_demo.py
```

This script reads real-world retained Zeek telemetry from 6 distinct cyber attack experiments, passes them through the causal 78-dimensional feature assembler and calibrated ML model, and transmits the resulting alert events into the live running server:

```text
================================================================================
UniDetect Phase 8: FastAPI Backend & Dashboard Integration Demo
Target Server: http://127.0.0.1:8000
WebSocket URL: ws://127.0.0.1:8000/ws/alerts
================================================================================

1. Initial Health & Status Verification against Running Server:
  GET /health -> HTTP 200 (9.41ms): {'status': 'ok', 'model_loaded': True, ...}

2. Replaying Multi-Class Traffic into Real Backend via POST /api/v1/demo/alerts:
  [WebSocket] Connected to ws://127.0.0.1:8000/ws/alerts - listening for real-time alert broadcasts...
  [WebSocket Live Stream Verified] Received broadcast alert: fef25afb... (Label: BENIGN)
  [exp_benign_periodic_007  | BENIGN     ] Ingested 63 alerts -> Threats: 0, Benign: 63
  [exp_ddos_syn_001         | DDOS       ] Ingested 150 alerts -> Threats: 150, Benign: 0
  [exp_recon_001            | RECON      ] Ingested 59 alerts -> Threats: 54, Benign: 3
  [exp_slow_http_001        | SLOW_HTTP  ] Ingested 50 alerts -> Threats: 50, Benign: 0
  [exp_dns_tunnel_001       | DNS_TUNNEL ] Ingested 52 alerts -> Threats: 44, Benign: 8
  [exp_c2_beacon_001        | C2_BEACON  ] Ingested 50 alerts -> Threats: 50, Benign: 0

Total Replayed Alerts Stored on Server: 424

3. Testing REST API Query Endpoints on Real Server:
  GET /api/v1/alerts?limit=10 -> HTTP 200 (2.14ms) | Total in Store: 424, Items Returned: 10
  GET /api/v1/alerts?threat_class=C2_BEACON -> HTTP 200 | Matching Alerts: 50
  GET /api/v1/metrics -> HTTP 200 | Total Flows: 424 | Threats: 348 | Latency Avg: 20.67ms
  GET /api/v1/status -> HTTP 200 | Processed Flows: 424 | Threat Alerts: 348
```

### Step 4: Explore the Live Dashboard Features

Switch back to your browser at `http://127.0.0.1:8000`:
1. **Live Metric Cards**: Instantly updates to display **424 Total Observed Flows**, **348 Confirmed Threats**, **74 Benign Flows**, and **2 Analyst Reviews**.
2. **Threat Distribution Chart**: Visualizes the proportional breakdown across `DDOS`, `RECON`, `SLOW_HTTP`, `DNS_TUNNEL`, `C2_BEACON`, and `BENIGN`.
3. **Activity Timeline**: Displays flow frequency and threat spikes across timestamps.
4. **Live Alert Table**:
   - Displays incoming alerts in real time with class badges, calibrated confidence scores (e.g. `98.5%`), decision tags (`AUTOMATED_DETECTION` vs `ANALYST_REVIEW`), protocol, source/destination IPs and ports, and inference latency.
   - Use the **Search Bar** to filter by IP or Port (e.g., search `192.168.1.50` or `80`).
   - Use the **Class Filter** dropdown to filter by specific attack classes (e.g., `C2_BEACON`, `DDOS`, `DNS_TUNNEL`).
   - Click the **Pause / Resume** button to freeze the live feed for inspection.
5. **Forensic Alert Inspector**: Click on any alert row in the table to open a detailed modal showing:
   - Full 6-class calibrated probability distribution bar chart.
   - 5-tuple network identifiers and ISO timestamp.
   - Flow metrics (duration, originator bytes, responder bytes, connection state).
6. **Model Specification Drawer**: Click **"Model Specs"** in the top header to inspect the frozen ML model details:
   - Model Version: `unidetect-hgb-calibrated-v1.0.0`
   - Classifier Type: `CalibratedClassifierCV(HistGradientBoostingClassifier, method='sigmoid', cv=3)`
   - Feature Dimension: `78 features` (Feature contract compliant)
   - Decision Policy Thresholds: Abstain threshold `0.40`, Recon threshold `0.35`

---

## 🛠️ CLI Operational Modes

UniDetect can also be run in standalone command-line modes:

### 1. Offline Log Directory Threat Detection
Run calibrated ML detection over a directory of historical Zeek logs:
```powershell
python src/main.py --predict --log-dir data/zeek_logs
```
Outputs total flows processed, detected threats per class, analyst reviews, benign count, mean latency per flow, and sample AlertEvent JSON records.

### 2. Live Incremental Zeek Polling
Poll an actively written Zeek log directory incrementally using atomic byte checkpoints:
```powershell
python src/main.py --live-log-dir data/zeek_logs
```

### 3. Feature Extraction Summary
Extract and inspect statistical summaries of connections, protocols, services, and byte volumes:
```powershell
python src/main.py --show-features --log-dir data/zeek_logs
```

---

## 🧪 How to Run Automated Tests

UniDetect includes an extensive automated test suite covering unit, integration, ML inference, and API streaming functionality:

### Run Full Test Suite (117 Tests)
```powershell
python -m unittest discover tests
```

### Run FastAPI Backend & WebSocket Streaming Tests
```powershell
python -m unittest tests/test_phase8_backend.py
```

### Run Frozen ML Inference & Decision Policy Tests
```powershell
python -m unittest tests/test_phase6e_inference.py
```

### Run Real-Time Streaming & Sliding Window Tests
```powershell
python -m unittest tests/test_phase7_streaming.py
```

---

## 🌐 REST API & WebSocket Documentation

When the backend server is running on `http://127.0.0.1:8000`, interactive Swagger/OpenAPI documentation is available at:
👉 **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

### Key API Endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Server health, model loaded status, and schema versions |
| `GET` | `/api/v1/status` | Real-time flow counts, threat alert totals, uptime |
| `GET` | `/api/v1/alerts` | Paginated threat alerts with class and decision filters |
| `GET` | `/api/v1/alerts/{alert_id}` | Detailed alert record with probabilities and flow metadata |
| `GET` | `/api/v1/metrics` | Class distribution, total flows, and latency percentiles (p50, p95) |
| `GET` | `/api/v1/model` | Frozen ML model architecture, thresholds, active classes |
| `POST`| `/api/v1/demo/alerts` | Controlled demo telemetry ingestion & WebSocket broadcast |
| `WS`  | `/ws/alerts` | Real-time WebSocket streaming feed of AlertEvent JSON payloads |

---

## 📁 Repository Structure

```
unidetectml/
├── data/
│   ├── experiments/            # Retained multi-class Zeek experiment logs
│   │   ├── BENIGN/             # Baseline periodic benign activity
│   │   ├── DDOS/               # SYN and UDP flood attack logs
│   │   ├── RECON/              # Port scan & reconnaissance logs
│   │   ├── SLOW_HTTP/          # Slowloris HTTP attack logs
│   │   ├── DNS_TUNNEL/         # DNS exfiltration query logs
│   │   └── C2_BEACON/          # Command & Control beaconing logs
│   ├── master/                 # Phase 6A master training dataset & profile
│   └── zeek_logs/              # Offline sample Zeek log files
├── frontend/                   # React SOC Dashboard source & pre-built assets
│   ├── dist/                   # Production-built static assets served by FastAPI
│   ├── src/                    # TypeScript, React components, CSS design system
│   └── package.json
├── models/
│   └── phase6e/                # Frozen ML model artifacts & contracts
│       ├── model/model.joblib  # Calibrated multi-class classifier
│       ├── feature_contract/   # 78-dimensional feature specification
│       ├── thresholds/         # Operational decision policy thresholds
│       └── metadata/           # Model version and provenance metadata
├── reports/                    # Evaluation reports, confusion matrices, summaries
│   └── phase8/demo_summary.json# Replay demo execution summary
├── scripts/
│   └── run_phase8_demo.py      # End-to-end replay & live dashboard demo script
├── src/
│   ├── api/                    # FastAPI routes, WebSocket manager, state & schemas
│   │   ├── app.py              # FastAPI app factory & WebSocket stream
│   │   ├── dependencies.py     # State & manager dependency injectors
│   │   ├── routes.py           # REST route definitions
│   │   ├── schemas.py          # Pydantic request & response models
│   │   ├── state.py            # Thread-safe in-memory AlertStore
│   │   └── websocket.py        # Asynchronous WebSocket subscriber manager
│   ├── features/               # 78D feature extraction & window aggregation
│   ├── inference/              # Real-time ML inference pipeline & alert schemas
│   │   ├── alert.py            # AlertEvent dataclass & serialization
│   │   ├── contract.py         # Feature contract validator
│   │   ├── detector.py         # Calibrated ML threat detector & policy
│   │   └── pipeline.py         # RealtimeInferencePipeline orchestrator
│   ├── ingestion/              # Passive Zeek log readers, watchers, & checkpoints
│   └── main.py                 # Primary CLI & web server entrypoint
├── tests/                      # 117 automated unit & integration test cases
├── requirements.txt            # Python dependencies
└── README.md                   # Project documentation
```

---

## 🏆 Project Achievements & Benchmarks

- **78-Dimensional Causal Feature Space**: Incorporates volumetric ratios, flow inter-arrival jitter, sliding-window host interaction densities, connection state distributions, DNS entropy, and SSL cipher diversity without leaking future information.
- **Calibrated Decision Policy**: Employs sigmoid probability calibration to enable operational thresholds (`0.40` confidence boundary for automated defense vs analyst review).
- **Sub-25ms Processing Latency**: Real-time feature assembly, calibrated ML inference, and WebSocket transmission processes flows in **~20.6ms mean latency per flow** (~48 flows/sec per CPU core).
- **Zero Inline Impact**: Certified passive architecture — perfectly suited for university campus networks, hospital IT, or enterprise environments requiring non-disruptive cyber defense.
