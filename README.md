# UniDetect - Passive Network Traffic Analysis (SIH Problem Statement 145)

UniDetect is a university cybersecurity prototype designed to demonstrate **PASSIVE network traffic analysis**.

The core objective of UniDetect is to monitor and analyze network activity to generate security insights and detect anomalies without disturbing live network operations.

---

## 🔒 Security & Operational Guarantees

UniDetect adheres strictly to a **passive security architecture**. Specifically:
- **No Transmissions**: UniDetect must **NOT** send packets back to the network.
- **No Scanning**: UniDetect must **NOT** scan active or inactive devices.
- **No Probing**: UniDetect must **NOT** probe network hosts.
- **No Inline Blocking or Modification**: UniDetect must **NOT** block, alter, or delay live network traffic.
- **No Socket Connections**: Analysis is performed strictly offline or near-real-time from logs on disk.

---

## 🏗️ Implementation Status & Roadmap

### ✅ IMPLEMENTED NOW
- **Offline Zeek Log Ingestion**: Batch reading of `conn.log`, `dns.log`, `weird.log`, `ntp.log`, and `quic.log` (`src/ingestion/zeek_reader.py`).
- **FlowRecord Normalization DTO**: Standardized flow schema for `conn.log` entries (`src/models/flow_record.py`).
- **Feature Extraction**: Derived metrics (`total_bytes`, `total_packets`, `bytes_per_packet`, `answer_count`) and aggregate stats (`src/features/extractor.py`).
- **Checkpoint Management**: Atomic JSON state persistence for byte resume offsets (`src/ingestion/checkpoint.py`).
- **Incremental Log Reader**: Binary tailing of growing log files, binary byte-offset seeking, partial-line buffering, and truncation detection (`src/ingestion/incremental_reader.py`).
- **Local Zeek Log Watcher**: Polling-based log watcher detecting file changes across multiple log files and triggering incremental ingestion (`src/ingestion/watcher.py`).
- **Controlled Live Zeek Runner**: Foreground runner script directing active passive interface monitoring into dedicated live log directories (`scripts/run_zeek_live.sh`).

### ⏳ FUTURE STEPS (Not Implemented Yet)
- **Live Watcher Integration**: End-to-end integration connecting `ZeekLogWatcher` to the active live log directory in real-time.
- **End-to-End Controlled Traffic Testing**: Laboratory testing using simulated traffic against the live ingestion pipeline.
- **Security Feature Engineering**: Advanced domain/flow behavioral feature sets.
- **Machine Learning / Threat Classification**: ML anomaly and threat detection models.
- **FastAPI / REST Backend**: Backend service endpoints for alert streaming.
- **Web Dashboard**: Interactive user interface.

---

## 📁 Project Structure

```
unidetect/
├── data/
│   ├── live_zeek_logs/
│   │   └── README.md
│   ├── pcaps/
│   ├── zeek_logs/
│   └── README.md
├── output/
│   ├── alerts/
│   ├── reports/
│   └── README.md
├── scripts/
│   └── run_zeek_live.sh
├── src/
│   ├── models/
│   │   ├── __init__.py
│   │   └── flow_record.py
│   ├── features/
│   │   ├── __init__.py
│   │   └── extractor.py
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── checkpoint.py
│   │   ├── incremental_reader.py
│   │   ├── watcher.py
│   │   └── zeek_reader.py
│   ├── __init__.py
│   ├── main.py
│   └── README.md
├── tests/
│   ├── test_checkpoint.py
│   ├── test_feature_extractor.py
│   ├── test_flow_record.py
│   ├── test_incremental_reader.py
│   ├── test_watcher.py
│   ├── test_zeek_reader.py
│   └── __init__.py
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🐧 Windows + WSL Live Zeek Setup & Execution

### 1. Verify Zeek Installation (WSL / Ubuntu)
```bash
zeek --version
# Expected: zeek version 8.x.x
```

### 2. Discover Network Interfaces
Identify the interface on which Zeek will passively observe traffic:
```bash
ip -br link
# or
ip link
```

### 3. Start Live Zeek Runner
Run the controlled Zeek runner with your target interface and desired output directory:
```bash
# Default output directory (data/live_zeek_logs):
./scripts/run_zeek_live.sh eth0

# Or with custom native Linux path (recommended for WSL performance):
./scripts/run_zeek_live.sh eth0 ~/unidetect-live/logs
```

### 4. Verify Live Log Generation
Open a second terminal in WSL to observe newly generated Zeek logs:
```bash
# List generated log files:
ls -lah data/live_zeek_logs

# Follow connection logs in real-time:
tail -f data/live_zeek_logs/conn.log
```

> **Note**: To stop Zeek monitoring, press `Ctrl+C` in the runner terminal.

---

## 🚀 Existing Pipeline Execution

### 1. Ingestion Summary
```bash
python src/main.py --log-dir data/zeek_logs
```

### 2. Feature Extraction Summary (`--show-features`)
```bash
python src/main.py --log-dir data/zeek_logs --show-features
```

### 3. Running All Unit Tests
```bash
python -m unittest discover -s tests
```
