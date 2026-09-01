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
- **Live Zeek Directory Pipeline**: Integration layer connecting watcher, incremental reader, and checkpointing to actively monitor live Zeek log directories and stream `FlowRecord` objects (`src/ingestion/live_pipeline.py`).

### ⏳ NOT YET IMPLEMENTED (Future Steps)
- **Controlled Dummy Website Traffic**: Simulated test traffic generation for laboratory validation.
- **Full Live End-to-End Traffic Validation**: Automated end-to-end integration testing against continuous live traffic.
- **Security-Specific Feature Engineering**: Advanced behavioral and anomaly feature representations.
- **Machine Learning / Threat Classification**: ML training, inference, and alert generation.
- **FastAPI / REST Backend**: Backend service endpoints for live alert streaming.
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
│   │   ├── live_pipeline.py
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
│   ├── test_live_pipeline.py
│   ├── test_watcher.py
│   ├── test_zeek_reader.py
│   └── __init__.py
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🔄 Live Zeek Directory Pipeline (`src/ingestion/live_pipeline.py`)

The `LiveZeekPipeline` connects `ZeekLogWatcher`, `IncrementalZeekReader`, and `CheckpointManager` into a unified pipeline:

```
Zeek-Generated Log Files (conn.log, dns.log, weird.log)
                         │
                         ▼
        LiveZeekPipeline (`live_pipeline.py`)
                         │
                         ▼
             ZeekLogWatcher (`watcher.py`)
                         │
                         ▼
       IncrementalZeekReader (`incremental_reader.py`)
                         │
                         ▼
         CheckpointManager (`checkpoint.py`)
                         │
                         ▼
         FlowRecord (`models/flow_record.py`)
```

---

## 🚀 Execution & Usage

### 1. Offline Batch Ingestion
```bash
python src/main.py --log-dir data/zeek_logs
```

### 2. Offline Feature Extraction Summary
```bash
python src/main.py --log-dir data/zeek_logs --show-features
```

### 3. Live Zeek Log Directory Polling Mode
Demonstrates single-pass incremental polling of an active Zeek log directory:
```bash
python src/main.py --live-log-dir data/zeek_logs
```

### 4. Running All Automated Tests
```bash
python -m unittest discover -s tests
```
