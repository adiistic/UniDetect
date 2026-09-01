# UniDetect - Passive Network Traffic Analysis

UniDetect is a university cybersecurity prototype designed to demonstrate **PASSIVE network traffic analysis**.

The core objective of UniDetect is to monitor and analyze network activity to generate security insights and detect anomalies without disturbing live network operations.

---

## 🔒 Security & Operational Guarantees

UniDetect adheres strictly to a **passive security architecture**. Specifically:
- **No Transmissions**: UniDetect must **NOT** send packets back to the network.
- **No Scanning**: UniDetect must **NOT** scan active or inactive devices.
- **No Probing**: UniDetect must **NOT** probe network hosts.
- **No Inline Blocking or Modification**: UniDetect must **NOT** block, alter, or delay live network traffic.
- **No Socket Connections**: Analysis is performed strictly offline or near-real-time from logs/captures on disk.

---

## 🏗️ Implementation Status & Roadmap

### ✅ IMPLEMENTED NOW
- **Offline Zeek Log Ingestion**: Batch reading of `conn.log`, `dns.log`, `weird.log`, `ntp.log`, and `quic.log` (`src/ingestion/zeek_reader.py`).
- **FlowRecord Normalization DTO**: Standardized flow schema for `conn.log` entries (`src/models/flow_record.py`).
- **Feature Extraction**: Derived metrics (`total_bytes`, `total_packets`, `bytes_per_packet`, `answer_count`) and aggregate stats (`src/features/extractor.py`).
- **Checkpoint Management**: Atomic JSON state persistence for byte resume offsets (`src/ingestion/checkpoint.py`).
- **Incremental Log Reader**: Binary tailing of growing log files, binary byte-offset seeking, partial-line buffering, and truncation detection (`src/ingestion/incremental_reader.py`).
- **Local Zeek Log Watcher**: Polling-based log watcher detecting file changes across multiple log files and triggering incremental ingestion (`src/ingestion/watcher.py`).

### ⏳ NOT YET IMPLEMENTED (Future Milestones)
- **Live Zeek Packet Observation**: Live Zeek engine execution on mirrored interface.
- **Live Packet Capture**: Active packet capture drivers.
- **Dummy Website Traffic Generation**: Automated test traffic generators.
- **Machine Learning / Threat Classification**: ML detection engines.
- **FastAPI / REST Backend**: Backend service endpoints.
- **Web Dashboard**: Interactive user interface.

---

## 📁 Project Structure

```
unidetect/
├── data/
│   ├── pcaps/
│   ├── zeek_logs/
│   └── README.md
├── output/
│   ├── alerts/
│   ├── reports/
│   └── README.md
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

## 👁️ Local Log Watcher (`src/ingestion/watcher.py`)

The `ZeekLogWatcher` monitors local Zeek log files using lightweight polling and coordinates with `IncrementalZeekReader` to stream new entries without modifying log files.

### Key Features:
- **Polling-Based Change Detection**: Cross-platform polling (`poll_once()`) using file size, inode, and checkpoint offset comparisons.
- **Multiple File Support**: Monitors `conn.log`, `dns.log`, etc., independently.
- **Missing File Resilience**: Gracefully skips missing files during poll passes; automatically detects and processes files if created later.
- **Error Isolation**: Catches and logs errors on individual files without crashing or halting the watcher loop for other files.
- **FlowRecord Integration**: Returns normalized `FlowRecord` DTOs directly when querying connection logs.

---

## 🚀 Execution & Usage

### 1. Ingestion Summary Only
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
