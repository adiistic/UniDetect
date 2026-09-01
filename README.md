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

### ⏳ NOT YET IMPLEMENTED (Future Milestones)
- **Filesystem Watcher / Poller Loop**: Continuous file watching loops.
- **Live Zeek Capture Runner**: Integration with active network SPAN/TAP taps.
- **Machine Learning / Threat Classification**: ML detection engines.
- **FastAPI / REST Backend**: API service endpoints.
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
│   │   └── zeek_reader.py
│   ├── __init__.py
│   ├── main.py
│   └── README.md
├── tests/
│   ├── test_checkpoint.py
│   ├── test_feature_extractor.py
│   ├── test_flow_record.py
│   ├── test_incremental_reader.py
│   ├── test_zeek_reader.py
│   └── __init__.py
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🔖 Incremental Log Reader (`src/ingestion/incremental_reader.py`)

The `IncrementalZeekReader` prepares UniDetect for future near-real-time ingestion by tailing active Zeek log files without re-reading previously processed records.

### Key Features:
- **Binary Seeking**: Seeks directly to the authoritative byte offset (`start_offset`) stored in `CheckpointManager`.
- **Incomplete Line Safety**: Ignores incomplete final lines (lines not ending in `\n`) and defers their processing until completion without advancing the saved offset past incomplete data.
- **Truncation & Replacement Handling**: Resets read offset to 0 if the current file size is smaller than the saved offset or if the file inode/device ID changes.
- **UTF-8 Byte Safety**: Operates strictly on byte offsets to guarantee character boundary safety across multi-byte UTF-8 encodings.

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
