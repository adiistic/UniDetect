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

## 🏗️ System Architecture

UniDetect receives mirrored network traffic or offline packet capture/log files, ingests raw records, normalizes flow records, extracts behavioral features, and produces structured analysis summaries.

```
Traffic Copy / PCAP / PCAPNG
              │
              ▼
          Zeek Logs
 (conn.log, dns.log, etc.)
              │
              ▼
      Zeek Log Ingestion
  (src/ingestion/zeek_reader.py)
              │
              ▼
    Local Checkpoint Manager
  (src/ingestion/checkpoint.py)
              │
              ▼
      Normalized Flow Model
   (src/models/flow_record.py)
              │
              ▼
      Feature Extraction
 (src/features/extractor.py)
              │
              ▼
   Structured Behavioral Data
    (Alerts & Reports Input)
```

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
│   │   └── zeek_reader.py
│   ├── __init__.py
│   ├── main.py
│   └── README.md
├── tests/
│   ├── test_checkpoint.py
│   ├── test_feature_extractor.py
│   ├── test_flow_record.py
│   ├── test_zeek_reader.py
│   └── __init__.py
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🔖 State & Checkpoint Management (`src/ingestion/checkpoint.py`)

UniDetect includes a local `CheckpointManager` module in preparation for future near-real-time incremental Zeek log ingestion.

### Key Principles & Policy:
- **Purpose**: Persists file read positions and identity metadata so incremental readers can resume processing across runs without reprocessing normal records.
- **Default Checkpoint Path**: `data/.unidetect_checkpoint.json` (configurable via `CheckpointManager(checkpoint_path=...)`).
- **Authoritative Resume Position**: Byte offset (`offset`) is the sole authoritative position for resuming ingestion.
- **File Identity Metadata**: Records canonical file paths, byte sizes, OS inodes (`inode`), and device IDs (`device`) across platforms to track log files.
- **Atomic Writes**: Writes updated state to a `.tmp` file in the checkpoint directory before executing an atomic file replacement (`os.replace`) to prevent state corruption during ungraceful shutdowns.
- **Corrupt Checkpoint Policy**: If a checkpoint file is unparseable or malformed, `CheckpointManager` emits a warning, preserves the corrupt file on disk, and initializes a valid empty in-memory state.

---

## 📊 Normalized Flow Record Schema (`FlowRecord`)

UniDetect defines a normalized DTO in `src/models/flow_record.py` for structured handoff between Person 1's ingestion layer and downstream processing:

```json
{
  "timestamp": 1618317000.123,
  "uid": "CH432111",
  "source": {"ip": "192.168.1.50", "port": 51234},
  "destination": {"ip": "192.168.1.1", "port": 53},
  "network": {"protocol": "udp", "service": "dns"},
  "metrics": {
    "duration": 0.002341,
    "orig_bytes": 45,
    "resp_bytes": 110,
    "total_bytes": 155,
    "orig_packets": 1,
    "resp_packets": 1,
    "total_packets": 2,
    "bytes_per_packet": 77.5,
    "missed_bytes": 0
  },
  "connection_state": "SF",
  "metadata": {"history": "Dd", "local_orig": "-"}
}
```

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
