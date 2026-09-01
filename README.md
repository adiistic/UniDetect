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
- **No Socket Connections**: Analysis is performed strictly offline from logs/captures on disk.

---

## 🏗️ System Architecture

UniDetect receives mirrored network traffic or offline packet capture/log files, ingests the data passively, and outputs structured analysis results and alerts.

```
Traffic Copy / PCAP / PCAPNG
              │
              ▼
          Zeek Logs
 (conn.log, dns.log, etc.)
              │
              ▼
         UniDetect
 (Passive Ingestion & Analysis)
              │
              ▼
      Analysis Results
     (Alerts & Reports)
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
│   ├── ingestion/
│   │   ├── __init__.py
│   │   └── zeek_reader.py
│   ├── __init__.py
│   ├── main.py
│   └── README.md
├── tests/
│   ├── __init__.py
│   └── test_zeek_reader.py
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🚀 Step 2: Zeek Log Ingestion Usage

UniDetect implements an offline TSV log reader for Zeek log files (`conn.log`, `dns.log`, `weird.log`, `ntp.log`, `quic.log`).

### 1. Running the Ingestion CLI

Pass the target log directory containing Zeek logs using `--log-dir`:

```bash
python src/main.py --log-dir data/zeek_logs
```

**Example Output:**
```text
UniDetect Passive Traffic Analysis
----------------------------------
conn.log records: 2
dns.log records: 1
weird.log records: 1
ntp.log records: 1
quic.log records: 1
```

### 2. Running Unit Tests

Run the test suite using Python's standard `unittest` framework:

```bash
python -m unittest discover -s tests
```
