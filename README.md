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

UniDetect receives mirrored network traffic or offline packet capture/log files, ingests raw records, extracts behavioral features, and produces structured analysis summaries.

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
│   ├── features/
│   │   ├── __init__.py
│   │   └── extractor.py
│   ├── ingestion/
│   │   ├── __init__.py
│   │   └── zeek_reader.py
│   ├── __init__.py
│   ├── main.py
│   └── README.md
├── tests/
│   ├── test_feature_extractor.py
│   ├── test_zeek_reader.py
│   └── __init__.py
├── .gitignore
├── requirements.txt
└── README.md
```

---

## ⚙️ Step 3: Feature Extraction Layer

UniDetect converts raw ingested Zeek log entries into structured, normalized network behavioral features.

### Extracted & Derived Features

1. **Connection Features (`conn.log`):**
   - Core identifiers: `uid`, `timestamp`, `source_ip`, `source_port`, `destination_ip`, `destination_port`, `protocol`, `service`, `connection_state`.
   - Raw metrics: `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, `missed_bytes`.
   - **Derived metrics:**
     - `total_bytes = orig_bytes + resp_bytes`
     - `total_packets = orig_pkts + resp_pkts`
     - `bytes_per_packet = total_bytes / total_packets` (0.0 if total_packets is 0)

2. **DNS Features (`dns.log`):**
   - Query details: `uid`, `timestamp`, `source_ip`, `destination_ip`, `query`, `qtype_name`, `rcode_name`.
   - **Derived metrics:**
     - `answers`: Parsed list of returned IP/domain string answers.
     - `answer_count`: Length of returned DNS answers.

3. **Summary Statistics:**
   - Aggregated metrics across connection and DNS records: `total_connections`, `total_dns_queries`, `unique_source_ips`, `unique_destination_ips`, `total_bytes_observed`, `total_packets_observed`, and counters for protocols, services, and connection states.

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

**Example Output:**
```text
UniDetect Passive Traffic Analysis
----------------------------------
conn.log records: 2
dns.log records: 1
weird.log records: 1
ntp.log records: 1
quic.log records: 1

Feature Extraction Summary
--------------------------
Total connections: 2
Total DNS queries: 1
Unique source IPs: 1
Unique destination IPs: 4
Total bytes observed: 4835
Total packets observed: 12

Protocols:
udp: 1
tcp: 1

Services:
dns: 1
http: 1

Connection States:
SF: 2
```

### 3. Running All Unit Tests
```bash
python -m unittest discover -s tests
```
