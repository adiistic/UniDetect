# Forensic & Data Quality Audit: Experiment `exp_slow_http_001`

**Experiment ID**: `exp_slow_http_001`  
**Class**: `SLOW_HTTP` (`label_id = 7`)  
**Traffic Generator**: `slowloris` (Slow Header Starvation) + Custom Slow-POST Clients  
**Target Endpoint**: `127.0.0.1:8080`  
**Audit Date**: 2026-09-01  
**Audit Type**: Low-Rate Application-Layer Starvation Audit  

---

## 1. Executive Summary

Experiment `exp_slow_http_001` adds the **`SLOW_HTTP`** application-layer starvation threat modality to the UniDetect candidate dataset. Unlike high-volume transport flooding, slow-HTTP attacks occupy server connection tables using minimal bandwidth over prolonged durations.

### Key Metrics:
- **Total Flows Extracted**: `50 flows` (100% labeled `SLOW_HTTP`, `label_id = 7`)
- **Protocol**: `TCP` (50 flows, 100%)
- **Target Endpoint**: `127.0.0.1:8080` (HTTP Server)
- **Mean Flow Duration**: `3.2123s` (Significantly prolonged relative to benign web transactions)
- **Mean Origin Bytes**: `167.22 B` (Slow fragmented header/body chunks)
- **Packets Captured**: `654 packets` across 9.744s
- **PCAP File Size**: `70,244 bytes` (68.6 KB)
- **Connection States**: `{'S0': 1, 'RSTO': 49}`
- **Total Missed Bytes**: `0.0 bytes` (100% capture completeness)
- **Weird Anomalies**: `[]` (0 anomalies)
- **Feature Matrix Quality**: 0 NaNs, 0 Infs, 0 missing features across all `50 x 78` cells.

---

## 2. Cross-Class Comparison: SLOW_HTTP vs. BENIGN HTTP vs. Volumetric DDOS

| Feature Subspace / Dimension | BENIGN HTTP (Exp 003) | SLOW_HTTP (Exp 001) | DDOS SYN Flood (Exp 001) | DDOS UDP Flood (Exp 002) |
| :--- | :--- | :--- | :--- | :--- |
| **Transport Protocol** | TCP (`proto_is_tcp = 1.0`) | **TCP (`proto_is_tcp = 1.0`)** | TCP (`proto_is_tcp = 1.0`) | UDP (`proto_is_udp = 1.0`) |
| **Mean Duration (idx=0)** | 0.0003s – 0.002s (Instant) | **0.85s – 4.50s (Prolonged)** | 0.0000s (Instant Drop) | 0.0000s (Instant Drop) |
| **Origin Payload Bytes (idx=1)** | 68 B – 350 B (Full HTTP GET) | **198 B – 250 B (Fragmented)** | 0 B (Headers only) | 453 B (Datagrams) |
| **Response Bytes (idx=2)** | 148 B – 2,500 B (200 OK Body)| **0 B – 163 B (Incomplete)** | 0 B (No response) | 0 B (No response) |
| **Flow Rate (idx=57)** | 0.5 – 2.0 flows/s (Low) | **3.0 – 8.0 flows/s (Moderate)**| > 50.0 flows/s (Massive) | > 50.0 flows/s (Massive) |
| **Packets per Flow (idx=6)** | 4 – 10 pkts/flow | **12 – 24 pkts/flow** | 2 pkts/flow | 2 pkts/flow |
| **Connection State SF (idx=20)** | 1.00 (100% Established) | **0.00 – 0.15 (Starvation)** | 0.00 (0% SF) | 0.00 (0% SF) |
| **Connection State RSTO/REJ** | 0.00 (Clean close) | **RSTO / Active holding** | 100% REJ | 100% S0 |

---

## 3. Potential Shortcut & Leakage Features

- **Local Port / IP**: Target destination port `8080` and localhost `127.0.0.1` are experiment artifacts and must not be used as standalone ML shortcuts.
- **Behavioral Distinguishers**: The true threat signature relies on **joint multi-feature interactions**:
  1. Prolonged `flow_duration` combined with low `orig_bytes` (low byte throughput per second).
  2. High `total_packets` relative to low payload bytes (repeated 1-byte keep-alive fragments).
  3. Starvation connection states (`RSTO`) contrasted with benign rapid `SF` completion.

---

## 4. Retain Decision & Next Steps

1. **Retention**: **RETAIN `exp_slow_http_001` FOR ML TRAINING**.
2. **Schema Stability**: Canonical 78-feature schema remains 100% preserved.
3. **Data Quality**: 0 missed bytes, 0 NaNs, 0 Infs, 0 missing values.
