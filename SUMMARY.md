# UniDetect — Project Status & Implementation Summary
**Passive Network Traffic Analysis & Machine Learning Threat Detection (SIH PS 145)**

*Generated on: 2026-09-02*

---

## 📌 Executive Summary

**UniDetect** is a high-performance, passive cybersecurity network analysis and threat detection system designed for institutional and university campus networks. Operating under **SIH Problem Statement 145**, UniDetect monitors network telemetry derived from [Zeek Network Security Monitor](https://zeek.org/) without transmitting active probes, injecting packets, or interrupting live network traffic.

To date, the project has established:
1. **Passive Log Ingestion & Incremental Tailing Architecture**: High-speed, crash-consistent, byte-offset tracking and incremental live log streaming.
2. **Unified Data Transfer Object (DTO) Layer**: Normalized, typed representations of network flows.
3. **Authoritative 78-Dimensional Feature Engineering Engine**: Mathematical, protocol-specific, cross-log correlated, and sliding-window temporal feature extraction.
4. **Controlled Traffic Generation & Experimentation Suite**: Reproducible laboratory traffic generators and experiments capturing PCAPs, Zeek logs, and feature matrices across multiple threat modalities.
5. **Comprehensive Test & Audit Suite**: 63 passing unit/integration tests and automated statistical validation scripts.

---

## 🔒 Passive Security & Operational Guarantees

UniDetect adheres strictly to a **passive-only** architectural model:
- **Zero Inbound/Outbound Active Packets**: The engine does not send packets, perform port scans, or probe connected endpoints.
- **Zero Inline Delay or Traffic Alteration**: Operates entirely out-of-band on tap/mirror feeds or offline log captures.
- **Disk-Decoupled / Near-Real-Time Analysis**: Ingestion works via file system watchers and incremental binary tailing of logs produced by Zeek.

---

## 🏗️ Implemented Architecture & Subsystems

```
                                    +----------------------------------------+
                                    |     Raw Network Traffic / PCAPs        |
                                    +----------------------------------------+
                                                        |
                                                        v
                                    +----------------------------------------+
                                    |   Zeek Network Security Monitor        |
                                    | (conn.log, dns.log, weird.log, etc.)   |
                                    +----------------------------------------+
                                                        |
                        +-------------------------------+-------------------------------+
                        |                                                               |
                        v                                                               v
         [ Offline Batch Ingestion ]                                      [ Live Directory Tailing ]
          src/ingestion/zeek_reader.py                                      src/ingestion/watcher.py
                        |                                                 src/ingestion/incremental_reader.py
                        |                                                 src/ingestion/checkpoint.py
                        +-------------------------------+-------------------------------+
                                                        |
                                                        v
                                        +-------------------------------+
                                        |    Normalized FlowRecord DTO  |
                                        |    src/models/flow_record.py  |
                                        +-------------------------------+
                                                        |
                        +-------------------------------+-------------------------------+
                        |                               |                               |
                        v                               v                               v
             [ Multi-Log Correlator ]       [ Mathematical Utilities ]     [ Sliding-Window Aggregator ]
             src/features/correlator.py     src/features/math_utils.py     src/features/window_aggregator.py
            (UID & Host IP indexing)       (Shannon entropy, IP tests)    (10s, 60s, 300s lookback windows)
                        |                               |                               |
                        +-------------------------------+-------------------------------+
                                                        |
                                                        v
                                        +-------------------------------+
                                        |  78-D Vector Assembler Matrix |
                                        |  src/features/vector_assembler.py
                                        |  src/features/schema.py       |
                                        +-------------------------------+
                                                        |
                                                        v
                                        +-------------------------------+
                                        |  ML Dataset & Candidate Corpus|
                                        |  data/experiments/            |
                                        +-------------------------------+
```

---

## 📦 Detailed Breakdown of Code Modules

### 1. Ingestion Layer (`src/ingestion/`)
- [`zeek_reader.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/ingestion/zeek_reader.py):
  - Ingests standard Zeek ASCII/TSV logs (`conn.log`, `dns.log`, `weird.log`, `ntp.log`, `quic.log`, `ssl.log`).
  - Automatically parses headers (`#fields`, `#types`), skips comment delimiters, coerces types, and normalizes null/empty indicators (`-`, `(empty)`).
- [`checkpoint.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/ingestion/checkpoint.py):
  - `CheckpointManager` maintains crash-consistent byte resume offsets per monitored log file.
  - Employs atomic write operations (`tempfile` + `os.replace`) to prevent state corruption during sudden shutdowns.
- [`incremental_reader.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/ingestion/incremental_reader.py):
  - `IncrementalZeekReader` performs binary byte seeking (`seek(offset)`) to read only new lines appended to growing log files.
  - Handles incomplete/partial-line buffering across poll cycles and detects file truncation or log rotations.
- [`watcher.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/ingestion/watcher.py):
  - `ZeekLogWatcher` monitors directories for file modifications using configurable polling intervals and isolated exception handling.
- [`live_pipeline.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/ingestion/live_pipeline.py):
  - `LiveZeekPipeline` coordinates the watcher, incremental reader, and checkpoint manager to output normalized flow streams in real time.

### 2. Data Models (`src/models/`)
- [`flow_record.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/models/flow_record.py):
  - Provides strongly-typed data structures: `Endpoint` (IP, port), `NetworkInfo` (protocol, service, transport), `Metrics` (durations, byte/packet counts, ratios), and `FlowRecord`.
  - Includes `normalize_conn_record()` for uniform conversion of raw log dictionaries into standardized DTOs.

### 3. Feature Engineering Engine (`src/features/`)
- [`schema.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/features/schema.py):
  - Specifies the authoritative **78-feature numerical schema** in deterministic order (Index 0 to 77), along with baseline imputation defaults and 9 target PS 145 threat classes (`BENIGN`, `DDOS`, `RECON`, `DGA`, `DNS_TUNNEL`, `C2_BEACON`, `ENCRYPTED_SESSION`, `SLOW_HTTP`, `EXFILTRATION`).
- [`math_utils.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/features/math_utils.py):
  - Shannon entropy calculation for domain names and SNI strings.
  - RFC 1918 private IP address classification (`is_private_ip`).
  - DNS lexical metrics: subdomain depth, maximum label length, numeric character ratio, and vowel ratio.
- [`correlator.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/features/correlator.py):
  - `LogCorrelator` builds fast in-memory indexes mapping `FlowRecord` objects to auxiliary log events (`dns.log`, `weird.log`, `quic.log`, `ssl.log`) using Zeek connection UIDs and IP host tuples.
- [`window_aggregator.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/features/window_aggregator.py):
  - `WindowAggregator` computes 22 sliding-window behavioral features across 10-second, 60-second, and 300-second lookback horizons.
  - Tracks flow rates, fan-out degrees (unique destination IPs and ports), failed connection ratios, S0 SYN flood ratios, outbound byte velocities, and inter-arrival time statistics (mean $\mu$, standard deviation $\sigma$, and coefficient of variation $\text{CV} = \sigma / \mu$) for C2 beaconing detection.
- [`vector_assembler.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/features/vector_assembler.py):
  - `FeatureVectorAssembler` transforms flow records and correlated contexts into exact 78-dimensional float vectors with strict validation against `NaN` and `Inf`.
  - Exposes `extract_feature_matrix()` for batch extraction across entire log directories.
- [`extractor.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/features/extractor.py):
  - Offline aggregate statistics extractor for high-level summaries.

---

## 📊 The 78-Dimensional Feature Schema

| Section | Feature Indices | Feature Domain | Key Features / Description |
|---|---|---|---|
| **1. Flow-Level** | 0 – 26 (27 features) | `conn.log` / `FlowRecord` | `flow_duration`, `orig_bytes`, `resp_bytes`, `total_bytes`, `orig_packets`, `resp_packets`, `total_packets`, `bytes_per_packet`, `orig_bytes_ratio`, `orig_packets_ratio`, `bytes_asymmetry_ratio`, `missed_bytes`, port categories (`is_well_known_dst_port`, `is_registered_dst_port`, `is_dynamic_dst_port`), RFC 1918 flags (`is_src_private_ip`, `is_dst_private_ip`), protocol one-hot (`proto_is_tcp`, `proto_is_udp`, `proto_is_icmp`), connection states (`conn_state_is_SF`, `conn_state_is_S0`, `conn_state_is_REJ`, `conn_state_is_RSTO`), history flags (`history_len`, `history_has_syn`, `history_has_reset`). |
| **2. DNS-Level** | 27 – 39 (13 features) | `dns.log` | `has_dns_context`, `dns_query_len`, `dns_query_entropy`, `dns_subdomain_depth`, `dns_max_label_len`, `dns_numeric_ratio`, `dns_vowel_ratio`, query types (`dns_qtype_is_A`, `dns_qtype_is_TXT`, `dns_qtype_is_NULL`), `dns_is_nxdomain`, `dns_answer_count`, `dns_rtt`. |
| **3. QUIC-Level** | 40 – 43 (4 features) | `quic.log` | `has_quic_context`, `quic_sni_len`, `quic_sni_entropy`, `quic_dcid_len`. |
| **4. Protocol Anomalies** | 44 – 48 (5 features) | `weird.log` | `has_weird_anomaly`, `weird_anomaly_count_flow`, `weird_is_bad_syn_ack`, `weird_is_bad_http`, `weird_notice_flag`. |
| **5. TLS / SSL** | 49 – 55 (7 features) | `ssl.log` | `has_ssl_context`, `ssl_sni_len`, `ssl_sni_entropy`, `ssl_is_outdated_version`, `ssl_is_self_signed`, `ssl_has_ja3_fingerprint`, `ssl_resumed_flag`. |
| **6. Behavioral Windows** | 56 – 77 (22 features) | Temporal Aggregates | **Source IP Window (56–67)**: `win_src_flow_count_60s`, `win_src_flow_rate_10s`, `win_src_unique_dst_ips_60s`, `win_src_unique_dst_ports_60s`, `win_src_failed_conn_ratio_60s`, `win_src_s0_syn_ratio_60s`, `win_src_total_orig_bytes_300s`, `win_src_outbound_byte_rate_60s`, `win_src_dns_query_count_60s`, `win_src_dns_nxdomain_ratio_60s`, `win_src_dns_unique_domains_60s`, `win_src_weird_count_60s`.<br>**Destination IP Window (68–71)**: `win_dst_inbound_flow_rate_10s`, `win_dst_unique_sources_60s`, `win_dst_s0_syn_ratio_10s`, `win_dst_avg_bytes_per_flow_60s`.<br>**Host-Pair Window (72–77)**: `win_pair_flow_count_300s`, `win_pair_delta_t_mean`, `win_pair_delta_t_std`, `win_pair_delta_t_cv`, `win_pair_orig_bytes_std`, `win_pair_total_orig_bytes_300s`. |

---

## 🧪 Experiments & Dataset Inventory

The laboratory generation suite has produced **655 validated candidate feature vectors** across 6 distinct traffic classes, with full artifact preservation (PCAP, Zeek logs, JSONL vectors, `metadata.json`, and `AUDIT.md`).

### Authoritative Retained Experiment Matrix (12 Experiments)

| Class | Experiment ID | Traffic Generator / Description | Validated Vectors | PCAP Size | Associated Zeek Logs | Key Feature Separators |
|---|---|---|---|---|---|---|
| **BENIGN** | `exp_benign_iperf_002` | Controlled TCP/UDP bandwidth load | 9 | 74.6 MB | `conn.log`, `packet_filter.log` | High bytes/pkt (~1460 B), state `SF`, balanced flows |
| **BENIGN** | `exp_benign_multi_003` | Multi-protocol web browsing & downloads | 15 | 3.97 MB | `conn.log`, `dns.log`, `files.log`, `http.log` | Standard HTTP/DNS interactions, realistic entropy |
| **BENIGN** | `exp_benign_dns_004` | Diverse realistic DNS queries (A, TXT, NX) | 20 | 4.7 KB | `conn.log`, `dns.log` | Natural lexical ratios, normal subdomain depths |
| **BENIGN** | `exp_benign_tls_005` | Modern TLS 1.2/1.3 encrypted HTTPS sessions | 8 | 141.7 KB | `conn.log`, `ssl.log` | Valid SNI, standard entropy, valid certificates |
| **BENIGN** | `exp_benign_mixed_006` | Mixed multi-service web, chunked assets, burst-idle | 28 | 328.7 KB | `conn.log`, `dns.log`, `http.log`, `ssl.log` | Anti-shortcut baseline: multi-port, multi-duration, burst-idle |
| **BENIGN** | `exp_benign_periodic_007`| Legitimate periodic health checks, scrapes, DNS | 63 | 122.9 KB | `conn.log`, `dns.log`, `http.log`, `ssl.log` | Hard-negative periodic baseline ($CV \approx 0.17$, 5 ports) |
| **DDOS** | `exp_ddos_syn_001` | TCP SYN flood attack (unanswered SYNs) | 150 | 21.0 KB | `conn.log`, `reporter.log` | `conn_state_is_S0=1.0`, `orig_bytes=0`, high flow rate |
| **DDOS** | `exp_ddos_udp_002` | High-rate UDP datagram flood | 151 | 162.6 KB | `conn.log` | `proto_is_udp=1.0`, high inbound flow rate, fixed payloads |
| **RECON** | `exp_recon_001` | Multi-host / multi-port TCP SYN port scan | 59 | 17.4 KB | `conn.log`, `dns.log`, `http.log` | High `win_src_unique_dst_ports_60s`, high failed ratio |
| **SLOW_HTTP** | `exp_slow_http_001` | Slowloris / Slow HTTP POST connection hold | 50 | 70.2 KB | `conn.log`, `files.log`, `http.log` | Extended `flow_duration` (avg 3.2s vs <0.01s), low byte rate |
| **DNS_TUNNEL** | `exp_dns_tunnel_001` | Base32/Hex encoded DNS data exfiltration | 52 | 13.8 KB | `conn.log`, `dns.log` | High `dns_query_entropy` (3.9+), high `dns_subdomain_depth` |
| **C2_BEACON** | `exp_c2_beacon_001` | Periodic HTTP Command & Control heartbeats | 50 | 81.8 KB | `conn.log`, `http.log`, `files.log` | Low inter-arrival jitter (`win_pair_delta_t_cv = 0.137`), uniform size |
| **TOTAL** | **12 Experiments** | **Authoritative Corpus Total** | **655** | **~75.9 MB** | — | **100% Zero-Loss Capture (0.0 missed bytes)** |

> **Comprehensive Corpus Audit**: See [`FINAL_PHASE5_AUDIT.md`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/FINAL_PHASE5_AUDIT.md) for full forensic validation, causal temporal checks, and Phase 6 train/test split guidelines.

---

## 🔬 Multi-Class Statistical Feature Divergence

Statistical comparisons across generated datasets demonstrate high discriminatory power across the 78-dimensional space:

```
Feature Comparison Across Attack Modalities vs Benign:
------------------------------------------------------------------------------------------------------------------------
Feature Name                  | BENIGN (Avg)   | DDOS SYN (Avg) | DDOS UDP (Avg) | RECON (Avg)    | SLOW_HTTP | C2_BEACON
------------------------------------------------------------------------------------------------------------------------
flow_duration                 | 0.052 s        | 0.000 s        | 0.000 s        | 0.103 s        | 3.212 s   | 0.001 s
total_bytes                   | 3,812 B        | 0 B            | 1,024 B        | 53 B           | 326 B     | 471 B
bytes_per_packet              | 524 B          | 0 B            | 1,024 B        | 8.3 B          | 25.2 B    | 33.6 B
proto_is_tcp                  | 0.82           | 1.00           | 0.00           | 1.00           | 1.00      | 1.00
proto_is_udp                  | 0.18           | 0.00           | 1.00           | 0.00           | 0.00      | 0.00
conn_state_is_SF              | 0.94           | 0.00           | 1.00           | 0.35           | 0.90      | 1.00
conn_state_is_S0              | 0.00           | 1.00           | 0.00           | 0.40           | 0.00      | 0.00
win_src_flow_rate_10s         | 1.48 flows/s   | 7.55 flows/s   | 7.55 flows/s   | 2.46 flows/s   | 2.55 f/s  | 1.82 f/s
win_pair_delta_t_cv (Jitter)  | 0.170 (varies) | 0.883          | 0.000          | 0.704          | 2.379     | 0.137 (strict)
dns_query_entropy             | 2.15           | 0.00           | 0.00           | 0.00           | 0.00      | 0.00 (tunnel=3.9+)
```

---

## 🛠️ Testing & Quality Assurance

The codebase features an exhaustive automated test suite running with Python `unittest`:

```bash
python -m unittest discover -s tests
```
- **Total Tests**: **113 tests** across 12 test suites.
- **Pass Rate**: **100% (113/113 passing)**.
- **Coverage Areas**:
  - `test_checkpoint.py`: Atomic state persistence, corruption recovery, concurrent read/write.
  - `test_flow_record.py`: Schema validation, normalization edge cases, missing field imputation.
  - `test_incremental_reader.py`: Binary seek positioning, tailing, partial-line buffering, log rotation handling.
  - `test_watcher.py`: Polling detection, file debounce, error isolation.
  - `test_live_pipeline.py`: End-to-end live directory tailing and flow extraction.
  - `test_zeek_reader.py`: Parsing of `conn`, `dns`, `weird`, `ssl`, `quic`, and `ntp` logs.
  - `test_feature_extractor.py`: Flow-level metric extractions.
  - `test_feature_engineering_phase4.py`: Strict validation of 78D vector schema, Shannon entropy calculations, sliding window computations, cross-log correlation, and zero NaN/Inf assertions.
  - `test_master_dataset.py`: Master dataset CSV/JSONL row count (655 rows), dimensionality (78D), metadata structure, label agreement, and schema alignment.
  - `test_phase6e_inference.py`: Verification of serialized artifacts (`model.joblib`, `model_metadata.json`, `feature_contract.json`, `decision_policy.json`), frozen 78D feature contract, selective classification abstention policy ($\theta=0.40$), and input validation assertions.
  - `test_phase7_streaming.py`: End-to-end real-time inference streaming pipeline, causal sliding window tracking, standardized `AlertEvent` schema, fail-safe error handling, and offline experiment replay verification.
  - `test_phase8_backend.py`: FastAPI REST API routes (`/health`, `/api/v1/status`, `/api/v1/alerts`, `/api/v1/metrics`, `/api/v1/model`), WebSocket streaming (`/ws/alerts`), query validation, bounded in-memory `AlertStore` ring buffer, and React SOC dashboard static HTML serving.

---

## 🗺️ Next Steps & Project Roadmap

| Phase | Milestone | Status | Details |
|---|---|---|---|
| **Phase 1** | Project scaffolding & passive architecture definition | ✅ Completed | Setup directory structure, passive security guarantees |
| **Phase 2** | Batch Zeek Log Ingestion & FlowRecord DTO | ✅ Completed | Implemented `zeek_reader.py`, `flow_record.py` |
| **Phase 3** | Incremental live log reader, watcher, checkpointing | ✅ Completed | Implemented `checkpoint.py`, `incremental_reader.py`, `watcher.py`, `live_pipeline.py` |
| **Phase 4** | 78-D Feature Engineering & Multi-Log Correlator | ✅ Completed | Implemented `schema.py`, `math_utils.py`, `correlator.py`, `window_aggregator.py`, `vector_assembler.py` |
| **Phase 5** | Multi-Class Traffic Generation & Final Corpus Audit | ✅ Completed | 12 retained experiments, 655 vectors, 100% zero-loss capture verified in `FINAL_PHASE5_AUDIT.md` |
| **Phase 6A** | Master Dataset Assembly & Forensic Profiling | ✅ Completed | Built `master_dataset.csv`, `master_dataset.jsonl`, `DATASET_PROFILE.md`, zero defects |
| **Phase 6B** | Baseline Machine Learning Model Benchmarking | ✅ Completed | Leakage-controlled evaluation across 5 models, HistGradientBoosting achieved 0.7941 Macro F1 (`PHASE6B_BASELINE_REPORT.md`) |
| **Phase 6C** | In-Depth Model Evaluation, Error & Robustness Analysis | ✅ Completed | Validated cross-modality DDoS transfer, benign hard-negative resistance, seed stability ($\sigma < 0.004$) (`PHASE6C_ROBUST_EVALUATION_REPORT.md`) |
| **Phase 6D** | Model Refinement, Calibration & Threshold Analysis | ✅ Completed | Evaluated sensitivity, sigmoid probability calibration (reduced log loss $34.3\%$), abstention trade-offs (`PHASE6D_MODEL_REFINEMENT_REPORT.md`) |
| **Phase 6E** | Final Model Selection, Packaging & Artifact Serialization | ✅ Completed | Frozen 78D contract, serialized calibrated model bundle under `models/phase6e/`, standalone inference engine (`src/inference/`), 79/79 passing tests (`PHASE6E_FINAL_MODEL_SELECTION_REPORT.md`) |
| **Phase 7** | Real-Time Inference & Alert Streaming Pipeline | ✅ Completed | Connected `LiveZeekPipeline` to frozen ML model, standardized `AlertEvent` schema, full 12-experiment replay benchmark, 94/94 passing tests (`PHASE7_REALTIME_INFERENCE_REPORT.md`) |
| **Phase 8** | FastAPI Backend & API Layer | ✅ Completed | Implemented REST endpoints, WebSocket `/ws/alerts`, bounded `AlertStore`, OpenAPI documentation, 112/112 passing tests (`PHASE8_FASTAPI_BACKEND_REPORT.md`) |
| **Phase 9** | React/TypeScript SOC Dashboard Frontend | ✅ Completed | Built React/TypeScript/Vite SOC dashboard, probability bar visualization, forensic modal, model specs drawer, 113/113 passing tests (`PHASE9_SOC_DASHBOARD_REPORT.md`) |
