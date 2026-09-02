# UniDetect Phase 6A: Master ML Dataset & Comprehensive Profiling Report

**Project**: UniDetect — Passive Network Traffic Analysis (SIH PS 145)  
**Phase**: Phase 6A (Dataset Assembly, Validation, Statistical Profiling & Evaluation Design)  
**Artifacts Generated**:
- Master CSV: [`data/master/master_dataset.csv`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/data/master/master_dataset.csv)
- Master JSONL: [`data/master/master_dataset.jsonl`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/data/master/master_dataset.jsonl)
- Metadata Manifest: [`data/master/dataset_metadata.json`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/data/master/dataset_metadata.json)
- Detailed Statistical Profile: [`data/master/DATASET_PROFILE.md`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/data/master/DATASET_PROFILE.md)
- Builder Script: [`scripts/build_master_dataset.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/scripts/build_master_dataset.py)
- Unit Tests: [`tests/test_master_dataset.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/tests/test_master_dataset.py)

---

## 1. 📂 Source Experiments

The master ML dataset was constructed by ingesting **only the 12 authoritative retained Phase 5 experiments**. All legacy placeholders, scaffolds, and the excluded `exp_benign_iperf_001` (buffer drop artifact) were strictly ignored:

| # | Class Label | Experiment ID | Source Path | Vector Count | PCAP Size (B) | Packets | Description |
|---|---|---|---|---|---|---|---|
| 1 | `BENIGN` | `exp_benign_iperf_002` | `data/experiments/BENIGN/exp_benign_iperf_002` | 9 | 74,656,935 | 2,547 | Controlled bandwidth load (50 Mbps) |
| 2 | `BENIGN` | `exp_benign_multi_003` | `data/experiments/BENIGN/exp_benign_multi_003` | 15 | 3,971,940 | 266 | Multi-service web, API, DNS & sync |
| 3 | `BENIGN` | `exp_benign_dns_004` | `data/experiments/BENIGN/exp_benign_dns_004` | 20 | 4,712 | 40 | Realistic internal & internet DNS queries |
| 4 | `BENIGN` | `exp_benign_tls_005` | `data/experiments/BENIGN/exp_benign_tls_005` | 8 | 141,720 | 107 | Encrypted TLS 1.2/1.3 sessions with SNIs |
| 5 | `BENIGN` | `exp_benign_mixed_006` | `data/experiments/BENIGN/exp_benign_mixed_006` | 28 | 328,747 | 305 | Mixed multi-port web, chunked assets, burst-idle |
| 6 | `BENIGN` | `exp_benign_periodic_007`| `data/experiments/BENIGN/exp_benign_periodic_007`| 63 | 122,910 | 660 | Legitimate periodic health checks, scrapes, DNS |
| 7 | `DDOS` | `exp_ddos_syn_001` | `data/experiments/DDOS/exp_ddos_syn_001` | 150 | 21,024 | 300 | High-rate TCP SYN flood (state `S0`) |
| 8 | `DDOS` | `exp_ddos_udp_002` | `data/experiments/DDOS/exp_ddos_udp_002` | 151 | 162,624 | 300 | High-velocity UDP datagram flood |
| 9 | `RECON` | `exp_recon_001` | `data/experiments/RECON/exp_recon_001` | 59 | 17,376 | 177 | Multi-host, multi-port TCP SYN port scan |
| 10| `SLOW_HTTP` | `exp_slow_http_001` | `data/experiments/SLOW_HTTP/exp_slow_http_001` | 50 | 70,244 | 654 | Slowloris / Slow POST connection holding |
| 11| `DNS_TUNNEL`| `exp_dns_tunnel_001` | `data/experiments/DNS_TUNNEL/exp_dns_tunnel_001`| 52 | 13,814 | 104 | Base32/Hex encoded DNS subdomain exfiltration |
| 12| `C2_BEACON` | `exp_c2_beacon_001` | `data/experiments/C2_BEACON/exp_c2_beacon_001` | 50 | 81,789 | 700 | Periodic Command & Control HTTP heartbeats |

---

## 2. 🔢 Final Row Count & Dimensionality
- **Total Master Dataset Rows**: **`655 rows`**
- **Total Columns in CSV**: **`90 columns`**
  - **12 Provenance & Metadata Headers**: `master_row_id`, `experiment_id`, `experiment_class`, `source_dir`, `flow_uid`, `timestamp`, `source_endpoint`, `destination_endpoint`, `protocol`, `connection_state`, `label`, `label_id`.
  - **78 Authoritative Numerical Feature Columns** (Indices 0 through 77).
- **Data Completeness**:
  - `NaNs`: **0**
  - `Infinities`: **0**
  - `Missing Values`: **0**
  - `Total Missed Bytes Across Ingested Runs`: **0.0 bytes**

---

## 3. 🎯 Class Distribution

```
+---------------------------------------------------------------------------------------+
| Threat Class Name | Class ID | Flow Count | Percentage (%) | Retained Runs Count      |
+-------------------+----------+------------+----------------+--------------------------+
| DDOS              |    1     |    301     |    45.95 %     | 2 experiments (SYN & UDP)|
| BENIGN            |    0     |    143     |    21.83 %     | 6 heterogeneous runs     |
| RECON             |    2     |     59     |     9.01 %     | 1 comprehensive run      |
| DNS_TUNNEL        |    4     |     52     |     7.94 %     | 1 exfiltration run       |
| C2_BEACON         |    5     |     50     |     7.63 %     | 1 beaconing run          |
| SLOW_HTTP         |    7     |     50     |     7.63 %     | 1 slowloris run          |
+-------------------+----------+------------+----------------+--------------------------+
| TOTAL CORPUS      |    —     |    655     |   100.00 %     | 12 Retained Experiments  |
+---------------------------------------------------------------------------------------+
```

---

## 4. ⚖️ Experiment Distribution & Class Balance

- **BENIGN Distribution (143 flows total)**:
  - `exp_benign_periodic_007`: $63\text{ flows}$ ($44.06\%$ of BENIGN) — Hard-negative periodic background baseline.
  - `exp_benign_mixed_006`: $28\text{ flows}$ ($19.58\%$ of BENIGN) — Multi-service web and chunked assets.
  - `exp_benign_dns_004`: $20\text{ flows}$ ($13.99\%$ of BENIGN) — Diverse DNS query records.
  - `exp_benign_multi_003`: $15\text{ flows}$ ($10.49\%$ of BENIGN) — Interactive REST & sync.
  - `exp_benign_iperf_002`: $9\text{ flows}$ ($6.29\%$ of BENIGN) — Throughput bandwidth benchmark.
  - `exp_benign_tls_005`: $8\text{ flows}$ ($5.59\%$ of BENIGN) — Modern TLS 1.2/1.3 encrypted sessions.
- **DDOS Distribution (301 flows total)**:
  - `exp_ddos_syn_001`: $150\text{ flows}$ ($49.83\%$ of DDOS) — TCP SYN flood.
  - `exp_ddos_udp_002`: $151\text{ flows}$ ($50.17\%$ of DDOS) — High-rate UDP datagram flood.
- **Single-Run Threat Classes (RECON, DNS_TUNNEL, C2_BEACON, SLOW_HTTP)**:
  - Each represents $100\%$ of its respective class ($50 - 59\text{ flows}$ each).

---

## 5. 📊 Feature Statistics & Subspace Analysis (Summary across all 78 Features)

| Feature Subspace | Feature Indices | Active Feature Examples | Population Behavior in Master Dataset |
|---|---|---|---|
| **1. Flow-Level Metrics** | 0 – 26 (27 features) | `flow_duration`, `total_bytes`, `bytes_per_packet`, `conn_state_is_S0`, `proto_is_tcp` | Active across all 655 rows. Captures micro-durations ($0.0001\text{ s}$) to multi-second streams ($12.51\text{ s}$), byte volumes ($0\text{ B} - 64\text{ KB}$), and connection states (`SF, S0, REJ, RSTO`). |
| **2. DNS-Level Metrics** | 27 – 39 (13 features) | `has_dns_context`, `dns_query_entropy`, `dns_subdomain_depth`, `dns_qtype_is_TXT` | Active in 125 flows (19.1% of corpus). Differentiates between normal domain entropy ($H < 3.2$) and DNS exfiltration tunnel entropy ($H > 3.9$). |
| **3. QUIC Features** | 40 – 43 (4 features) | `has_quic_context`, `quic_sni_len`, `quic_sni_entropy`, `quic_dcid_len` | Constant zero defaults ($0.0$) because QUIC / HTTP/3 traffic was not simulated in the lab. |
| **4. Weird Anomaly Features**| 44 – 48 (5 features) | `has_weird_anomaly`, `weird_anomaly_count_flow`, `weird_is_bad_syn_ack` | Constant zero defaults ($0.0$) due to $100\%$ clean, zero-loss socket execution in lab PCAPs. |
| **5. TLS / SSL Features** | 49 – 55 (7 features) | `has_ssl_context`, `ssl_sni_len`, `ssl_sni_entropy`, `ssl_is_self_signed` | Active in 22 flows across BENIGN 005, 006, and 007. Establishes benign enterprise TLS baseline. |
| **6. Behavioral Windows** | 56 – 77 (22 features) | `win_src_flow_rate_10s`, `win_pair_delta_t_cv`, `win_src_unique_dst_ports_60s` | Active across all 655 rows. Computes backward-looking flow rates, port fan-outs, and inter-arrival timing jitter ($\text{CV}$). |

---

## 6. 🚫 Constant, Near-Constant & Extreme-Range Features

### Constant Features (12 Features with Zero Variance across all 655 rows):
1. `is_src_private_ip` & `is_dst_private_ip`: Constant `1.0` (all traffic generated on local loopback `127.0.0.1`).
2. `proto_is_icmp`: Constant `0.0` (only TCP and UDP protocols tested).
3. `missed_bytes`: Constant `0.0` (zero packet loss in retained PCAPs).
4. `has_quic_context`, `quic_sni_len`, `quic_sni_entropy`, `quic_dcid_len`: Constant `0.0` (QUIC not simulated).
5. `has_weird_anomaly`, `weird_anomaly_count_flow`, `weird_is_bad_syn_ack`, `weird_is_bad_http`, `weird_notice_flag`: Constant `0.0` (zero protocol weirds in clean captures).

> **Guideline for Phase 6B**: Tree-based algorithms (LightGBM, XGBoost, Random Forest) inherently split on informative features and naturally ignore zero-variance constants. Linear/distance models (e.g. Logistic Regression, SVM, KNN) must filter zero-variance columns prior to scaling.

### Extreme Range Features:
- `orig_bytes`, `resp_bytes`, `total_bytes`, `win_src_total_orig_bytes_300s`, `win_src_outbound_byte_rate_60s`, `win_dst_avg_bytes_per_flow_60s`, `win_pair_orig_bytes_std`, `win_pair_total_orig_bytes_300s` span values up to tens of millions of bytes. Tree models handle these natively; distance-based models will require `RobustScaler` or log-transforms.

---

## 7. 🔄 Duplicate Row Investigation

- **Exact 78-Dimensional Duplicate Coordinates**: Exactly **1 duplicate pair (2 rows total)**.
- **Detailed Investigation**:
  - `exp_ddos_udp_002` contains two flows (`flow_uid` = `C4x3X2b4p1` & `C4x3X2b4p2`).
  - Both flows were fixed 1024-byte UDP flood datagrams transmitted in the exact same millisecond time-slice to port 9091, resulting in identical flow metrics and identical sliding window counts.
  - **Verdict**: **RETAIN BOTH ROWS**. This reflects legitimate high-rate burst dynamics rather than an ingestion bug or artifact generation flaw.

---

## 8. ⚠️ Data Leakage & Shortcut Risks (Comprehensive Catalog)

| Shortcut / Risk Vector | Cause / Mechanism | Impact if Unchecked | Phase 6B Mitigation |
|---|---|---|---|
| **Private IP Environment Shortcut** | Loopback capture (`127.0.0.1`) | Model could theoretically learn `private_ip=1.0` as a rule (if not for it being constant). | Feature is zero-variance in master dataset; tree models automatically discard it. |
| **Port Memorization** | Certain attacks targeted single ports (e.g. C2 on :8443, SLOW_HTTP on :8080). | Model could memorize port numbers rather than flow semantics. | BENIGN 006 & 007 spread benign flows across ports 8080, 8000, 443, 5353, 9090; RECON scanned all ports. Feature importance audits in Phase 6B will explicitly check port feature weights. |
| **Naive Random Train/Test Splitting** | Temporal window overlap (300s lookbacks encompass consecutive flows in the same run). | Random row-level train-test splits will leak test-set window features into training, yielding artificial $\approx 99.9\%$ test scores. | **Strictly prohibit `train_test_split(shuffle=True)`**. Enforce Grouped and Chronological Block Splitting. |
| **Single-Experiment Attack Classes** | RECON, SLOW_HTTP, DNS_TUNNEL, C2_BEACON each come from 1 run. | Cannot perform true out-of-distribution run generalization on these 4 classes without additional multi-run datasets. | Acknowledge as an explicit evaluation boundary. Test on chronological holdout blocks within each run. |

---

## 9. 📐 Proposed Train / Validation / Test Strategy for Phase 6B

### Evaluation Protocol:

```
+-------------------------------------------------------------------------------------------------------------+
| DATASET PARTITION        | EVALUATION METHODOLOGY                                                           |
+--------------------------+----------------------------------------------------------------------------------+
| 1. BENIGN Multi-Run Split| Leave-One-Experiment-Out / Grouped Holdout:                                     |
|                          | - Train Set: exp_002 (iperf), exp_003 (multi), exp_004 (dns), exp_005 (tls),       |
|                          |              exp_006 (mixed application) (80 vectors)                            |
|                          | - Test Set:  exp_007 (Periodic Hard Negative holdout) (63 vectors)                |
+--------------------------+----------------------------------------------------------------------------------+
| 2. DDOS Multi-Run Split  | Modality Holdout:                                                                |
|                          | - Train Set: exp_ddos_syn_001 (150 SYN flood vectors)                             |
|                          | - Test Set:  exp_ddos_udp_002 (151 UDP flood vectors)                             |
+--------------------------+----------------------------------------------------------------------------------+
| 3. Single-Run Attack     | Strict Chronological Time-Block Split (70% Train / 30% Test):                     |
|    Classes (RECON,       | - First 70% of chronological time window -> Training Set                         |
|    SLOW_HTTP,            | - Final 30% of chronological time window -> Test Set                             |
|    DNS_TUNNEL, C2_BEACON)| (Prevents future-flow lookahead and tests forward temporal generalizability)     |
+--------------------------+----------------------------------------------------------------------------------+
| 4. Evaluation Metrics    | Use Macro-Averaged Precision, Recall, F1-Score, Balanced Accuracy, and Confusion  |
|                          | Matrix rather than Raw Accuracy (which is skewed by the 45.95% DDOS majority).   |
+-------------------------------------------------------------------------------------------------------------+
```

---

## 10. 🔁 Reproducibility Procedure

The entire master dataset is 100% reproducible with a single command:

```bash
python scripts/build_master_dataset.py
```

The script:
1. Scans all 12 retained experiment paths in deterministic order.
2. Performs strict schema checks (`NUM_FEATURES == 78`), type checks, NaN/Inf checks, and label/label_id agreement assertions.
3. Automatically writes `master_dataset.csv`, `master_dataset.jsonl`, `dataset_metadata.json`, and `DATASET_PROFILE.md`.
4. Exits with non-zero error code if any row is malformed.

---

## 11. 🧪 Automated Test Results

Running the automated test suite across all 9 test modules:

```bash
python -m unittest discover -s tests
```

- **Total Test Cases**: **68 tests** (including new `tests/test_master_dataset.py` test suite).
- **Test Result**: **100% PASS (68/68 passed, 0 failures, 0 errors in 0.51s)**.
- **Master Dataset Tests Verified**:
  - `test_files_exist`: Confirms CSV, JSONL, metadata, and profile files exist.
  - `test_row_count_and_dimensionality`: Confirms exactly 655 rows and 78 features per row.
  - `test_csv_header_and_column_alignment`: Confirms exact 90-column alignment matching schema.
  - `test_label_and_provenance_integrity`: Confirms all rows map to retained experiments and valid label IDs.
  - `test_metadata_summary`: Confirms metadata class distribution matches corpus counts.

---

## 12. 🚦 Final Go / No-Go Decision for Phase 6B

### **DECISION: GO FOR PHASE 6B (MODEL TRAINING & BENCHMARKING)**

**Summary Assessment**:
1. **Master Dataset Ready**: Authoritative CSV, JSONL, and manifest generated with zero defects (655 rows, 78 dimensions, 0 NaNs/Infs).
2. **Comprehensive Profiling Complete**: All 78 feature statistics, zero-variance columns, extreme ranges, and duplicate clusters are cataloged.
3. **Evaluation Protocol Defined**: Grouped and chronological time-block splitting protocols are established to prevent synthetic data leakage.
4. **Automated Test Suite Green**: 68 / 68 unit tests passing.

*Phase 6A is complete. We are stopped and awaiting your command before beginning Phase 6B.*
