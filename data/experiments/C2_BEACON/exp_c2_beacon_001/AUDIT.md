# Forensic & Data Quality Audit: Experiment `exp_c2_beacon_001`

**Experiment ID**: `exp_c2_beacon_001`  
**Class**: `C2_BEACON` (`label_id = 5`)  
**Traffic Generator**: Custom Python RFC-compliant HTTP C2 Beaconing Client  
**Target Endpoint**: `127.0.0.1:8443` (Local HTTP C2 Target Server)  
**Audit Date**: 2026-09-01  
**Audit Type**: Periodic Communication & Temporal Window Feature Validation  

---

## 1. Executive Summary

Experiment `exp_c2_beacon_001` evaluates the temporal sliding-window capabilities of the UniDetect 78-dimensional feature extractor to capture **Command-and-Control (C2) periodic beaconing** patterns.

### Key Metrics:
- **Total Flows Extracted**: `50 flows` (100% labeled `C2_BEACON`, `label_id = 5`)
- **Protocol**: `TCP` (50 flows, 100%)
- **Target Endpoint**: `127.0.0.1:8443` (Fixed C2 Endpoint)
- **Mean Inter-Arrival Interval (\Delta t)**: `0.4116s` (Min: `0.3229s`, Max: `0.5486s`)
- **Interval Coefficient of Variation (CV)**: `0.1759` (Low-jitter periodicity)
- **PCAP File Size**: `81,789 bytes` (79.9 KB, 700 packets)
- **Connection States**: `{'SF': 50}` (Clean `SF` / `RSTO` transactions)
- **Total Missed Bytes**: `0.0 bytes` (100% capture completeness)
- **Weird Anomalies**: `[]` (0 anomalies)
- **Feature Matrix Quality**: 0 NaNs, 0 Infs, 0 missing features across all `50 x 78` cells.

---

## 2. Multi-Class Behavioral Comparison: C2_BEACON vs. Other Modalities

| Feature Subspace / Dimension | BENIGN HTTP (Exp 003) | C2_BEACON (Exp 001) | DDOS SYN (Exp 001) | SLOW_HTTP (Exp 001) | DNS_TUNNEL (Exp 001) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Host-Pair Delta-t Mean (idx=73)**| 0.001s (Bursty) | **0.35s – 0.50s (Periodic)**| 0.000s (Flooding) | 0.85s – 3.20s | N/A (UDP DNS) |
| **Host-Pair Delta-t CV (idx=75)**  | 1.00 (Default) | **0.12 – 0.28 (Low Jitter)** | 0.00 (Immediate)  | 0.45 – 0.80 | N/A |
| **Host-Pair Flow Count 300s (72)** | 1 – 5 flows | **15 – 50 flows (Recurrent)**| > 150 flows | 15 – 50 flows | N/A |
| **Inbound Flow Rate 10s (idx=69)** | 0.45 flows/s | **2.0 – 3.0 flows/s** | > 50.0 flows/s | 2.55 flows/s | 2.0 flows/s |
| **Payload Bytes per Flow (idx=3)** | 18.48 KB (Heavy) | **150 B – 260 B (Beacons)** | 0 B (Headers) | 326 B (Dribble) | 149 B (Queries) |
| **Flow Duration (idx=0)**          | 0.001s (Fast) | **0.001s – 0.003s (Fast)** | 0.000s | 3.212s (Slow) | 0.000s |

---

## 3. Temporal Window Feature Analysis & Periodicity

- **Low-Jitter Recurrence (`win_pair_delta_t_cv`)**: The coefficient of variation ($CV = \sigma / \mu$) for C2 beaconing stays tightly constrained ($0.12 - 0.28$), providing an explicit mathematical differentiator against irregular human web browsing ($CV > 1.5$).
- **Compact Uniform Payloads (`win_pair_orig_bytes_std`)**: Standard deviation of payload sizes remains small ($20 - 45\text{ bytes}$), characteristic of automated beacon polling payloads.

---

## 4. Shortcut & Leakage Analysis

- **Potential Shortcuts Documented**: Local port `8443` and server IP `127.0.0.1` are environmental properties.
- **True Behavioral Signature**: Relies on **temporal window invariants**:
  `win_pair_delta_t_cv` (< 0.30) + `win_pair_flow_count_300s` (> 15) + compact `total_bytes` + rapid completion duration.

---

## 5. Retain Decision & Next Steps

1. **Retention**: **RETAIN `exp_c2_beacon_001` FOR ML TRAINING**. Capture quality is 100% complete (0.0 missed bytes), zero anomalies, exactly 78 dimensions, zero NaNs/Infs, and establishes pristine periodic C2 beaconing ground truth.
2. **Schema Sufficiency**: The frozen 78-dimensional schema successfully captures inter-arrival delta-t, jitter CV, and host-pair frequency without schema modifications.
