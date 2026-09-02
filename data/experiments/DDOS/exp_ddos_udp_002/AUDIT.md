# Forensic & Data Quality Audit: Experiment `exp_ddos_udp_002`

**Experiment ID**: `exp_ddos_udp_002`  
**Class**: `DDOS` (`label_id = 1`)  
**Traffic Generator**: `hping3` (UDP Flood Mode `--udp`)  
**Target Endpoint**: `127.0.0.1:9999`  
**Audit Date**: 2026-09-01  
**Audit Type**: DoS Multi-Modality & Data Quality Audit  

---

## 1. Executive Summary

Experiment `exp_ddos_udp_002` expands the `DDOS` threat class beyond TCP SYN floods by establishing ground-truth behavioral signatures for **high-rate UDP Flood Denial of Service** attacks under passive observation.

### Key Metrics:
- **Total Flows Extracted**: `151 flows` (100% labeled `DDOS`, `label_id = 1`)
- **Protocol**: `UDP` (150 flows, 100%)
- **Target Port**: `9999` (100% concentrated on single destination port)
- **Packets Captured**: `300 packets` across 1.853s
- **PCAP File Size**: `162,624 bytes` (158.8 KB)
- **Connection States**: `{'S0': 150, 'OTH': 1}` (Predominantly `S0` unanswered connection attempts)
- **Total Missed Bytes**: `0.0 bytes` (100% capture completeness)
- **Weird Anomalies**: `[]` (0 anomalies)
- **Feature Matrix Quality**: 0 NaNs, 0 Infs, 0 missing features across all `151 x 78` cells.

---

## 2. Cross-Experiment Behavioral Comparison Matrix

| Feature Dimension / Subspace | BENIGN (52 flows) | DDOS SYN 001 (150 flows) | DDOS UDP 002 (150 flows) | RECON 001 (59 flows) |
| :--- | :--- | :--- | :--- | :--- |
| **Protocol `proto_is_udp` (idx=18)** | 0.50 (DNS/iperf) | **0.00 (0% UDP)** | **1.00 (100% UDP)** | 0.00 (100% TCP) |
| **Protocol `proto_is_tcp` (idx=17)** | 0.50 | **1.00 (100% TCP)** | **0.00 (0% TCP)** | 1.00 (100% TCP) |
| **Connection State `S0` (idx=21)** | 0.00 (0%) | 0.00 (0%) | **1.00 (100% S0)** | 0.00 (0%) |
| **Connection State `REJ` (idx=22)** | 0.00 (0%) | **1.00 (100% REJ)** | 0.00 (0%) | 0.73 (73% REJ) |
| **Unique Dst Ports 60s (idx=59)** | 1 - 3 ports | 1 - 2 ports (Concentrated)| **1.0 (Single Port)** | **Up to 45 ports (Sweep)** |
| **Inbound Flow Rate 10s (idx=69)** | 0.1 - 2.0 flows/s | > 50.0 flows/s | **> 50.0 flows/s** | 2.5 - 15.0 flows/s |
| **Failed Conn Ratio 60s (idx=60)** | 0.00 - 0.20 | 1.00 (100% Failed) | **1.00 (100% S0 Attempts)**| 0.89 (High Failed Probes) |
| **Payload Bytes per Flow (idx=3)** | 68 B - 25.0 MB | 0 B (Header only) | **0 B (Header only)** | 53 B (Scan Probes) |

---

## 3. Retain Decision & Next Steps

1. **Retention**: **RETAIN `exp_ddos_udp_002` FOR ML TRAINING**. It introduces the critical UDP volumetric attack modality, ensuring the classifier recognizes DoS across both transport protocols (TCP SYN flood and UDP flood).
2. **Multi-Feature Coherence**: The classifier can distinguish UDP DDoS from legitimate UDP (DNS) by:
   - Absence of DNS context (`has_dns_context = 0.0`)
   - State `S0` ratio (`win_src_s0_syn_ratio_60s = 1.0` vs 0.0 in DNS)
   - Connection frequency surge (>50 flows/s vs 0.8 flows/s in DNS).
