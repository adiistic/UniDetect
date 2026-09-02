# Forensic & Data Quality Audit: Experiment `exp_ddos_syn_001`

**Experiment ID**: `exp_ddos_syn_001`  
**Class**: `DDOS` (`label_id = 1`)  
**Traffic Generator**: `hping3` (TCP SYN Flood Mode `-S`)  
**Target Endpoints**: `127.0.0.1:9090`, `127.0.0.1:9091`  
**Audit Date**: 2026-09-01  
**Audit Type**: Security Behavioral & Data Quality Audit  

---

## 1. Executive Summary

Experiment `exp_ddos_syn_001` represents the first threat experiment in the UniDetect dataset, establishing ground-truth behavioral signatures for volumetric **TCP SYN Flood Denial of Service** attacks under passive observation.

### Key Metrics:
- **Total Flows Extracted**: `150 flows` (100% labeled `DDOS`, `label_id = 1`)
- **Packets Captured**: `300 packets` across 1.66s
- **PCAP File Size**: `21,024 bytes` (20.5 KB)
- **Target Ports**: `9090` (100 flows), `9091` (50 flows)
- **Connection States**: `{'REJ': 150}` (100% incomplete/rejected connections)
- **Total Missed Bytes**: `$0.0\text{ bytes}$` ($100\%$ capture completeness)
- **Weird Anomalies**: `[]` ($0\text{ anomalies}$)
- **Feature Matrix Quality**: 0 NaNs, 0 Infs, 0 missing features across all `150 \times 78` cells.

---

## 2. Behavioral Signature & Feature Space Separation vs. BENIGN

| Feature Dimension / Subspace | 49 BENIGN Vectors (Exps 001–004) | 150 DDOS Vectors (`exp_ddos_syn_001`) | Attack Discriminative Power |
| :--- | :--- | :--- | :--- |
| **Connection State `REJ` (`idx=22`)** | **$0.0$** ($0\%$ in clean benign) | **$1.0$ ($100\%$ in SYN flood)** | Clean mathematical separation |
| **Connection State `SF` (`idx=20`)**  | **$0.80 - 1.00$** ($80-100\%$) | **$0.0$** ($0\%$ established) | Complete absence of normal teardown |
| **TCP History Flags (`idx=25, 26`)**   | `ShADaFf` (Full 3-way handshake) | `Sr` / `S` (SYN sent, immediate RST/drop) | Clear protocol-level anomaly |
| **Failed Conn Ratio 60s (`idx=60`)** | **$0.00 - 0.20$** | **$1.00$ ($100\%$ failed attempts)** | Aggregated behavioral indicator |
| **Inbound Flow Rate 10s (`idx=69`)** | **$0.1 - 0.5\text{ flows/s}$** | **$> 50.0\text{ flows/s}$** | $100\times$ connection rate surge |
| **Payload Bytes (`idx=1, 2, 3`)**     | Real application data (35 B to 35 GB)| **$0\text{ bytes}$ (Headers only)** | Pure signaling overhead |
| **Bytes Asymmetry Ratio (`idx=10`)**  | Diverse ($-0.99$ to $+1.00$) | **$0.000$** (No payload in either direction) | Characteristic header-only flood |

---

## 3. Recommendation

**RETAIN `exp_ddos_syn_001` FOR ML TRAINING.**  
This dataset provides a pristine, mathematically separable, and reproducible ground truth for SYN-flood detection with zero packet drops ($0.0\text{ missed bytes}$) and zero artificial anomalies.
