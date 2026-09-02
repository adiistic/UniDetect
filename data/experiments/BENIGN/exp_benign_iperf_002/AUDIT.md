# Forensic & Data Quality Audit: Experiment `exp_benign_iperf_002`

**Experiment ID**: `exp_benign_iperf_002`  
**Class**: `BENIGN` (`label_id = 0`)  
**Traffic Generator**: `iperf3` (Rate-Limited: 50 Mbps TCP, 15 Mbps UDP)  
**Audit Date**: 2026-09-02  
**Audit Type**: Data Quality & Rate-Limiting Validation  

---

## 1. Executive Summary

Experiment `exp_benign_iperf_002` resolves the capture loss issues observed in `exp_benign_iperf_001` by applying explicit bandwidth rate-limiting ($50\text{ Mbps}$ TCP, $15\text{ Mbps}$ UDP).

### Key Metrics:
- **Total Flows**: `9 flows` (TCP bulk uploads, reverse downloads, parallel sessions, UDP stream, and control sessions)
- **Packets Captured**: `2,547 packets`
- **PCAP File Size**: `74,656,935 bytes` ($74.66\text{ MB}$)
- **Zeek Logs**: `conn.log`, `packet_filter.log`
- **Missed Bytes**: **$0.0\text{ bytes}$** ($100\%$ capture completeness)
- **Weird Events**: **$0\text{ anomalies}$** (`weird.log` is clean and empty)
- **Feature Quality**: 0 NaNs, 0 Infs, 0 missing values across all 9 vectors $\times$ 78 dimensions.

---

## 2. Retention Decision

**RETAIN `exp_benign_iperf_002` FOR ML TRAINING.**  
This dataset provides a pristine, high-throughput benign baseline with zero packet loss and clean connection states (`SF`).
