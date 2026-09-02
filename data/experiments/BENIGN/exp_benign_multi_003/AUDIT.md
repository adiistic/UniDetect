# Forensic & Data Quality Audit: Experiment `exp_benign_multi_003`

**Experiment ID**: `exp_benign_multi_003`  
**Class**: `BENIGN` (`label_id = 0`)  
**Traffic Mode**: Multi-Service Hybrid (Interactive Web REST API + RFC1035 DNS + Throttled Sync)  
**Audit Date**: 2026-09-01  
**Audit Type**: Comprehensive Behavioral & Quality Validation  

---

## 1. Executive Summary

Experiment 003 introduces **materially different behavioral characteristics** from Experiments 001 and 002:
- **Multi-Service Diversity**: Combines HTTP REST transactions on port 8080, UDP DNS resolutions on port 5353, and throttled synchronization on port 5203.
- **Variable Session Durations**: Spans micro-durations ($0.0003\text{s}$ DNS, $0.0005\text{s}$ JSON API) to multi-second streaming flows ($3.00\text{s}$).
- **Volumetric Range**: Spans small 48-byte DNS records, 67-byte JSON status payloads, ~3 KB HTML web pages, up to 64 KB chunked downloads and ~3.75 MB sync streams.
- **Capture Quality**: **$0.0\text{ missed bytes}$** ($100\%$ capture completeness) with **0 weird anomalies** and 0 NaN/Inf values.

---

## 2. Quantitative Metrics & Distributions

- **Total Captured Flows**: `15 flows`
- **Protocol Breakdown**: `{'udp': 5, 'tcp': 10}`
- **Destination Port Breakdown**: `{5353: 5, 5203: 2, 8080: 8}`
- **Captured Packets**: `266 packets`
- **PCAP File Size**: `3,971,940 bytes` (~3.79 MB)
- **Total Missed Bytes**: `0.0 bytes` ($0.0\text{ dropped bytes}$)
- **Zeek Anomaly Events**: `[]` ($0\text{ anomalies}$)

---

## 3. Comparison with Prior Experiments

| Attribute | Exp 001 (`exp_benign_iperf_001`) | Exp 002 (`exp_benign_iperf_002`) | Exp 003 (`exp_benign_multi_003`) |
| :--- | :--- | :--- | :--- |
| **Primary Workload** | Bulk Throughput (Unthrottled) | Bulk Upload & Download (50 Mbps) | **Interactive REST + DNS + Web + Sync** |
| **Active Protocols** | TCP, UDP | TCP, UDP | **TCP (HTTP/iperf), UDP (DNS)** |
| **Target Ports** | 5201 | 5202 | **8080 (HTTP), 5353 (DNS), 5203 (iperf)** |
| **Zeek Logs Generated** | `conn.log`, `weird.log` | `conn.log` | **`conn.log`, `dns.log`, `http.log`** |
| **Duration Range** | $2.99\text{s} - 5.00\text{s}$ | $0.00\text{s} - 4.00\text{s}$ | **$0.0003\text{s} - 3.00\text{s}$** |
| **Payload Volume Range**| $474\text{ B} - 35.1\text{ GB}$ | $37\text{ B} - 25.0\text{ MB}$ | **$48\text{ B} - 3.75\text{ MB}$** |
| **Missed Bytes** | $69.61\text{ GB}$ (Buffer drop) | $0.0\text{ B}$ | **$0.0\text{ B}$ ($100\%$ complete)** |
| **Weird Events** | Sequence gaps & underflows | None | **None** |

---

## 4. Recommendation

**RETAIN `exp_benign_multi_003` FOR ML TRAINING.**  
This experiment significantly expands benign training diversity, populates `dns.log` and `http.log` feature spaces with legitimate baseline traffic, and maintains $100\%$ capture integrity.
