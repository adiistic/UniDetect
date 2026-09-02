# Forensic & Data Quality Audit: Experiment `exp_benign_mixed_006`

**Experiment ID**: `exp_benign_mixed_006`  
**Class**: `BENIGN` (`label_id = 0`)  
**Traffic Mode**: Mixed Realistic Application Traffic (Multi-Service, Multi-Protocol, Variable Durations & Volumetrics)  
**Audit Date**: 2026-09-02  
**Audit Type**: Baseline Diversity & Anti-Shortcut Validation  

---

## 1. Executive Summary

Experiment `exp_benign_mixed_006` successfully generates a **heterogeneous benign baseline** across multiple local application services. Its primary objective is to prevent machine learning classifiers from learning simplistic heuristic shortcuts (such as associating specific ports, short flow durations, or only TCP/HTTP with benign traffic).

### Key Accomplishments & Metrics:
- **Total Validated Vectors**: `28 vectors` ($78\text{ dimensions}$, $0\text{ NaNs}$, $0\text{ Infs}$, $0\text{ missing}$)
- **Multi-Protocol Distribution**: `{'tcp': 23, 'udp': 5}`
- **Multi-Port Distribution**: `{8080: 7, 8000: 6, 9090: 4, 443: 6, 5353: 5}` (Covers Ports `8080`, `8000`, `443`, `5353`, `9090`)
- **Flow Duration Dynamic Range**: `0.0001\text{s}` to `2.8027\text{s}` (Micro-transactions to long-lived streams)
- **Volumetric Dynamic Range**: Originator: `21 B` to `31,637 B` | Responder: `26 B` to `64,172 B`
- **Capture Completeness**: `$0.0\text{ missed bytes}$` (Zero packet loss across all transactions)
- **Zeek Quality**: `[]` ($0\text{ anomalous protocol weirds}$)
- **Zeek Logs Generated**: `conn.log, dns.log, files.log, http.log, packet_filter.log, ssl.log`

---

## 2. Anti-Shortcut Defense Analysis

| Potential Simplistic Shortcut | How Experiment 006 Disproves It | Quantitative Evidence in Exp 006 |
| :--- | :--- | :--- |
| **"Specific Ports = Benign"** | Spans 5 distinct services and ports (`8080`, `8000`, `443`, `5353`, `9090`) | Port distribution: `{8080: 7, 8000: 6, 9090: 4, 443: 6, 5353: 5}` |
| **"Short Duration = Benign"** | Contains micro-flows ($<0.001\text{s}$) up to multi-second streaming flows ($>2.5\text{s}$) | Duration range: `$0.0001\text{s} - 2.8027\text{s}$` |
| **"HTTP Only = Benign"** | Integrates TLS 1.3 encrypted sessions, UDP DNS lookups, and framed binary TCP streams | Protocols: `{'tcp': 23, 'udp': 5}`, TLS flows: `6`, DNS flows: `5` |
| **"TCP Only = Benign"** | Integrates RFC 1035 UDP DNS lookups | Protocol split: `{'tcp': 23, 'udp': 5}` |
| **"Low Traffic Volume = Benign"** | Spans small 48-byte DNS queries up to 65 KB JS bundles and 32 KB telemetry uploads | Responder byte range: `$26 - 64,172\text{ bytes}$` |
| **"Constant Rate = Benign"** | Mixes interactive gaps ($0.1\text{s}$), concurrent bursts ($7\text{ parallel threads}$), and $1.5\text{s}$ idle pauses | Time-window features populated across $10\text{s}$, $60\text{s}$, $300\text{s}$ |

---

## 3. Detailed Forensic Verification

- **PCAP Capture File**: `/mnt/c/Users/GOURAV GABA/Downloads/unidetectml/data/experiments/BENIGN/exp_benign_mixed_006/pcap/capture.pcap` (`328,747 bytes`, `305 packets`)
- **Total Missed Bytes**: `0.0 bytes`
- **Weird Events Count**: `0`
- **Subspace Coverage**:
  - Flow metrics ($0 - 26$): Fully populated with diverse states (`SF`), byte ratios, and asymmetric metrics.
  - DNS metrics ($27 - 39$): Active across internal domain resolutions (`gateway.campus.local`, `mail.exchange.local`).
  - TLS metrics ($49 - 55$): Active across SNI requests (`secure.campus.internal`, `portal.service.local`, `api.storage.local`).
  - Behavioral Window metrics ($56 - 77$): Demonstrates dynamic burst-and-idle flow rate transitions.

---

## 4. Recommendation & Status

**STATUS: RETAINED FOR ML TRAINING**  
Experiment `exp_benign_mixed_006` exhibits $100\%$ capture integrity ($0\text{ missed bytes}$, $0\text{ weirds}$) and provides the essential cross-protocol and cross-port baseline diversity required for robust threat classification.
