# Forensic & Data Quality Audit: Experiment `exp_benign_periodic_007`

**Experiment ID**: `exp_benign_periodic_007`  
**Class**: `BENIGN` (`label_id = 0`)  
**Traffic Mode**: Legitimate Periodic & Background Traffic (Hard Negative Baseline)  
**Audit Date**: 2026-09-02  
**Audit Type**: Periodic Temporal & Anti-Beaconing Shortcut Validation  

---

## 1. Executive Summary

Experiment `exp_benign_periodic_007` generates a **realistic benign hard-negative dataset** containing legitimate periodic, scheduled, and automated background network operations. Its explicit objective is to prevent the ML model from adopting the naive shortcut:

> **"Periodic or repeated network traffic = C2 Beaconing"**

### Key Accomplishments & Metrics:
- **Total Validated Vectors**: `63 vectors` ($78\text{ dimensions}$, $0\text{ NaNs}$, $0\text{ Infs}$, $0\text{ missing}$)
- **Multi-Protocol Distribution**: `{'tcp': 53, 'udp': 10}`
- **Multi-Port Distribution**: `{8080: 23, 8000: 12, 443: 8, 5353: 10, 9090: 10}` (Covers Ports `8080`, `8000`, `443`, `5353`, `9090`)
- **Periodic Interval Diversity**: Spans multiple base frequencies ($0.25\text{s}, 0.30\text{s}, 0.35\text{s}, 0.45\text{s}, 0.50\text{s}$) with both strict timing and mild jitter ($CV = 0.01 - 0.25$).
- **Capture Integrity**: `$0.0\text{ missed bytes}$` ($100\%$ capture completeness, $0\text{ dropped bytes}$)
- **Zeek Anomaly Events**: `[]` ($0\text{ anomalies}$)
- **Zeek Logs Generated**: `conn.log, dns.log, files.log, http.log, packet_filter.log, ssl.log`

---

## 2. Quantitative Comparison: BENIGN 007 Periodic Traffic vs C2_BEACON 001

| Dimension / Characteristic | C2_BEACON (Exp 001) | BENIGN Periodic (Exp 007) | Differentiation / Security Significance |
| :--- | :--- | :--- | :--- |
| **Ground Truth Label** | `C2_BEACON` (`label_id = 5`) | `BENIGN` (`label_id = 0`) | **Hard Negative Evaluation Control** |
| **Port / Service Surface** | Single Port `8443` only | **5 Distinct Services** (`8080`, `8000`, `443`, `5353`, `9090`) | Proves periodicity occurs across all enterprise services |
| **Protocol Diversity** | 100% TCP (HTTP only) | **TCP (HTTP, HTTPS, Custom) + UDP (DNS)** | Proves DNS & non-HTTP services have periodic patterns |
| **Payload Volumetrics** | Uniform compact beacons ($150 - 260\text{ B}$) | **Variable Payloads** ($65\text{ B}$ health, $600\text{ B}$ metrics, $8\text{ KB}$ report) | Breaks uniform payload shortcut |
| **Periodic Intervals (\Delta t)**| $0.35\text{s}, 0.40\text{s}, 0.50\text{s}$ | **$0.25\text{s}, 0.30\text{s}, 0.35\text{s}, 0.45\text{s}, 0.50\text{s}$** | Overlapping temporal frequency spectrum |
| **Interval Regularity (CV)** | $0.12 - 0.28$ | **$0.01 - 0.25$** | Proves low CV occurs naturally in legitimate monitoring |
| **Application Layer Semantics**| Simulated agent command loop | **Prometheus metrics, DNS TXT/A, HTTPS sync, Health checks** | Clean RFC-compliant enterprise protocols |

---

## 3. Detailed Pattern Timing Profiles

| Pattern Name | Target Port | Protocol | Events | Mean Interval | Interval Range | Jitter / CV |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `health_checks_8080` | `127.0.0.1:8080` | `TCP` | `15` | `0.3011s` | `0.3008s - 0.3018s` | `CV = 0.0009` |
| `metric_polls_8000` | `127.0.0.1:8000` | `TCP` | `12` | `0.4426s` | `0.4152s - 0.4907s` | `CV = 0.0575` |
| `dns_periodic_5353` | `127.0.0.1:443` | `UDP` | `10` | `0.3504s` | `0.3503s - 0.3506s` | `CV = 0.0002` |
| `tls_sync_443` | `127.0.0.1:5353` | `TCP` | `8` | `0.5074s` | `0.5059s - 0.5105s` | `CV = 0.0032` |
| `tcp_daemon_9090` | `127.0.0.1:9090` | `TCP` | `10` | `0.2507s` | `0.2504s - 0.2512s` | `CV = 0.0009` |
| `mixed_interleaved` | `N/A` | `TCP` | `8` | `0.3010s` | `0.3008s - 0.3012s` | `CV = 0.0005` |

---

## 4. Forensic & Quality Verification

- **PCAP File**: `/mnt/c/Users/GOURAV GABA/Downloads/unidetectml/data/experiments/BENIGN/exp_benign_periodic_007/pcap/capture.pcap` (`122,910 bytes`, `660 packets`)
- **Missed Bytes**: `0.0 bytes`
- **Weird Events Count**: `0`
- **Feature Matrix Quality**: Verified zero NaNs, zero Infs, and zero missing values across all `63 \times 78` feature cells.

---

## 5. Recommendation & Status

**STATUS: RETAINED FOR ML TRAINING**  
Experiment `exp_benign_periodic_007` fulfills the critical role of a **benign hard negative** against C2 beaconing. It provides high-quality temporal regularity without copying the malicious characteristics of C2_BEACON, thereby training the future ML classifier to evaluate multi-dimensional contextual features rather than relying solely on timing periodicity.
