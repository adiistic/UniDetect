# UniDetect Phase 7: Real-Time Inference & Alert Streaming Pipeline Report

**Project**: UniDetect — Passive Network Threat Detection (SIH PS 145)  
**Phase**: Phase 7 (End-to-End Real-Time & Replay Inference Streaming Pipeline, Alert Schema & Performance Benchmarks)  
**Execution Date**: 2026-09-02  
**Frozen Model Target**: `models/phase6e/` (`unidetect-hgb-calibrated-v1.0.0`)  
**Feature Schema Version**: `1.0.0` (78 Continuous Numerical Dimensions)  
**Integration Status**: **100% Fully Connected (94 / 94 Automated Unit Tests Passing)**

---

## 1. 🎯 Executive Summary

Phase 7 successfully connected the passive Zeek log ingestion layer (`IncrementalZeekReader`, `ZeekLogWatcher`, `LiveZeekPipeline`) to the frozen Phase 6E calibrated inference engine (`ThreatDetector`, `FeatureContract`, `DecisionPolicy`).

The pipeline supports both **deterministic offline experiment replay** and **near-real-time live streaming log polling**, transforming incoming network connection records into 78-dimensional causal feature vectors, executing calibrated multi-class probability inference, and emitting standardized `AlertEvent` objects without modifying the network, decrypting payloads, or transmitting active probes.

```
+---------------------------------------------------------------------------------------------------------+
| PHASE 7 REAL-TIME STREAMING PIPELINE AT A GLANCE                                                        |
+---------------------------------+-----------------------------------------------------------------------+
| Supported Ingestion Modes       | 1. Deterministic Experiment Replay  2. Live Incremental Directory Tail|
| Passive Security Guarantees     | 100% Passive Read-Only (Zero Packets Transmitted / Zero Injections)  |
| Total Retained Flows Replayed   | 655 Flows Across All 12 Retained Laboratory Experiments               |
| Benign False Positive Rate      | 0.0% False Alarms on Retained Benign Corpus (143/143 Benign Correct)  |
| Threat Detection Performance    | 100% on C2 Beacon, Slow HTTP, DDoS SYN; High Recall on Recon & Tunnel |
| Median Latency ($P_{50}$)       | 15.802 ms / flow (In-Memory Processing on Single-Thread CPU)          |
| 95th Percentile Latency ($P_{95}$)| 19.887 ms / flow                                                    |
| Single-Thread Throughput        | ~55.7 flows / second                                                  |
| Automated Test Suite Status     | 94 / 94 Unit Tests Passing (100% Green across 11 test suites)         |
+---------------------------------+-----------------------------------------------------------------------+
```

---

## 2. 🏗️ Streaming Pipeline Architecture & End-to-End Data Flow

```
[ PCAP / Passive Network Mirror ]
                 │
                 ▼
          [ Zeek Engine ]  (Passive Protocol Analyzers: conn, dns, ssl, weird, quic)
                 │
                 ▼
         ( disk / log files )
                 │
                 ▼
   [ IncrementalZeekReader / LiveZeekPipeline ]  (File watcher + checkpoint offset tracking)
                 │
                 ▼
      [ LogCorrelator (UID & IP Indexing) ]
                 │
                 ▼
    [ WindowAggregator (10s / 60s / 300s Causal Backward-Looking History) ]
                 │
                 ▼
  [ FeatureVectorAssembler (Strict 78-Dimensional Schema Vector Assembly) ]
                 │
                 ▼
    [ FeatureContract (Strict NaN/Inf, Dimension & Type Validation) ]
                 │
                 ▼
 [ Frozen Phase 6E CalibratedClassifierCV (HistGradientBoosting Estimator) ]
                 │
                 ▼
[ DecisionPolicy (θ_abstain = 0.40, θ_recon = 0.35, Selective Routing) ]
                 │
                 ▼
        [ AlertEvent Emission ]
                 │
                 ▼
{ "decision": "AUTOMATED_DETECTION", "threat": "DDOS", "confidence": 0.94, ... }
```

---

## 3. 🛡️ Passive Security Guarantees

UniDetect adheres strictly to passive monitoring principles:
1. **Zero Outbound Transmissions**: The inference pipeline never transmits packets, sends ARP/ICMP probes, or performs active handshakes.
2. **Zero In-Line Packet Interception**: Traffic is observed via Zeek's passive tap/pcap interface without inline modification or latency impact on live university traffic.
3. **Zero Payload Decryption**: Encryption boundaries (TLS 1.2/1.3, QUIC) are strictly preserved. The pipeline only examines metadata fields (SNI length, entropy, certificate validation flags, cipher suite identifiers) without decrypting application data.
4. **Isolated Memory Processing**: Ingested log streams remain completely local and are not transmitted to external cloud APIs or third-party analytical endpoints.

---

## 4. ⏱️ Causal Temporal Window Tracking & Sliding Horizon Integrity

The streaming aggregator updates behavioral statistics strictly over backward-looking horizons:
- **Source IP Windows**: $[t - 10\text{s}, t]$, $[t - 60\text{s}, t]$, $[t - 300\text{s}, t]$.
- **Destination IP Windows**: $[t - 10\text{s}, t]$, $[t - 60\text{s}, t]$.
- **Host-Pair Windows**: $[t - 300\text{s}, t]$ (Inter-arrival jitter $\text{CV} = \sigma / \mu$, byte standard deviation).

> [!NOTE]
> **Zero Future Leakage**: At timestamp $t$, every sliding window metric only queries events with $t_{\text{event}} \le t$. Future flows are never queried or visible to the feature assembler.

---

## 5. 📜 Standardized Alert Event Schema (`AlertEvent`)

Every inference step produces a standardized, decoupled `AlertEvent` dictionary:

```json
{
  "alert_id": "c86ba998-9ed0-4e89-9fbf-1f14e6e51552",
  "flow_uid": "CKrmsV2WDQfBY203Z3",
  "timestamp": 1788341408.393671,
  "timestamp_iso": "2026-09-02T09:30:08.393671+00:00",
  "source_ip": "127.0.0.1",
  "destination_ip": "127.0.0.1",
  "source_port": 34332,
  "destination_port": 8080,
  "protocol": "tcp",
  "predicted_class_id": 0,
  "predicted_label": "BENIGN",
  "confidence": 0.4854,
  "probabilities": {
    "BENIGN": 0.4854,
    "DDOS": 0.1665,
    "RECON": 0.0319,
    "DNS_TUNNEL": 0.0496,
    "C2_BEACON": 0.054,
    "SLOW_HTTP": 0.2126
  },
  "abstained": false,
  "decision": "AUTOMATED_DETECTION",
  "model_version": "unidetect-hgb-calibrated-v1.0.0",
  "schema_version": "1.0.0",
  "processing_time_ms": 15.8,
  "metadata": {
    "duration": 0.000795,
    "orig_bytes": 116,
    "resp_bytes": 229,
    "total_bytes": 345,
    "conn_state": "SF"
  }
}
```

---

## 6. 📊 Full Corpus Replay Benchmark Results (12 Retained Experiments)

Replaying all 12 authoritative experiments through `RealtimeInferencePipeline.replay_directory()`:

```
========================================================================================================================
EXPERIMENT ID              | GROUND TRUTH | FLOWS | THREATS DETECTED | BENIGN DETECTED | REVIEW (ABSTAIN) | MEAN LATENCY
---------------------------+--------------+-------+------------------+-----------------+------------------+-------------
exp_benign_iperf_002       | BENIGN       |   9   |        0         |        9        |        0         |  162.27 ms*
exp_benign_multi_003       | BENIGN       |  15   |        0         |       15        |        0         |   14.88 ms
exp_benign_dns_004         | BENIGN       |  20   |        0         |       20        |        0         |   16.51 ms
exp_benign_tls_005         | BENIGN       |   8   |        0         |        8        |        0         |   15.47 ms
exp_benign_mixed_006       | BENIGN       |  28   |        0         |       28        |        0         |   15.18 ms
exp_benign_periodic_007    | BENIGN       |  63   |        0         |       63        |        0         |   15.80 ms
exp_ddos_syn_001           | DDOS         | 150   |      150         |        0        |        0         |   15.74 ms
exp_ddos_udp_002           | DDOS         | 151   |      109         |       23        |       19         |   16.33 ms
exp_recon_001              | RECON        |  59   |       54         |        3        |        2         |   15.75 ms
exp_slow_http_001          | SLOW_HTTP    |  50   |       50         |        0        |        0         |   16.51 ms
exp_dns_tunnel_001         | DNS_TUNNEL   |  52   |       44         |        8        |        0         |   16.57 ms
exp_c2_beacon_001          | C2_BEACON    |  50   |       50         |        0        |        0         |   15.29 ms
---------------------------+--------------+-------+------------------+-----------------+------------------+-------------
CORPUS TOTALS / AVERAGES   | ALL CLASSES  | 655   |      457         |      154        |       21         |   17.96 ms
========================================================================================================================
```
*\*Note: Initial run includes cold-start model deserialization and scikit-learn tree cache warm-up.*

### Key Observations:
1. **Zero Benign False Positives**: All 143 benign flows across 6 distinct experiments (`iperf_002`, `multi_003`, `dns_004`, `tls_005`, `mixed_006`, `periodic_007`) were correctly classified as `BENIGN` ($0\text{ false alarms}$).
2. **100% Threat Detection**: `exp_c2_beacon_001` ($50/50$), `exp_slow_http_001` ($50/50$), and `exp_ddos_syn_001` ($150/150$).
3. **Low-Latency Performance**: Post-warmup median inference latency was **$15.802\text{ ms}$ / flow** with a 95th percentile latency of **$19.887\text{ ms}$ / flow**.

---

## 7. 🛡️ Robust Error Handling & Fail-Safe Modes

The pipeline guarantees resilient operation under adverse log conditions:
- **Missing Auxiliary Logs**: If a flow lacks corresponding `dns.log`, `ssl.log`, or `weird.log` records, the correlator automatically applies frozen default values ($0.0$) without throwing errors.
- **Corrupted Numerical Inputs / NaNs**: Caught safely by `FeatureContract` or `_safe_float` imputation, emitting an `INFERENCE_ERROR` alert (`abstained = True`) rather than crashing the polling thread.
- **Duplicate UIDs**: Incremental state tracking deduplicates records gracefully without corrupting sliding window histories.

---

## 8. 📁 Implemented Phase 7 Modules & Artifacts

1. [`src/inference/alert.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/inference/alert.py): `AlertEvent` schema and serialization methods.
2. [`src/inference/pipeline.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/inference/pipeline.py): `RealtimeInferencePipeline` connecting ingestion to frozen ML model.
3. [`src/main.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/main.py): CLI interface updated with `--predict` and `--live-log-dir` flags.
4. [`scripts/run_phase7_replay.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/scripts/run_phase7_replay.py): Replay benchmark script across all 12 retained experiments.
5. [`reports/phase7/replay_benchmark.csv`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/reports/phase7/replay_benchmark.csv): Latency, throughput, and detection statistics.
6. [`reports/phase7/sample_alerts.json`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/reports/phase7/sample_alerts.json): Exported standardized alert records for downstream API integration.
7. [`tests/test_phase7_streaming.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/tests/test_phase7_streaming.py): 15 comprehensive streaming unit tests.

---

## 9. 🧪 Verification & Test Suite Summary

```bash
python -m unittest discover -s tests
```
- **Total Test Suites**: 11 suites
- **Total Passing Tests**: **94 tests** (68 baseline + 11 Phase 6E + 15 Phase 7 streaming tests)
- **Pass Rate**: **100% (94 / 94 passing)**

---

## 10. 🚦 Phase 7 Conclusion & Phase 8 GO/NO-GO Recommendation

### **FINAL RECOMMENDATION: GO FOR PHASE 8 (FASTAPI BACKEND & DASHBOARD INTEGRATION)**

**Summary**:
- Real-time and replay inference pipelines are **fully integrated, tested, and benchmarked**.
- Zero payload logging or active network interaction.
- Standalone inference is completely decoupled from web or database layers.

*Phase 7 is concluded. Awaiting user authorization before starting Phase 8.*
