# Forensic & Data Quality Audit: Experiment `exp_benign_iperf_001`

**Experiment ID**: `exp_benign_iperf_001`  
**Class**: `BENIGN` (`label_id = 0`)  
**Traffic Generator**: `iperf3`  
**Audit Date**: 2026-09-02  
**Audit Type**: Read-Only Forensic & Data Quality Analysis  

---

## 1. Executive Summary

This forensic audit investigates the technical relationship between the captured raw packet capture (`capture.pcap`), the Zeek connection and anomaly logs (`conn.log`, `weird.log`), and the derived 78-dimensional feature vectors (`features.jsonl`).

### Key Findings:
1. **Provenance & Reproducibility**: 100% bit-exact reproducibility confirmed. Regenerating Zeek logs from `capture.pcap` produces identical feature vectors with 0 numerical variance.
2. **Byte Accounting Explanation**: The discrepancy between the 225 MB PCAP file and the ~35 GB `orig_bytes` reported by Zeek for TCP worker streams is caused by **TCP Sequence Number tracking across unthrottled loopback memory transfers (~60 Gbps)** where `tcpdump` experienced user-space buffer drops while Zeek calculated true TCP stream sequence spans ($\text{last\_seq} - \text{first\_seq}$).
3. **Weird Log Origin**: `TCP_seq_underflow_or_misorder` and `TCP_ack_underflow_or_misorder` were caused by capture buffer drops during the in-memory loopback burst, not application anomalies.
4. **Retention Recommendation**: **Retain Experiment 001** as a documented reference of high-throughput loopback behavior. Apply bandwidth rate-limiting (`-b 50M` to `-b 100M`) for subsequent benign experiments to prevent PCAP buffer drops.

---

## 2. Deep Dive: PCAP vs. Zeek Byte Accounting

### Metrics Comparison Table:

| Metric / Attribute | Raw PCAP (`tshark` Analysis) | Zeek `conn.log` Record | Underlying Technical Cause |
| :--- | :--- | :--- | :--- |
| **PCAP Total File Size** | $225,319,107\text{ bytes}$ (~$225.3\text{ MB}$) | — | Total bytes written to disk by `tcpdump`. |
| **Total Captured Packets** | $8,596\text{ frames}$ | $8,600\text{ packets}$ ($4,309 + 4,134 + 117 + 18 + 18 + \text{control}$) | Frames captured before ring buffer drop. |
| **TCP Worker Stream 1 Bytes** | $103.93\text{ MB}$ captured | `orig_bytes = 34,697,379,878` (~$34.70\text{ GB}$) | Zeek computes: $\Delta \text{Seq} = \text{last\_seq} - \text{syn\_seq}$. |
| **TCP Worker Stream 2 Bytes** | $117.18\text{ MB}$ captured | `orig_bytes = 35,133,849,638` (~$35.13\text{ GB}$) | True in-memory transfer volume. |
| **Missed Bytes (Stream 1)** | — | `missed_bytes = 34,595,018,798` (~$34.60\text{ GB}$) | $\text{orig\_bytes} - \text{captured\_bytes} = 102.36\text{ MB}$. |
| **Missed Bytes (Stream 2)** | — | `missed_bytes = 35,016,804,637` (~$35.01\text{ GB}$) | $\text{orig\_bytes} - \text{captured\_bytes} = 117.04\text{ MB}$. |
| **TCP Flow History** | — | `ShADaGGGwGf` / `ShADawGGGGf` | `G` indicates sequence gaps from dropped packets. |
| **Average Frame Size** | $46,223\text{ bytes/frame}$ | — | Linux GSO (Generic Segmentation Offload) 64 KB super-packets. |

### Technical Analysis:
- `iperf3` on Linux loopback transfers data at memory bus speeds ($\sim 60\text{ Gbps}$). Over 5 seconds, $69.83\text{ GB}$ of payload data was pushed across kernel sockets.
- `tcpdump` writes to disk via a user-space pcap buffer at disk I/O speed ($\sim 50\text{ MB/s}$), capturing $225.3\text{ MB}$ before buffer drops occurred.
- Zeek passively inspects TCP sequence numbers. When segments were missing, Zeek recorded `missed_bytes = 35.01 GB` and logged sequence gap indicators (`G`) in `history`.
- Therefore, Zeek's accounting is **mathematically exact**: `orig_ip_bytes` ($117\text{ MB}$) represents the captured IP volume, while `orig_bytes` ($35.13\text{ GB}$) represents the true application stream volume inferred from sequence boundaries.

---

## 3. Analysis of `weird.log`

The following two records were logged in `zeek/weird.log`:
1. `TCP_seq_underflow_or_misorder` (UID `Ccx22FOeXWxaUKdLl`, port `37928 -> 5201`)
2. `TCP_ack_underflow_or_misorder` (UID `Ccx22FOeXWxaUKdLl`, port `37928 -> 5201`)

### Environmental Context:
- Neither event represents application-layer corruption or security attacks.
- Because `tcpdump` dropped packets during the high-throughput loopback transfer, Zeek observed non-contiguous sequence numbers and ACK jumps across the surviving sampled packets.
- In our 78-feature vector, this set `has_weird_anomaly = 1.0` and `weird_anomaly_count_flow = 2.0` for Flow 3.

---

## 4. 78-Feature Vector Breakdown & Environmental Influence

Across the 5 extracted vectors:

```
                            78-FEATURE DISTRIBUTION SUMMARY
┌────────────────────────────────────────┬─────────────┬───────────────────────────────────────────┐
│ Feature Category                       │ Count       │ Audit Assessment                          │
├────────────────────────────────────────┼─────────────┼───────────────────────────────────────────┤
│ Zero-Only Features                     │ 39 / 78     │ Expected: DNS, SSL, QUIC, ICMP, Attack    │
│ Constant Non-Zero Features             │ 6 / 78      │ Expected: Private IP, Registered Port     │
│ Inflated / Loopback-Influenced Features│ 9 / 78      │ orig_bytes, total_bytes, bytes_per_packet,│
│                                        │             │ missed_bytes, win_orig_bytes_300s, etc.   │
│ Dynamic Protocol Features              │ 24 / 78     │ duration, packets, TCP/UDP flags, states  │
└────────────────────────────────────────┴─────────────┴───────────────────────────────────────────┘
```

### Features Affected by Loopback / GSO / Buffer Drop:
1. `orig_bytes`, `total_bytes` (Indices 1, 3): Reflect sequence difference ($35.1\text{ GB}$) rather than captured wire length ($117\text{ MB}$).
2. `bytes_per_packet` (Index 7): Inflated to $8.39\text{ MB/pkt}$ because total sequence bytes were divided by captured packet count.
3. `missed_bytes` (Index 11): Reflects uncaptured in-memory payload bytes ($35.0\text{ GB}$).
4. `conn_state_is_SF` vs `conn_state_is_S3` (Index 20): Worker streams logged as `S3` because teardown packets were dropped in the capture buffer.
5. `has_weird_anomaly`, `weird_anomaly_count_flow` (Indices 44, 45): Triggered by sequence gap weirds.
6. `win_src_total_orig_bytes_300s`, `win_src_outbound_byte_rate_60s`, `win_dst_avg_bytes_per_flow_60s`, `win_pair_orig_bytes_std`, `win_pair_total_orig_bytes_300s` (Indices 62, 63, 71, 76, 77): Window aggregations incorporate the $69.83\text{ GB}$ total sequence volume.
7. `is_src_private_ip`, `is_dst_private_ip`, `is_registered_dst_port` (Indices 13, 15, 16): Equal $1.0$ due to `127.0.0.1:5201`.

---

## 5. Provenance & Bit-Exact Reproducibility Verification

A standalone verification test executed Zeek against the preserved `pcap/capture.pcap` file in an isolated temporary directory:
- Flow Count: **5 flows regenerated** (100% match).
- Vector Dimensions: **5 vectors $\times$ 78 features**.
- Numerical Variance: $\max |\mathbf{x}_{\text{saved}} - \mathbf{x}_{\text{regenerated}}| = 0.00000000$ (**0.0 difference across all 390 numerical cells**).

---

## 6. Recommendations & Conclusions

1. **Retention Decision**: **RETAIN `exp_benign_iperf_001`**. It provides a valid, reproducible ground-truth record of unthrottled high-throughput TCP and UDP traffic under passive Zeek monitoring.
2. **Bandwidth Throttling for Future Experiments**: For subsequent `iperf3` benign experiments, pass `-b 50M` or `-b 100M` (e.g. `iperf3 -c 127.0.0.1 -b 50M -t 10`). This bounds loopback throughput within disk write capacity, eliminating pcap packet drops (`missed_bytes == 0`), preventing artificial `weird` sequence gap events, and keeping `bytes_per_packet` within standard MTU expectations.
3. **No Code / Schema Modifications Required**: The 78-feature engineering pipeline, `LogCorrelator`, `WindowAggregator`, and `FeatureVectorAssembler` functioned with 100% mathematical integrity without exceptions, NaNs, or schema deviations.
