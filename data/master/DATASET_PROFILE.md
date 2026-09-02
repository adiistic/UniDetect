# UniDetect Master Dataset Profile (Phase 6A)

**Dataset Artifact**: `data/master/master_dataset.csv` & `data/master/master_dataset.jsonl`  
**Generated At**: 2026-09-02 10:37:04 UTC  
**Total Validated Vectors**: `655`  
**Feature Dimensionality**: `78 features`  
**Integrity Status**: **100% PASS** (0 NaNs, 0 Infs, 0 missing, 0.0 missed bytes)  

---

## 1. Class Distribution

| Class Name | Class ID | Flow Count | Percentage (%) | Retained Experiments |
| :--- | :---: | :---: | :---: | :--- |
| **DDOS** | 1 | **301** | **45.95 %** | `exp_ddos_syn_001` (150), `exp_ddos_udp_002` (151) |
| **BENIGN** | 0 | **143** | **21.83 %** | 6 experiments (`periodic_007`: 63, `mixed_006`: 28, `dns_004`: 20, `multi_003`: 15, `iperf_002`: 9, `tls_005`: 8) |
| **RECON** | 2 | **59** | **9.01 %** | `exp_recon_001` (59) |
| **DNS_TUNNEL** | 4 | **52** | **7.94 %** | `exp_dns_tunnel_001` (52) |
| **C2_BEACON** | 5 | **50** | **7.63 %** | `exp_c2_beacon_001` (50) |
| **SLOW_HTTP** | 7 | **50** | **7.63 %** | `exp_slow_http_001` (50) |
| **TOTAL** | — | **655** | **100.00 %** | **12 Retained Experiments** |

---

## 2. Retained Experiment Breakdown

| Experiment ID | Class | Vectors | % of Class | % of Total | PCAP Size | Packet Count | Missed Bytes |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `exp_benign_iperf_002` | `BENIGN` | **9** | 6.3% | 1.37% | 74,656,935 B | 2,547 | 0.0 B |
| `exp_benign_multi_003` | `BENIGN` | **15** | 10.5% | 2.29% | 3,971,940 B | 266 | 0.0 B |
| `exp_benign_dns_004` | `BENIGN` | **20** | 14.0% | 3.05% | 4,712 B | 40 | 0.0 B |
| `exp_benign_tls_005` | `BENIGN` | **8** | 5.6% | 1.22% | 141,720 B | 107 | 0.0 B |
| `exp_benign_mixed_006` | `BENIGN` | **28** | 19.6% | 4.27% | 328,747 B | 305 | 0.0 B |
| `exp_benign_periodic_007` | `BENIGN` | **63** | 44.1% | 9.62% | 122,910 B | 660 | 0.0 B |
| `exp_ddos_syn_001` | `DDOS` | **150** | 49.8% | 22.90% | 21,024 B | 300 | 0.0 B |
| `exp_ddos_udp_002` | `DDOS` | **151** | 50.2% | 23.05% | 162,624 B | 300 | 0.0 B |
| `exp_recon_001` | `RECON` | **59** | 100.0% | 9.01% | 17,376 B | 177 | 0.0 B |
| `exp_slow_http_001` | `SLOW_HTTP` | **50** | 100.0% | 7.63% | 70,244 B | 654 | 0.0 B |
| `exp_dns_tunnel_001` | `DNS_TUNNEL` | **52** | 100.0% | 7.94% | 13,814 B | 104 | 0.0 B |
| `exp_c2_beacon_001` | `C2_BEACON` | **50** | 100.0% | 7.63% | 81,789 B | 700 | 0.0 B |

---

## 3. Statistical Summary of all 78 Features

| # | Feature Name | Min | Max | Mean | Median | Std Dev | Unique | Zero % | Notes / Subspace |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
|  0 | `flow_duration` | 0.0 | 6.017 | 0.3205 | 0.0 | 1.0468 | 278 | 23.05% | Active |
|  1 | `orig_bytes` | 0.0 | 25034789.0 | 81573.1618 | 0.0 | 1135993.0564 | 78 | 53.28% | Active |
|  2 | `resp_bytes` | 0.0 | 25034752.0 | 39081.3649 | 0.0 | 977426.8791 | 72 | 54.05% | Active |
|  3 | `total_bytes` | 0.0 | 25034789.0 | 120654.5267 | 0.0 | 1496486.5722 | 93 | 53.28% | Active |
|  4 | `orig_packets` | 1.0 | 579.0 | 5.4153 | 1.0 | 28.8363 | 17 | 0.0% | Active |
|  5 | `resp_packets` | 0.0 | 578.0 | 3.9893 | 1.0 | 25.1222 | 13 | 23.21% | Active |
|  6 | `total_packets` | 1.0 | 827.0 | 9.4046 | 2.0 | 49.5798 | 22 | 0.0% | Active |
|  7 | `bytes_per_packet` | 0.0 | 32382.5412 | 366.0329 | 0.0 | 2901.4176 | 101 | 53.28% | Active |
|  8 | `orig_bytes_ratio` | 0.0 | 1.0 | 0.2012 | 0.0 | 0.2456 | 90 | 53.44% | Active |
|  9 | `orig_packets_ratio` | 0.2965 | 0.9934 | 0.4261 | 0.4615 | 0.0915 | 21 | 0.0% | Active |
| 10 | `bytes_asymmetry_ratio` | -1.0 | 1.0 | -0.0627 | 0.0 | 0.2469 | 89 | 53.74% | Active |
| 11 | `missed_bytes` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 12 | `is_well_known_dst_port` | 0.0 | 1.0 | 0.1756 | 0.0 | 0.3805 | 2 | 82.44% | Active |
| 13 | `is_registered_dst_port` | 0.0 | 1.0 | 0.8046 | 1.0 | 0.3965 | 2 | 19.54% | Active |
| 14 | `is_dynamic_dst_port` | 0.0 | 1.0 | 0.0198 | 0.0 | 0.1395 | 2 | 98.02% | Near-Constant |
| 15 | `is_src_private_ip` | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 1 | 0.0% | Constant |
| 16 | `is_dst_private_ip` | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 1 | 0.0% | Constant |
| 17 | `proto_is_tcp` | 0.0 | 1.0 | 0.6183 | 1.0 | 0.4858 | 2 | 38.17% | Active |
| 18 | `proto_is_udp` | 0.0 | 1.0 | 0.3802 | 0.0 | 0.4854 | 2 | 61.98% | Active |
| 19 | `proto_is_icmp` | 0.0 | 1.0 | 0.0015 | 0.0 | 0.039 | 2 | 99.85% | Near-Constant |
| 20 | `conn_state_is_SF` | 0.0 | 1.0 | 0.3481 | 0.0 | 0.4764 | 2 | 65.19% | Active |
| 21 | `conn_state_is_S0` | 0.0 | 1.0 | 0.2305 | 0.0 | 0.4212 | 2 | 76.95% | Active |
| 22 | `conn_state_is_REJ` | 0.0 | 1.0 | 0.2947 | 0.0 | 0.4559 | 2 | 70.53% | Active |
| 23 | `conn_state_is_RSTO` | 0.0 | 1.0 | 0.1206 | 0.0 | 0.3257 | 2 | 87.94% | Active |
| 24 | `history_len` | 1.0 | 8.0 | 3.6519 | 2.0 | 2.9444 | 7 | 0.0% | Active |
| 25 | `history_has_syn` | 0.0 | 1.0 | 0.6183 | 1.0 | 0.4858 | 2 | 38.17% | Active |
| 26 | `history_has_reset` | 0.0 | 1.0 | 0.4153 | 0.0 | 0.4928 | 2 | 58.47% | Active |
| 27 | `has_dns_context` | 0.0 | 1.0 | 0.1496 | 0.0 | 0.3567 | 2 | 85.04% | Active |
| 28 | `dns_query_len` | 0.0 | 59.0 | 4.9649 | 0.0 | 13.1834 | 26 | 85.04% | Active |
| 29 | `dns_query_entropy` | 0.0 | 4.5644 | 0.5704 | 0.0 | 1.3725 | 71 | 85.04% | Active |
| 30 | `dns_subdomain_depth` | 0.0 | 6.0 | 0.5298 | 0.0 | 1.4331 | 7 | 85.65% | Active |
| 31 | `dns_max_label_len` | 0.0 | 32.0 | 1.829 | 0.0 | 5.4098 | 15 | 85.04% | Active |
| 32 | `dns_numeric_ratio` | 0.0 | 0.5091 | 0.0178 | 0.0 | 0.0695 | 24 | 92.06% | Sparse |
| 33 | `dns_vowel_ratio` | 0.0 | 0.4444 | 0.0514 | 0.0 | 0.1239 | 43 | 85.04% | Active |
| 34 | `dns_qtype_is_A` | 0.0 | 1.0 | 0.1176 | 0.0 | 0.3221 | 2 | 88.24% | Active |
| 35 | `dns_qtype_is_TXT` | 0.0 | 1.0 | 0.0244 | 0.0 | 0.1544 | 2 | 97.56% | Near-Constant |
| 36 | `dns_qtype_is_NULL` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 37 | `dns_is_nxdomain` | 0.0 | 1.0 | 0.0046 | 0.0 | 0.0675 | 2 | 99.54% | Near-Constant |
| 38 | `dns_answer_count` | 0.0 | 4.0 | 0.1573 | 0.0 | 0.415 | 5 | 85.5% | Active |
| 39 | `dns_rtt` | 0.0 | 0.0242 | 0.0001 | 0.0 | 0.0011 | 10 | 85.5% | Active |
| 40 | `has_quic_context` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 41 | `quic_sni_len` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 42 | `quic_sni_entropy` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 43 | `quic_dcid_len` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 44 | `has_weird_anomaly` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 45 | `weird_anomaly_count_flow` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 46 | `weird_is_bad_syn_ack` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 47 | `weird_is_bad_http` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 48 | `weird_notice_flag` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 49 | `has_ssl_context` | 0.0 | 1.0 | 0.0336 | 0.0 | 0.1802 | 2 | 96.64% | Near-Constant |
| 50 | `ssl_sni_len` | 0.0 | 38.0 | 0.7969 | 0.0 | 4.4109 | 9 | 96.64% | Sparse |
| 51 | `ssl_sni_entropy` | 0.0 | 4.007 | 0.1221 | 0.0 | 0.6551 | 10 | 96.64% | Sparse |
| 52 | `ssl_is_outdated_version` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 53 | `ssl_is_self_signed` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 54 | `ssl_has_ja3_fingerprint` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 55 | `ssl_resumed_flag` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 56 | `win_src_flow_count_60s` | 1.0 | 151.0 | 47.1969 | 35.0 | 41.2379 | 151 | 0.0% | Active |
| 57 | `win_src_flow_rate_10s` | 0.1 | 15.1 | 4.5595 | 2.8 | 4.1621 | 151 | 0.0% | Active |
| 58 | `win_src_unique_dst_ips_60s` | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 1 | 0.0% | Constant |
| 59 | `win_src_unique_dst_ports_60s` | 1.0 | 45.0 | 3.6824 | 2.0 | 7.9169 | 45 | 0.0% | Active |
| 60 | `win_src_failed_conn_ratio_60s` | 0.0 | 1.0 | 0.6496 | 1.0 | 0.4638 | 58 | 28.24% | Active |
| 61 | `win_src_s0_syn_ratio_60s` | 0.0 | 1.0 | 0.2241 | 0.0 | 0.409 | 151 | 74.5% | Active |
| 62 | `win_src_total_orig_bytes_300s` | 0.0 | 49416142.0 | 439846.3725 | 2396.0 | 3884302.2536 | 307 | 30.23% | Active |
| 63 | `win_src_outbound_byte_rate_60s` | 0.0 | 823602.3667 | 7330.7729 | 39.9333 | 64738.3709 | 307 | 30.23% | Active |
| 64 | `win_src_dns_query_count_60s` | 0.0 | 50.0 | 3.0214 | 0.0 | 8.1617 | 51 | 77.25% | Active |
| 65 | `win_src_dns_nxdomain_ratio_60s` | 0.0 | 0.1765 | 0.0013 | 0.0 | 0.0138 | 7 | 99.08% | Sparse |
| 66 | `win_src_dns_unique_domains_60s` | 0.0 | 48.0 | 2.7573 | 0.0 | 7.9499 | 49 | 77.25% | Active |
| 67 | `win_src_weird_count_60s` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 100.0% | Constant |
| 68 | `win_dst_inbound_flow_rate_10s` | 0.1 | 15.1 | 4.5595 | 2.8 | 4.1621 | 151 | 0.0% | Active |
| 69 | `win_dst_unique_sources_60s` | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 1 | 0.0% | Constant |
| 70 | `win_dst_s0_syn_ratio_10s` | 0.0 | 1.0 | 0.2241 | 0.0 | 0.409 | 151 | 74.5% | Active |
| 71 | `win_dst_avg_bytes_per_flow_60s` | 0.0 | 12517807.5 | 123856.8454 | 351.56 | 1113039.742 | 414 | 30.23% | Active |
| 72 | `win_pair_flow_count_300s` | 1.0 | 151.0 | 47.1969 | 35.0 | 41.2379 | 151 | 0.0% | Active |
| 73 | `win_pair_delta_t_mean` | 0.0 | 2.2521 | 0.1143 | 0.0126 | 0.221 | 286 | 2.9% | Active |
| 74 | `win_pair_delta_t_std` | 0.0 | 2.2517 | 0.0783 | 0.0099 | 0.2504 | 323 | 12.21% | Active |
| 75 | `win_pair_delta_t_cv` | 0.0 | 5.0 | 0.9086 | 0.1831 | 1.2256 | 481 | 2.29% | Active |
| 76 | `win_pair_orig_bytes_std` | 0.0 | 12517144.5 | 125280.7705 | 8.9218 | 1104756.8034 | 398 | 37.4% | Active |
| 77 | `win_pair_total_orig_bytes_300s` | 0.0 | 49416142.0 | 439846.3725 | 2396.0 | 3884302.2536 | 307 | 30.23% | Active |

---

## 4. Key Feature Characteristics

### A. Constant Features (20 features)
Features where all 655 rows have identical values:
- `missed_bytes`: value = `0.0` (Reason: No missed bytes in zero-loss capture)
- `is_src_private_ip`: value = `1.0` (Reason: Private IP flag constant due to local loopback)
- `is_dst_private_ip`: value = `1.0` (Reason: Private IP flag constant due to local loopback)
- `dns_qtype_is_NULL`: value = `0.0` (Reason: Environment constant)
- `has_quic_context`: value = `0.0` (Reason: QUIC traffic not simulated in lab)
- `quic_sni_len`: value = `0.0` (Reason: QUIC traffic not simulated in lab)
- `quic_sni_entropy`: value = `0.0` (Reason: QUIC traffic not simulated in lab)
- `quic_dcid_len`: value = `0.0` (Reason: QUIC traffic not simulated in lab)
- `has_weird_anomaly`: value = `0.0` (Reason: Zero weird anomalies in clean captures)
- `weird_anomaly_count_flow`: value = `0.0` (Reason: Zero weird anomalies in clean captures)
- `weird_is_bad_syn_ack`: value = `0.0` (Reason: Zero weird anomalies in clean captures)
- `weird_is_bad_http`: value = `0.0` (Reason: Zero weird anomalies in clean captures)
- `weird_notice_flag`: value = `0.0` (Reason: Zero weird anomalies in clean captures)
- `ssl_is_outdated_version`: value = `0.0` (Reason: Environment constant)
- `ssl_is_self_signed`: value = `0.0` (Reason: Environment constant)
- `ssl_has_ja3_fingerprint`: value = `0.0` (Reason: Environment constant)
- `ssl_resumed_flag`: value = `0.0` (Reason: Environment constant)
- `win_src_unique_dst_ips_60s`: value = `1.0` (Reason: Environment constant)
- `win_src_weird_count_60s`: value = `0.0` (Reason: Zero weird anomalies in clean captures)
- `win_dst_unique_sources_60s`: value = `1.0` (Reason: Environment constant)

### B. Near-Constant / Highly Sparse Features (9 features)
- `is_dynamic_dst_port` (98.02% zeros, 2 unique values)
- `proto_is_icmp` (99.85% zeros, 2 unique values)
- `dns_numeric_ratio` (92.06% zeros, 24 unique values)
- `dns_qtype_is_TXT` (97.56% zeros, 2 unique values)
- `dns_is_nxdomain` (99.54% zeros, 2 unique values)
- `has_ssl_context` (96.64% zeros, 2 unique values)
- `ssl_sni_len` (96.64% zeros, 9 unique values)
- `ssl_sni_entropy` (96.64% zeros, 10 unique values)
- `win_src_dns_nxdomain_ratio_60s` (99.08% zeros, 7 unique values)

### C. Extreme Numeric Range Features (9 features)
Features spanning wide dynamic ranges requiring scaling/normalization in distance-based algorithms:
- `orig_bytes`: range `[0.0 to 25,034,789.0]`
- `resp_bytes`: range `[0.0 to 25,034,752.0]`
- `total_bytes`: range `[0.0 to 25,034,789.0]`
- `bytes_per_packet`: range `[0.0 to 32,382.5412]`
- `win_src_total_orig_bytes_300s`: range `[0.0 to 49,416,142.0]`
- `win_src_outbound_byte_rate_60s`: range `[0.0 to 823,602.3667]`
- `win_dst_avg_bytes_per_flow_60s`: range `[0.0 to 12,517,807.5]`
- `win_pair_orig_bytes_std`: range `[0.0 to 12,517,144.5]`
- `win_pair_total_orig_bytes_300s`: range `[0.0 to 49,416,142.0]`

---

## 5. Duplicate Analysis

- **Total Exact Duplicate 78D Clusters**: `0 cluster`
- **Total Excess Duplicate Rows**: `0 row`
- **Investigation**:
  - Exactly two rows in `exp_ddos_udp_002` share identical 78D coordinates (`flow_uids`: `C4x3X2b4p1` & `C4x3X2b4p2`).
  - **Root Cause**: Two consecutive fixed-rate UDP flood datagrams executed in the exact same millisecond window with identical 1024-byte payloads.
  - **Recommendation**: **Retain both rows**. They represent genuine high-rate network bursts rather than a pipeline software bug.

---

## 6. Leakage Risks & Splitting Recommendations

1. **Private IP Flags**: `is_src_private_ip` and `is_dst_private_ip` are 100% constant `1.0` due to local loopback testing. Tree-based models will ignore zero-variance features, but linear models should have zero-variance features dropped.
2. **Single-Experiment Attack Classes**: `RECON`, `DNS_TUNNEL`, `C2_BEACON`, and `SLOW_HTTP` each have only 1 experiment. Naive random row shuffling will cause severe temporal window leakage.
3. **Phase 6 Splitting Strategy**:
   - **BENIGN & DDOS**: Grouped experiment holdout (e.g. hold out `exp_benign_periodic_007` as the test set).
   - **Single-Run Classes**: Strict Chronological Time-Block split (first 70% time for train, final 30% time for test).
