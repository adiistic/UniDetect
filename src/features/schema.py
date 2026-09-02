"""
UniDetect Feature Schema Definition (Person 2 - Phase 4)

Defines the exact, authoritative 78-feature numerical schema for ML threat classification,
specifying exact column ordering, default imputation values, and feature groupings.
"""

from typing import Dict, List

# Exact 78 feature column names in deterministic order (Index 0 to 77)
FEATURE_COLUMNS: List[str] = [
    # --------------------------------------------------------------------------
    # Section 1: Flow-Level Features from conn.log / FlowRecord (Indices 0 - 26)
    # --------------------------------------------------------------------------
    "flow_duration",               # 0
    "orig_bytes",                  # 1
    "resp_bytes",                  # 2
    "total_bytes",                 # 3
    "orig_packets",                # 4
    "resp_packets",                # 5
    "total_packets",               # 6
    "bytes_per_packet",            # 7
    "orig_bytes_ratio",            # 8
    "orig_packets_ratio",          # 9
    "bytes_asymmetry_ratio",       # 10
    "missed_bytes",                # 11
    "is_well_known_dst_port",      # 12
    "is_registered_dst_port",      # 13
    "is_dynamic_dst_port",         # 14
    "is_src_private_ip",           # 15
    "is_dst_private_ip",           # 16
    "proto_is_tcp",                # 17
    "proto_is_udp",                # 18
    "proto_is_icmp",               # 19
    "conn_state_is_SF",            # 20
    "conn_state_is_S0",            # 21
    "conn_state_is_REJ",           # 22
    "conn_state_is_RSTO",          # 23
    "history_len",                 # 24
    "history_has_syn",             # 25
    "history_has_reset",           # 26

    # --------------------------------------------------------------------------
    # Section 2: DNS-Level Features from dns.log (Indices 27 - 39)
    # --------------------------------------------------------------------------
    "has_dns_context",             # 27
    "dns_query_len",               # 28
    "dns_query_entropy",           # 29
    "dns_subdomain_depth",         # 30
    "dns_max_label_len",           # 31
    "dns_numeric_ratio",           # 32
    "dns_vowel_ratio",             # 33
    "dns_qtype_is_A",              # 34
    "dns_qtype_is_TXT",            # 35
    "dns_qtype_is_NULL",           # 36
    "dns_is_nxdomain",             # 37
    "dns_answer_count",            # 38
    "dns_rtt",                     # 39

    # --------------------------------------------------------------------------
    # Section 3: QUIC Features from quic.log (Indices 40 - 43)
    # --------------------------------------------------------------------------
    "has_quic_context",            # 40
    "quic_sni_len",                # 41
    "quic_sni_entropy",            # 42
    "quic_dcid_len",               # 43

    # --------------------------------------------------------------------------
    # Section 4: Protocol Anomaly Features from weird.log (Indices 44 - 48)
    # --------------------------------------------------------------------------
    "has_weird_anomaly",           # 44
    "weird_anomaly_count_flow",    # 45
    "weird_is_bad_syn_ack",        # 46
    "weird_is_bad_http",           # 47
    "weird_notice_flag",           # 48

    # --------------------------------------------------------------------------
    # Section 5: TLS Features from ssl.log when available (Indices 49 - 55)
    # --------------------------------------------------------------------------
    "has_ssl_context",             # 49
    "ssl_sni_len",                 # 50
    "ssl_sni_entropy",             # 51
    "ssl_is_outdated_version",     # 52
    "ssl_is_self_signed",          # 53
    "ssl_has_ja3_fingerprint",     # 54
    "ssl_resumed_flag",            # 55

    # --------------------------------------------------------------------------
    # Section 6: Behavioral / Time-Window Features (Indices 56 - 77)
    # --------------------------------------------------------------------------
    # Group A: Source IP Window Features (56 - 67)
    "win_src_flow_count_60s",        # 56
    "win_src_flow_rate_10s",         # 57
    "win_src_unique_dst_ips_60s",    # 58
    "win_src_unique_dst_ports_60s",  # 59
    "win_src_failed_conn_ratio_60s", # 60
    "win_src_s0_syn_ratio_60s",      # 61
    "win_src_total_orig_bytes_300s", # 62
    "win_src_outbound_byte_rate_60s",# 63
    "win_src_dns_query_count_60s",   # 64
    "win_src_dns_nxdomain_ratio_60s",# 65
    "win_src_dns_unique_domains_60s",# 66
    "win_src_weird_count_60s",       # 67

    # Group B: Destination IP Window Features (68 - 71)
    "win_dst_inbound_flow_rate_10s", # 68
    "win_dst_unique_sources_60s",    # 69
    "win_dst_s0_syn_ratio_10s",      # 70
    "win_dst_avg_bytes_per_flow_60s",# 71

    # Group C: Host-Pair Window Features (72 - 77)
    "win_pair_flow_count_300s",      # 72
    "win_pair_delta_t_mean",         # 73
    "win_pair_delta_t_std",          # 74
    "win_pair_delta_t_cv",           # 75
    "win_pair_orig_bytes_std",       # 76
    "win_pair_total_orig_bytes_300s" # 77
]

NUM_FEATURES: int = len(FEATURE_COLUMNS)
assert NUM_FEATURES == 78, f"Expected 78 features in schema, got {NUM_FEATURES}"

# Fast lookup map from column name to index
FEATURE_INDICES: Dict[str, int] = {col: i for i, col in enumerate(FEATURE_COLUMNS)}

# Default neutral numerical values for missing logs/records
FEATURE_DEFAULTS: Dict[str, float] = {col: 0.0 for col in FEATURE_COLUMNS}
# Special baseline defaults for single-flow or neutral states
FEATURE_DEFAULTS.update({
    "is_src_private_ip": 1.0,
    "win_src_flow_count_60s": 1.0,
    "win_src_flow_rate_10s": 0.1,
    "win_src_unique_dst_ips_60s": 1.0,
    "win_src_unique_dst_ports_60s": 1.0,
    "win_dst_inbound_flow_rate_10s": 0.1,
    "win_dst_unique_sources_60s": 1.0,
    "win_pair_flow_count_300s": 1.0,
    "win_pair_delta_t_cv": 1.0,
})

# PS 145 Threat Classes Target Mapping (9 Canonical Classes)
THREAT_CLASSES: List[str] = [
    "BENIGN",             # 0
    "DDOS",               # 1
    "RECON",              # 2
    "DGA",                # 3
    "DNS_TUNNEL",         # 4
    "C2_BEACON",          # 5
    "ENCRYPTED_SESSION",  # 6
    "SLOW_HTTP",          # 7
    "EXFILTRATION",       # 8
]
