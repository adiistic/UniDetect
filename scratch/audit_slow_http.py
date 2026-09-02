import json
import math
import sys
sys.path.insert(0, '.')
from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

slow_recs = [json.loads(line) for line in open('data/experiments/SLOW_HTTP/exp_slow_http_001/features/features.jsonl')]
ben_http_recs = [json.loads(line) for line in open('data/experiments/BENIGN/exp_benign_multi_003/features/features.jsonl') if json.loads(line)['destination_endpoint'].endswith(':8080')]
ddos_syn_recs = [json.loads(line) for line in open('data/experiments/DDOS/exp_ddos_syn_001/features/features.jsonl')]
ddos_udp_recs = [json.loads(line) for line in open('data/experiments/DDOS/exp_ddos_udp_002/features/features.jsonl')]

print(f"Total SLOW_HTTP Vectors:     {len(slow_recs)}")
print(f"Total BENIGN HTTP Vectors:   {len(ben_http_recs)}")
print(f"Total DDOS SYN Vectors:      {len(ddos_syn_recs)}")
print(f"Total DDOS UDP Vectors:      {len(ddos_udp_recs)}")

# Check NaN/Inf
nan_c = sum(1 for r in slow_recs for v in r['features'] if math.isnan(v))
inf_c = sum(1 for r in slow_recs for v in r['features'] if math.isinf(v))
print(f"SLOW_HTTP NaNs={nan_c}, Infs={inf_c}, Dim={len(slow_recs[0]['features'])}")

key_features = [
    'flow_duration',
    'orig_bytes',
    'resp_bytes',
    'total_bytes',
    'total_packets',
    'bytes_per_packet',
    'bytes_asymmetry_ratio',
    'conn_state_is_SF',
    'conn_state_is_RSTO',
    'conn_state_is_REJ',
    'conn_state_is_S0',
    'win_src_flow_rate_10s',
    'win_dst_inbound_flow_rate_10s',
    'win_src_failed_conn_ratio_60s',
    'win_src_unique_dst_ports_60s',
    'proto_is_tcp',
    'proto_is_udp',
]

print("\n=== COMPARISON: BENIGN HTTP (5) vs SLOW_HTTP (50) vs DDOS SYN (150) vs DDOS UDP (151) ===")
print(f"{'Feature Name':28s} | {'BENIGN HTTP':15s} | {'SLOW_HTTP':15s} | {'DDOS SYN':15s} | {'DDOS UDP':15s}")
print("-" * 95)

for f in key_features:
    idx = FEATURE_INDICES[f]
    b_m = sum(r['features'][idx] for r in ben_http_recs) / len(ben_http_recs) if ben_http_recs else 0.0
    sl_m = sum(r['features'][idx] for r in slow_recs) / len(slow_recs)
    ds_m = sum(r['features'][idx] for r in ddos_syn_recs) / len(ddos_syn_recs)
    du_m = sum(r['features'][idx] for r in ddos_udp_recs) / len(ddos_udp_recs)
    print(f"{f:28s} | {b_m:15.3f} | {sl_m:15.3f} | {ds_m:15.3f} | {du_m:15.3f}")
