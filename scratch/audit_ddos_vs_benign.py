import json
import math
import sys
sys.path.insert(0, '.')
from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

benign_files = [
    'data/experiments/BENIGN/exp_benign_iperf_001/features/features.jsonl',
    'data/experiments/BENIGN/exp_benign_iperf_002/features/features.jsonl',
    'data/experiments/BENIGN/exp_benign_multi_003/features/features.jsonl',
    'data/experiments/BENIGN/exp_benign_dns_004/features/features.jsonl',
]
ddos_file = 'data/experiments/DDOS/exp_ddos_syn_001/features/features.jsonl'

benign_recs = []
for bf in benign_files:
    benign_recs.extend([json.loads(line) for line in open(bf)])

ddos_recs = [json.loads(line) for line in open(ddos_file)]

print(f"Total BENIGN Vectors: {len(benign_recs)}")
print(f"Total DDOS Vectors:   {len(ddos_recs)}")

# Check NaN / Inf across DDOS vectors
ddos_nan = 0
ddos_inf = 0
for r in ddos_recs:
    for v in r['features']:
        if math.isnan(v): ddos_nan += 1
        if math.isinf(v): ddos_inf += 1

print(f"DDOS NaN Count: {ddos_nan}, Inf Count: {ddos_inf}")

# Compare key features
key_features = [
    'orig_bytes',
    'total_bytes',
    'orig_packets',
    'resp_packets',
    'conn_state_is_SF',
    'conn_state_is_REJ',
    'history_has_syn',
    'history_has_reset',
    'win_src_flow_rate_10s',
    'win_src_failed_conn_ratio_60s',
    'win_dst_inbound_flow_rate_10s',
    'is_registered_dst_port',
]

print("\n=== FEATURE COMPARISON: BENIGN (49) vs DDOS (150) ===")
print(f"{'Feature Name':30s} | {'BENIGN Mean (Min..Max)':28s} | {'DDOS Mean (Min..Max)':28s}")
print("-" * 92)

for feat in key_features:
    idx = FEATURE_INDICES[feat]
    b_vals = [r['features'][idx] for r in benign_recs]
    d_vals = [r['features'][idx] for r in ddos_recs]
    
    b_mean = sum(b_vals) / len(b_vals)
    d_mean = sum(d_vals) / len(d_vals)
    
    b_str = f"{b_mean:9.3f} ({min(b_vals):.1f}..{max(b_vals):.1f})"
    d_str = f"{d_mean:9.3f} ({min(d_vals):.1f}..{max(d_vals):.1f})"
    print(f"{feat:30s} | {b_str:28s} | {d_str:28s}")
