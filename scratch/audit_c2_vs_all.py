import json
import math
import sys
sys.path.insert(0, '.')
from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

c2_recs = [json.loads(line) for line in open('data/experiments/C2_BEACON/exp_c2_beacon_001/features/features.jsonl')]
ben_http_recs = [json.loads(line) for line in open('data/experiments/BENIGN/exp_benign_multi_003/features/features.jsonl') if json.loads(line)['destination_endpoint'].endswith(':8080')]
slow_recs = [json.loads(line) for line in open('data/experiments/SLOW_HTTP/exp_slow_http_001/features/features.jsonl')]
syn_recs = [json.loads(line) for line in open('data/experiments/DDOS/exp_ddos_syn_001/features/features.jsonl')]
recon_recs = [json.loads(line) for line in open('data/experiments/RECON/exp_recon_001/features/features.jsonl')]

print(f"Total C2_BEACON Vectors:     {len(c2_recs)}")
print(f"Total BENIGN HTTP Vectors:   {len(ben_http_recs)}")
print(f"Total SLOW_HTTP Vectors:     {len(slow_recs)}")
print(f"Total DDOS SYN Vectors:      {len(syn_recs)}")
print(f"Total RECON Vectors:         {len(recon_recs)}")

# Check NaN/Inf
nan_c = sum(1 for r in c2_recs for v in r['features'] if math.isnan(v))
inf_c = sum(1 for r in c2_recs for v in r['features'] if math.isinf(v))
print(f"C2_BEACON NaNs={nan_c}, Infs={inf_c}, Dim={len(c2_recs[0]['features'])}")

temporal_features = [
    'win_pair_delta_t_mean',
    'win_pair_delta_t_std',
    'win_pair_delta_t_cv',
    'win_pair_flow_count_300s',
    'win_pair_orig_bytes_std',
    'win_src_flow_rate_10s',
    'win_dst_inbound_flow_rate_10s',
    'flow_duration',
    'orig_bytes',
    'resp_bytes',
    'total_bytes',
    'total_packets',
    'bytes_per_packet',
]

print("\n=== MULTI-CLASS TEMPORAL COMPARISON ===")
print(f"{'Feature Name':28s} | {'BENIGN HTTP':14s} | {'C2_BEACON':14s} | {'SLOW_HTTP':14s} | {'DDOS SYN':14s} | {'RECON':14s}")
print("-" * 105)

for f in temporal_features:
    idx = FEATURE_INDICES[f]
    b_m = sum(r['features'][idx] for r in ben_http_recs) / len(ben_http_recs) if ben_http_recs else 0.0
    c_m = sum(r['features'][idx] for r in c2_recs) / len(c2_recs)
    sl_m = sum(r['features'][idx] for r in slow_recs) / len(slow_recs)
    ds_m = sum(r['features'][idx] for r in syn_recs) / len(syn_recs)
    rc_m = sum(r['features'][idx] for r in recon_recs) / len(recon_recs)
    print(f"{f:28s} | {b_m:14.3f} | {c_m:14.3f} | {sl_m:14.3f} | {ds_m:14.3f} | {rc_m:14.3f}")
