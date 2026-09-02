import json
import math
import sys
sys.path.insert(0, '.')
from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

benign_files = [
    'data/experiments/BENIGN/exp_benign_iperf_002/features/features.jsonl',
    'data/experiments/BENIGN/exp_benign_multi_003/features/features.jsonl',
    'data/experiments/BENIGN/exp_benign_dns_004/features/features.jsonl',
    'data/experiments/BENIGN/exp_benign_tls_005/features/features.jsonl',
]
ddos_file = 'data/experiments/DDOS/exp_ddos_syn_001/features/features.jsonl'
recon_file = 'data/experiments/RECON/exp_recon_001/features/features.jsonl'

benign_recs = []
for bf in benign_files:
    benign_recs.extend([json.loads(line) for line in open(bf)])

ddos_recs = [json.loads(line) for line in open(ddos_file)]
recon_recs = [json.loads(line) for line in open(recon_file)]

print(f"Total Candidate BENIGN Vectors: {len(benign_recs)}")
print(f"Total Candidate DDOS Vectors:   {len(ddos_recs)}")
print(f"Total Candidate RECON Vectors:  {len(recon_recs)}")

# Check NaN/Inf on RECON
recon_nan = sum(1 for r in recon_recs for v in r['features'] if math.isnan(v))
recon_inf = sum(1 for r in recon_recs for v in r['features'] if math.isinf(v))
print(f"RECON NaN={recon_nan}, Inf={recon_inf}")

key_features = [
    'win_src_unique_dst_ports_60s',
    'win_src_flow_count_60s',
    'win_src_flow_rate_10s',
    'win_src_failed_conn_ratio_60s',
    'win_src_s0_syn_ratio_60s',
    'conn_state_is_REJ',
    'conn_state_is_SF',
    'history_has_syn',
    'history_has_reset',
    'is_dynamic_dst_port',
    'is_well_known_dst_port',
    'is_registered_dst_port',
    'flow_duration',
    'orig_bytes',
    'resp_bytes',
    'total_bytes',
    'total_packets',
    'bytes_per_packet',
]

print("\n=== THREE-WAY CLASS COMPARISON: BENIGN (52) vs RECON (59) vs DDOS (150) ===")
print(f"{'Feature Name':30s} | {'BENIGN Mean (Min..Max)':25s} | {'RECON Mean (Min..Max)':25s} | {'DDOS Mean (Min..Max)':25s}")
print("-" * 115)

for feat in key_features:
    idx = FEATURE_INDICES[feat]
    b_vals = [r['features'][idx] for r in benign_recs]
    r_vals = [r['features'][idx] for r in recon_recs]
    d_vals = [r['features'][idx] for r in ddos_recs]
    
    b_str = f"{sum(b_vals)/len(b_vals):7.2f} ({min(b_vals):.0f}..{max(b_vals):.0f})"
    r_str = f"{sum(r_vals)/len(r_vals):7.2f} ({min(r_vals):.0f}..{max(r_vals):.0f})"
    d_str = f"{sum(d_vals)/len(d_vals):7.2f} ({min(d_vals):.0f}..{max(d_vals):.0f})"
    print(f"{feat:30s} | {b_str:25s} | {r_str:25s} | {d_str:25s}")
