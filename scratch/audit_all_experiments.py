import json
import math
import sys
from pathlib import Path
sys.path.insert(0, '.')
from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

experiments = [
    ("BENIGN", "exp_benign_iperf_002", "data/experiments/BENIGN/exp_benign_iperf_002/features/features.jsonl"),
    ("BENIGN", "exp_benign_multi_003", "data/experiments/BENIGN/exp_benign_multi_003/features/features.jsonl"),
    ("BENIGN", "exp_benign_dns_004",   "data/experiments/BENIGN/exp_benign_dns_004/features/features.jsonl"),
    ("BENIGN", "exp_benign_tls_005",   "data/experiments/BENIGN/exp_benign_tls_005/features/features.jsonl"),
    ("DDOS",   "exp_ddos_syn_001",     "data/experiments/DDOS/exp_ddos_syn_001/features/features.jsonl"),
    ("DDOS",   "exp_ddos_udp_002",     "data/experiments/DDOS/exp_ddos_udp_002/features/features.jsonl"),
    ("RECON",  "exp_recon_001",        "data/experiments/RECON/exp_recon_001/features/features.jsonl"),
]

all_data = {}
total_vectors = 0
for cls, eid, path in experiments:
    recs = [json.loads(line) for line in open(path)]
    all_data[eid] = (cls, recs)
    total_vectors += len(recs)
    
    # Check NaN / Inf
    nan_c = sum(1 for r in recs for v in r['features'] if math.isnan(v))
    inf_c = sum(1 for r in recs for v in r['features'] if math.isinf(v))
    dim_c = [len(r['features']) for r in recs]
    assert all(d == 78 for d in dim_c), f"Non-78D in {eid}"
    print(f"[{cls:6s}] {eid:20s}: {len(recs):3d} vectors | NaNs={nan_c}, Infs={inf_c}, Dim=78")

print(f"\nTOTAL VALIDATED CANDIDATE ML VECTORS: {total_vectors}")

# Class Totals
class_totals = {}
for cls, eid, path in experiments:
    class_totals[cls] = class_totals.get(cls, 0) + len(all_data[eid][1])
print("Class breakdown:", class_totals)

# Compare DDOS SYN (001) vs DDOS UDP (002) vs BENIGN vs RECON
syn_recs = all_data["exp_ddos_syn_001"][1]
udp_recs = all_data["exp_ddos_udp_002"][1]
ben_recs = [r for eid in ["exp_benign_iperf_002", "exp_benign_multi_003", "exp_benign_dns_004", "exp_benign_tls_005"] for r in all_data[eid][1]]
rec_recs = all_data["exp_recon_001"][1]

key_feats = [
    "proto_is_tcp", "proto_is_udp", "proto_is_icmp",
    "conn_state_is_SF", "conn_state_is_S0", "conn_state_is_REJ",
    "win_src_unique_dst_ports_60s", "win_src_flow_rate_10s", "win_src_s0_syn_ratio_60s", "win_src_failed_conn_ratio_60s",
    "orig_bytes", "resp_bytes", "total_bytes", "total_packets", "flow_duration"
]

print("\n=== MULTI-MODALITY COMPARISON: BENIGN vs DDOS SYN vs DDOS UDP vs RECON ===")
print(f"{'Feature Name':28s} | {'BENIGN (52)':18s} | {'DDOS SYN (150)':18s} | {'DDOS UDP (151)':18s} | {'RECON (59)':18s}")
print("-" * 112)

for f in key_feats:
    idx = FEATURE_INDICES[f]
    b_m = sum(r['features'][idx] for r in ben_recs) / len(ben_recs)
    s_m = sum(r['features'][idx] for r in syn_recs) / len(syn_recs)
    u_m = sum(r['features'][idx] for r in udp_recs) / len(udp_recs)
    r_m = sum(r['features'][idx] for r in rec_recs) / len(rec_recs)
    print(f"{f:28s} | {b_m:18.2f} | {s_m:18.2f} | {u_m:18.2f} | {r_m:18.2f}")
