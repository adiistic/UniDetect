import json
import math
import sys
from pathlib import Path
sys.path.insert(0, '.')
from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

experiments = [
    ("BENIGN",     "exp_benign_iperf_002", "data/experiments/BENIGN/exp_benign_iperf_002/features/features.jsonl"),
    ("BENIGN",     "exp_benign_multi_003", "data/experiments/BENIGN/exp_benign_multi_003/features/features.jsonl"),
    ("BENIGN",     "exp_benign_dns_004",   "data/experiments/BENIGN/exp_benign_dns_004/features/features.jsonl"),
    ("BENIGN",     "exp_benign_tls_005",   "data/experiments/BENIGN/exp_benign_tls_005/features/features.jsonl"),
    ("DDOS",       "exp_ddos_syn_001",     "data/experiments/DDOS/exp_ddos_syn_001/features/features.jsonl"),
    ("DDOS",       "exp_ddos_udp_002",     "data/experiments/DDOS/exp_ddos_udp_002/features/features.jsonl"),
    ("RECON",      "exp_recon_001",        "data/experiments/RECON/exp_recon_001/features/features.jsonl"),
    ("SLOW_HTTP",  "exp_slow_http_001",    "data/experiments/SLOW_HTTP/exp_slow_http_001/features/features.jsonl"),
    ("DNS_TUNNEL", "exp_dns_tunnel_001",   "data/experiments/DNS_TUNNEL/exp_dns_tunnel_001/features/features.jsonl"),
]

total_vecs = 0
class_counts = {}
for cls, eid, p in experiments:
    recs = [json.loads(line) for line in open(p)]
    total_vecs += len(recs)
    class_counts[cls] = class_counts.get(cls, 0) + len(recs)
    print(f"[{cls:10s}] {eid:22s}: {len(recs):3d} vectors")

print(f"\nTOTAL CANDIDATE DATASET SIZE: {total_vecs} vectors across 5 distinct classes!")
print("Class Counts:", class_counts)
