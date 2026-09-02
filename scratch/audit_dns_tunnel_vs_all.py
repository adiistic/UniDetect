import json
import math
import sys
sys.path.insert(0, '.')
from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

dns_tunnel_recs = [json.loads(line) for line in open('data/experiments/DNS_TUNNEL/exp_dns_tunnel_001/features/features.jsonl')]
ben_dns_004_recs = [json.loads(line) for line in open('data/experiments/BENIGN/exp_benign_dns_004/features/features.jsonl')]
ben_multi_003_recs = [json.loads(line) for line in open('data/experiments/BENIGN/exp_benign_multi_003/features/features.jsonl') if json.loads(line)['protocol'] == 'udp' and json.loads(line)['destination_endpoint'].endswith(':5353')]

print(f"Total DNS_TUNNEL Vectors:     {len(dns_tunnel_recs)}")
print(f"Total BENIGN DNS 004 Vectors: {len(ben_dns_004_recs)}")
print(f"Total BENIGN Multi 003 DNS:   {len(ben_multi_003_recs)}")

# Check NaN/Inf
nan_c = sum(1 for r in dns_tunnel_recs for v in r['features'] if math.isnan(v))
inf_c = sum(1 for r in dns_tunnel_recs for v in r['features'] if math.isinf(v))
print(f"DNS_TUNNEL NaNs={nan_c}, Infs={inf_c}, Dim={len(dns_tunnel_recs[0]['features'])}")

dns_features = [
    'has_dns_context',
    'dns_query_len',
    'dns_query_entropy',
    'dns_subdomain_depth',
    'dns_max_label_len',
    'dns_numeric_ratio',
    'dns_vowel_ratio',
    'dns_qtype_is_A',
    'dns_qtype_is_TXT',
    'dns_qtype_is_NULL',
    'dns_is_nxdomain',
    'dns_answer_count',
    'dns_rtt',
    'total_bytes',
    'total_packets',
    'flow_duration',
]

print("\n=== COMPARISON: BENIGN DNS (004) vs BENIGN DNS (003) vs DNS_TUNNEL (001) ===")
print(f"{'Feature Name':25s} | {'BENIGN 004 (20)':18s} | {'BENIGN 003 (5)':18s} | {'DNS_TUNNEL 001 (52)':20s}")
print("-" * 90)

for f in dns_features:
    idx = FEATURE_INDICES[f]
    b4_m = sum(r['features'][idx] for r in ben_dns_004_recs) / len(ben_dns_004_recs)
    b3_m = sum(r['features'][idx] for r in ben_multi_003_recs) / len(ben_multi_003_recs)
    dt_m = sum(r['features'][idx] for r in dns_tunnel_recs) / len(dns_tunnel_recs)
    print(f"{f:25s} | {b4_m:18.3f} | {b3_m:18.3f} | {dt_m:20.3f}")
