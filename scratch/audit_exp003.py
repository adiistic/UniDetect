import json
import sys
sys.path.insert(0, '.')
from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

recs = [json.loads(line) for line in open('data/experiments/BENIGN/exp_benign_multi_003/features/features.jsonl')]
meta = json.load(open('data/experiments/BENIGN/exp_benign_multi_003/metadata.json'))

durs = [r['features'][FEATURE_INDICES['flow_duration']] for r in recs]
orig_b = [r['features'][FEATURE_INDICES['orig_bytes']] for r in recs]
resp_b = [r['features'][FEATURE_INDICES['resp_bytes']] for r in recs]
tot_b = [r['features'][FEATURE_INDICES['total_bytes']] for r in recs]
missed_b = [r['features'][FEATURE_INDICES['missed_bytes']] for r in recs]

print(f"Total Vectors: {len(recs)}")
print(f"Protocols: {meta['protocol_distribution']}")
print(f"Ports: {meta['port_distribution']}")
print(f"Durations: min={min(durs):.6f}s, max={max(durs):.4f}s, mean={sum(durs)/len(durs):.4f}s")
print(f"Orig Bytes: min={min(orig_b):,.0f} B, max={max(orig_b):,.0f} B, mean={sum(orig_b)/len(orig_b):,.0f} B")
print(f"Resp Bytes: min={min(resp_b):,.0f} B, max={max(resp_b):,.0f} B, mean={sum(resp_b)/len(resp_b):,.0f} B")
print(f"Total Missed Bytes: {sum(missed_b):.1f} B")

dns_flows = [r for r in recs if r['features'][FEATURE_INDICES['has_dns_context']] == 1.0]
print(f"DNS Flows Extracted: {len(dns_flows)}")
for i, df in enumerate(dns_flows):
    f = df['features']
    print(f"  DNS {i+1}: qlen={f[FEATURE_INDICES['dns_query_len']]}, entropy={f[FEATURE_INDICES['dns_query_entropy']]:.2f}, subdomains={f[FEATURE_INDICES['dns_subdomain_depth']]}, qtype_A={f[FEATURE_INDICES['dns_qtype_is_A']]}")

print("\n=== EXP 003 INDIVIDUAL FLOWS ===")
for i, r in enumerate(recs):
    f = r['features']
    print(f"Flow {i+1:2d} [{r['protocol']:3s} {r['connection_state']:2s}] {r['source_endpoint']:21s} -> {r['destination_endpoint']:14s} | dur={f[0]:8.4f}s | orig={f[1]:>8,.0f} B | resp={f[2]:>8,.0f} B | asym={f[10]:>6.3f} | dns={f[27]}")
