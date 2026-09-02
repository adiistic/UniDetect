import json
import math
import sys
sys.path.insert(0, '.')
from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

recs = [json.loads(line) for line in open('data/experiments/BENIGN/exp_benign_tls_005/features/features.jsonl')]
meta = json.load(open('data/experiments/BENIGN/exp_benign_tls_005/metadata.json'))

print(f"Total Vectors in Exp 005: {len(recs)}")

nan_count = 0
inf_count = 0
for r in recs:
    vec = r['features']
    for v in vec:
        if math.isnan(v): nan_count += 1
        if math.isinf(v): inf_count += 1

print(f"NaN Count: {nan_count}, Inf Count: {inf_count}")

print("\n=== EXP 005 TLS FEATURE VECTORS (8 FLOWS) ===")
for i, r in enumerate(recs):
    f = r['features']
    has_ssl = f[FEATURE_INDICES['has_ssl_context']]
    sni_len = f[FEATURE_INDICES['ssl_sni_len']]
    sni_ent = f[FEATURE_INDICES['ssl_sni_entropy']]
    outdated = f[FEATURE_INDICES['ssl_is_outdated_version']]
    self_signed = f[FEATURE_INDICES['ssl_is_self_signed']]
    ja3 = f[FEATURE_INDICES['ssl_has_ja3_fingerprint']]
    resumed = f[FEATURE_INDICES['ssl_resumed_flag']]
    
    ob = f[FEATURE_INDICES['orig_bytes']]
    rb = f[FEATURE_INDICES['resp_bytes']]
    dur = f[FEATURE_INDICES['flow_duration']]
    
    print(f"Flow {i+1} [{r['protocol']} {r['connection_state']}] {r['source_endpoint']:21s} -> {r['destination_endpoint']:14s} | dur={dur:6.4f}s | orig={ob:6.0f} B | resp={rb:6.0f} B | ssl_ctx={has_ssl} | sni_len={sni_len:4.1f} | sni_ent={sni_ent:5.3f} | self_signed={self_signed} | outdated={outdated}")
