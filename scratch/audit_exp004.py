import json
import math
import sys
sys.path.insert(0, '.')
from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

recs = [json.loads(line) for line in open('data/experiments/BENIGN/exp_benign_dns_004/features/features.jsonl')]
meta = json.load(open('data/experiments/BENIGN/exp_benign_dns_004/metadata.json'))

print(f"Total Vectors: {len(recs)}")

nan_count = 0
inf_count = 0
for r in recs:
    vec = r['features']
    for v in vec:
        if math.isnan(v): nan_count += 1
        if math.isinf(v): inf_count += 1

print(f"NaN Count: {nan_count}, Inf Count: {inf_count}")

print("\n=== EXP 004 DNS FEATURE VECTORS (20 FLOWS) ===")
for i, r in enumerate(recs):
    f = r['features']
    qlen = f[FEATURE_INDICES['dns_query_len']]
    ent = f[FEATURE_INDICES['dns_query_entropy']]
    depth = f[FEATURE_INDICES['dns_subdomain_depth']]
    max_lbl = f[FEATURE_INDICES['dns_max_label_len']]
    num_r = f[FEATURE_INDICES['dns_numeric_ratio']]
    vow_r = f[FEATURE_INDICES['dns_vowel_ratio']]
    is_a = f[FEATURE_INDICES['dns_qtype_is_A']]
    is_txt = f[FEATURE_INDICES['dns_qtype_is_TXT']]
    nx = f[FEATURE_INDICES['dns_is_nxdomain']]
    ans_c = f[FEATURE_INDICES['dns_answer_count']]
    
    qtype_str = "A" if is_a == 1.0 else ("TXT" if is_txt == 1.0 else "OTHER")
    status_str = "NXDOMAIN" if nx == 1.0 else f"OK({int(ans_c)} ans)"
    
    print(f"Flow {i+1:2d} | len={qlen:4.1f} | ent={ent:5.3f} | depth={int(depth)} | max_lbl={int(max_lbl):2d} | num_r={num_r:.3f} | vow_r={vow_r:.3f} | type={qtype_str:3s} | {status_str}")
