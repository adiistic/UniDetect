import json
import sys
sys.path.insert(0, '.')
from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

b_recs = [json.loads(line) for line in open('data/experiments/BENIGN/exp_benign_pilot_001/features.jsonl')]
d_recs = [json.loads(line) for line in open('data/experiments/DDOS/exp_ddos_pilot_001/features.jsonl')]
all_recs = b_recs + d_recs

d_ddos = [r for r in d_recs if r['label'] == 'DDOS']
b_benign = b_recs + [r for r in d_recs if r['label'] == 'BENIGN']

print(f"Total records: {len(all_recs)} (Benign: {len(b_benign)}, DDOS: {len(d_ddos)})")

constant_feats = []
zero_feats = []
distinct_feats = {}

for idx, col in enumerate(FEATURE_COLUMNS):
    b_vals = [r['features'][idx] for r in b_benign]
    d_vals = [r['features'][idx] for r in d_ddos]
    all_vals = [r['features'][idx] for r in all_recs]
    
    unique_all = set(all_vals)
    if len(unique_all) == 1:
        if 0.0 in unique_all:
            zero_feats.append(col)
        else:
            constant_feats.append((col, list(unique_all)[0]))
    else:
        distinct_feats[col] = {
            'b_min': min(b_vals), 'b_max': max(b_vals), 'b_mean': sum(b_vals)/len(b_vals),
            'd_min': min(d_vals), 'd_max': max(d_vals), 'd_mean': sum(d_vals)/len(d_vals),
            'b_unique': len(set(b_vals)), 'd_unique': len(set(d_vals))
        }

print(f"\n=== ALWAYS ZERO FEATURES ({len(zero_feats)} / 78) ===")
print(", ".join(zero_feats))

print(f"\n=== CONSTANT NON-ZERO FEATURES ({len(constant_feats)} / 78) ===")
for col, val in constant_feats:
    print(f"  {col} = {val}")

print(f"\n=== DYNAMIC FEATURES WITH DISTRIBUTIONS ({len(distinct_feats)} / 78) ===")
for col, stats in distinct_feats.items():
    print(f"{col:32s} | Benign: mean={stats['b_mean']:10.4f} [{stats['b_min']:8.2f}, {stats['b_max']:8.2f}] | DDOS: mean={stats['d_mean']:10.4f} [{stats['d_min']:8.2f}, {stats['d_max']:8.2f}]")
