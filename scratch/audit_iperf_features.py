import json
import sys
sys.path.insert(0, '.')
from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

recs = [json.loads(line) for line in open('data/experiments/BENIGN/exp_benign_iperf_001/features/features.jsonl')]

zero_feats = []
const_feats = []
dynamic_feats = []
huge_feats = []

for idx, col in enumerate(FEATURE_COLUMNS):
    vals = [r['features'][idx] for r in recs]
    uniq = set(vals)
    if len(uniq) == 1:
        if 0.0 in uniq:
            zero_feats.append(col)
        else:
            const_feats.append((col, list(uniq)[0]))
    else:
        dynamic_feats.append((col, vals))
    
    if any(abs(v) > 1e6 for v in vals):
        huge_feats.append((col, max(vals)))

print(f"=== ZERO FEATURES ({len(zero_feats)} / 78) ===")
print(", ".join(zero_feats))

print(f"\n=== CONSTANT NON-ZERO FEATURES ({len(const_feats)} / 78) ===")
for col, val in const_feats:
    print(f"  {col} = {val}")

print(f"\n=== HUGE / INFLATED FEATURES ({len(huge_feats)}) ===")
for col, max_val in huge_feats:
    print(f"  {col} (max = {max_val:,.2f})")

print(f"\n=== DYNAMIC FEATURES ({len(dynamic_feats)}) ===")
for col, vals in dynamic_feats:
    print(f"  {col:32s}: {vals}")
