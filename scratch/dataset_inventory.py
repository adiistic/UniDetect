import json
import math
import statistics
import sys
from pathlib import Path
from typing import Dict, List, Any

REPO_ROOT = Path(".").resolve()
sys.path.insert(0, str(REPO_ROOT))

from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES, NUM_FEATURES

experiments = [
    ("exp_benign_iperf_001", "data/experiments/BENIGN/exp_benign_iperf_001", True),
    ("exp_benign_iperf_002", "data/experiments/BENIGN/exp_benign_iperf_002", False),
    ("exp_benign_multi_003", "data/experiments/BENIGN/exp_benign_multi_003", False),
    ("exp_benign_dns_004", "data/experiments/BENIGN/exp_benign_dns_004", False),
]

exp_data = {}
candidate_recs = []

for exp_id, path_str, is_excluded in experiments:
    feat_file = Path(path_str) / "features" / "features.jsonl"
    meta_file = Path(path_str) / "metadata.json"
    
    recs = [json.loads(line) for line in open(feat_file)]
    meta = json.load(open(meta_file))
    
    exp_data[exp_id] = {
        "recs": recs,
        "meta": meta,
        "is_excluded": is_excluded,
    }
    if not is_excluded:
        candidate_recs.extend(recs)

print("=" * 100)
print("1. PER-EXPERIMENT INVENTORY REPORT")
print("=" * 100)

for exp_id, data in exp_data.items():
    recs = data["recs"]
    meta = data["meta"]
    excluded_str = " [EXCLUDED FROM ML]" if data["is_excluded"] else " [CANDIDATE ML DATA]"
    
    protos = {}
    states = {}
    src_ports = {}
    dst_ports = {}
    
    durs = []
    orig_b = []
    resp_b = []
    tot_b = []
    asyms = []
    missed_b = []
    weird_counts = []
    
    nan_count = 0
    inf_count = 0
    missing_count = 0
    
    for r in recs:
        p = r["protocol"]
        protos[p] = protos.get(p, 0) + 1
        st = r["connection_state"]
        states[st] = states.get(st, 0) + 1
        
        sp = r["source_endpoint"].split(":")[-1]
        src_ports[sp] = src_ports.get(sp, 0) + 1
        dp = r["destination_endpoint"].split(":")[-1]
        dst_ports[dp] = dst_ports.get(dp, 0) + 1
        
        vec = r["features"]
        if len(vec) != 78:
            missing_count += abs(78 - len(vec))
            
        for v in vec:
            if math.isnan(v): nan_count += 1
            if math.isinf(v): inf_count += 1
            
        durs.append(vec[FEATURE_INDICES["flow_duration"]])
        orig_b.append(vec[FEATURE_INDICES["orig_bytes"]])
        resp_b.append(vec[FEATURE_INDICES["resp_bytes"]])
        tot_b.append(vec[FEATURE_INDICES["total_bytes"]])
        asyms.append(vec[FEATURE_INDICES["bytes_asymmetry_ratio"]])
        missed_b.append(vec[FEATURE_INDICES["missed_bytes"]])
        weird_counts.append(vec[FEATURE_INDICES["weird_anomaly_count_flow"]])
        
    print(f"\n--- {exp_id}{excluded_str} ---")
    print(f"Label:                 {meta['label']} (id={meta['label_id']})")
    print(f"Flow/Vector Count:     {len(recs)}")
    print(f"Protocols:             {protos}")
    print(f"Connection States:     {states}")
    print(f"Destination Ports:     {dst_ports}")
    print(f"Duration (s):          min={min(durs):.6f}, max={max(durs):.4f}, mean={statistics.mean(durs):.4f}")
    print(f"Orig Bytes:            min={min(orig_b):,.0f}, max={max(orig_b):,.0f}, mean={statistics.mean(orig_b):,.0f}")
    print(f"Resp Bytes:            min={min(resp_b):,.0f}, max={max(resp_b):,.0f}, mean={statistics.mean(resp_b):,.0f}")
    print(f"Total Bytes:           min={min(tot_b):,.0f}, max={max(tot_b):,.0f}, mean={statistics.mean(tot_b):,.0f}")
    print(f"Bytes Asymmetry Ratio: min={min(asyms):.3f}, max={max(asyms):.3f}, mean={statistics.mean(asyms):.3f}")
    print(f"Missed Bytes:          total={sum(missed_b):,.0f}, max={max(missed_b):,.0f}")
    print(f"Weird Anomalies:       total={sum(weird_counts):.0f}, max={max(weird_counts):.0f}")
    print(f"Dimensionality:        78D (all {len(recs)} vectors)")
    print(f"NaN / Inf / Missing:   NaN={nan_count}, Inf={inf_count}, Missing={missing_count}")

print("\n" + "=" * 100)
print(f"2. CANDIDATE ML CORPUS FEATURE ANALYSIS (Experiments 002 + 003 + 004 : Total {len(candidate_recs)} flows)")
print("=" * 100)

stats_78 = []
for idx, col in enumerate(FEATURE_COLUMNS):
    vals = [r["features"][idx] for r in candidate_recs]
    non_zero = sum(1 for v in vals if v != 0.0)
    uniq = set(vals)
    min_v = min(vals)
    max_v = max(vals)
    mean_v = statistics.mean(vals)
    std_v = statistics.stdev(vals) if len(vals) > 1 else 0.0
    
    is_const = (len(uniq) == 1)
    is_zero = (is_const and 0.0 in uniq)
    
    # Check populating experiments
    pop_exps = []
    for exp_id in ["exp_benign_iperf_002", "exp_benign_multi_003", "exp_benign_dns_004"]:
        e_vals = [r["features"][idx] for r in exp_data[exp_id]["recs"]]
        if any(v != 0.0 for v in e_vals):
            pop_exps.append(exp_id.replace("exp_benign_", ""))
            
    stats_78.append({
        "idx": idx,
        "name": col,
        "min": min_v,
        "max": max_v,
        "mean": mean_v,
        "std": std_v,
        "non_zero": non_zero,
        "unique": len(uniq),
        "is_const": is_const,
        "is_zero": is_zero,
        "pop_exps": pop_exps,
    })

print(f"{'Idx':3s} | {'Feature Name':32s} | {'Min':10s} | {'Max':10s} | {'Mean':10s} | {'Std':10s} | {'Non0':4s} | {'Uniq':4s} | {'Exps'}")
print("-" * 115)
for s in stats_78:
    pop_str = ",".join(s["pop_exps"]) if s["pop_exps"] else "none"
    print(f"{s['idx']:3d} | {s['name']:32s} | {s['min']:10.2f} | {s['max']:10.2f} | {s['mean']:10.2f} | {s['std']:10.2f} | {s['non_zero']:4d} | {s['unique']:4d} | {pop_str}")
