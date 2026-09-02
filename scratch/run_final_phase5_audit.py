import json
import math
import sys
from pathlib import Path
from collections import defaultdict, Counter

REPO_ROOT = Path('.')
sys.path.insert(0, str(REPO_ROOT))

from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES, NUM_FEATURES, THREAT_CLASSES

base_dir = Path("data/experiments")

retained_exp_ids = {
    "BENIGN": [
        "exp_benign_iperf_002",
        "exp_benign_multi_003",
        "exp_benign_dns_004",
        "exp_benign_tls_005",
        "exp_benign_mixed_006",
        "exp_benign_periodic_007",
    ],
    "DDOS": [
        "exp_ddos_syn_001",
        "exp_ddos_udp_002",
    ],
    "RECON": [
        "exp_recon_001",
    ],
    "SLOW_HTTP": [
        "exp_slow_http_001",
    ],
    "DNS_TUNNEL": [
        "exp_dns_tunnel_001",
    ],
    "C2_BEACON": [
        "exp_c2_beacon_001",
    ],
}

flat_retained = {eid: cat for cat, eids in retained_exp_ids.items() for eid in eids}

print("=== STARTING FINAL PHASE 5 DATASET AUDIT ===")

all_experiments_found = []
retained_records = []
excluded_records = []

# Scan all folders under data/experiments
for cat_dir in sorted(base_dir.iterdir()):
    if not cat_dir.is_dir(): continue
    for exp_dir in sorted(cat_dir.iterdir()):
        if not exp_dir.is_dir(): continue
        
        eid = exp_dir.name
        is_retained = (eid in flat_retained)
        
        # Check files
        feat_p = exp_dir / "features" / "features.jsonl"
        legacy_feat_p = exp_dir / "features.jsonl"
        active_feat_p = feat_p if feat_p.exists() else (legacy_feat_p if legacy_feat_p.exists() else None)
        
        pcap_p = exp_dir / "pcap" / "capture.pcap"
        meta_p = exp_dir / "metadata.json"
        audit_p = exp_dir / "AUDIT.md"
        
        zeek_d = exp_dir / "zeek"
        legacy_zeek_d = exp_dir / "zeek_logs"
        active_zeek_d = zeek_d if zeek_d.exists() else (legacy_zeek_d if legacy_zeek_d.exists() else None)
        
        zeek_logs = sorted([f.name for f in active_zeek_d.glob("*.log")]) if active_zeek_d else []
        
        pcap_size = pcap_p.stat().st_size if pcap_p.exists() else 0
        meta = json.load(open(meta_p, "r", encoding="utf-8")) if meta_p.exists() else {}
        
        raw_lines = open(active_feat_p, "r", encoding="utf-8").readlines() if active_feat_p else []
        recs = [json.loads(line) for line in raw_lines]
        
        exp_info = {
            "category": cat_dir.name,
            "experiment_id": eid,
            "dir": str(exp_dir),
            "is_retained": is_retained,
            "vector_count": len(recs),
            "pcap_exists": pcap_p.exists(),
            "pcap_size": pcap_size,
            "packet_count": meta.get("capture_packet_count", len(recs)),
            "zeek_logs": zeek_logs,
            "meta_exists": meta_p.exists(),
            "audit_exists": audit_p.exists(),
            "generator": meta.get("traffic_generator", "N/A"),
            "weird_events": meta.get("weird_events", []),
            "metadata": meta,
            "records": recs,
        }
        
        all_experiments_found.append(exp_info)
        if is_retained:
            retained_records.append(exp_info)
        else:
            excluded_records.append(exp_info)

print(f"Total Experiment Directories Scanned: {len(all_experiments_found)}")
print(f"Retained Experiments: {len(retained_records)}")
print(f"Excluded Experiments: {len(excluded_records)}")

# 1. Check Retained Vectors Integrity
total_retained_vectors = 0
dim_issues = []
nan_issues = []
inf_issues = []
non_numeric_issues = []
label_mismatches = []
missed_bytes_by_exp = {}
feature_pop_counts = [0] * 78
all_feature_vectors = []
all_vector_hashes = Counter()
duplicate_rows_by_exp = defaultdict(int)

for exp in retained_records:
    eid = exp["experiment_id"]
    exp_class = exp["category"]
    expected_label_id = THREAT_CLASSES.index(exp_class)
    
    exp_missed_bytes = 0.0
    exp_vec_hashes = Counter()
    
    for i, r in enumerate(exp["records"]):
        total_retained_vectors += 1
        vec = r.get("features", [])
        
        # Check Dimension
        if len(vec) != 78:
            dim_issues.append((eid, i, len(vec)))
            
        # Check NaNs, Infs, Types
        for j, val in enumerate(vec):
            if not isinstance(val, (int, float)):
                non_numeric_issues.append((eid, i, j, type(val)))
            elif math.isnan(val):
                nan_issues.append((eid, i, j))
            elif math.isinf(val):
                inf_issues.append((eid, i, j))
            
            # Check population (non-zero / non-default)
            if val != 0.0:
                feature_pop_counts[j] += 1
                
        # Check Label Integrity
        lbl = r.get("label")
        lbl_id = r.get("label_id")
        if lbl != exp_class or lbl_id != expected_label_id:
            label_mismatches.append((eid, i, lbl, lbl_id, exp_class, expected_label_id))
            
        # Missed bytes
        if len(vec) > FEATURE_INDICES["missed_bytes"]:
            mb = vec[FEATURE_INDICES["missed_bytes"]]
            exp_missed_bytes += mb
            
        # Duplicate detection (tuple of features rounded to 4 decimals)
        vec_tuple = tuple(round(v, 4) for v in vec)
        all_vector_hashes[vec_tuple] += 1
        exp_vec_hashes[vec_tuple] += 1
        all_feature_vectors.append((eid, exp_class, vec))
        
    missed_bytes_by_exp[eid] = exp_missed_bytes
    
    # Check intra-experiment duplicates
    for h, c in exp_vec_hashes.items():
        if c > 1:
            duplicate_rows_by_exp[eid] += (c - 1)

print("\n--- VECTOR & LABEL INTEGRITY AUDIT ---")
print(f"Total Retained Vectors: {total_retained_vectors}")
print(f"Dimension Issues: {len(dim_issues)}")
print(f"NaN Issues: {len(nan_issues)}")
print(f"Inf Issues: {len(inf_issues)}")
print(f"Non-numeric Issues: {len(non_numeric_issues)}")
print(f"Label Mismatches: {len(label_mismatches)}")
print(f"Duplicate Vector Clusters (Identical 78D vectors): {sum(1 for c in all_vector_hashes.values() if c > 1)}")
print(f"Total Duplicate Rows Across Corpus: {sum(c - 1 for c in all_vector_hashes.values() if c > 1)}")
print(f"Duplicate Rows by Experiment: {dict(duplicate_rows_by_exp)}")

# 2. Class Distribution
class_counts = Counter()
exp_counts_per_class = Counter()
for exp in retained_records:
    cls = exp["category"]
    cnt = exp["vector_count"]
    class_counts[cls] += cnt
    exp_counts_per_class[cls] += 1

print("\n--- CLASS DISTRIBUTION (RETAINED) ---")
for cls, cnt in class_counts.most_common():
    pct = (cnt / total_retained_vectors) * 100
    print(f"  {cls:<15}: {cnt:4d} vectors ({pct:6.2f}%) | {exp_counts_per_class[cls]} experiment(s)")

# 3. Experiment Balance
print("\n--- EXPERIMENT BALANCE ---")
for exp in retained_records:
    eid = exp["experiment_id"]
    cls = exp["category"]
    cnt = exp["vector_count"]
    cls_total = class_counts[cls]
    pct_of_class = (cnt / cls_total) * 100 if cls_total > 0 else 0
    print(f"  [{cls:<12}] {eid:<25}: {cnt:4d} vectors ({pct_of_class:6.2f}% of {cls})")

# 4. Feature Subspace Coverage Analysis
print("\n--- FEATURE SUBSPACE COVERAGE ---")
subspaces = {
    "Flow Features (0-26)": (0, 26),
    "DNS Features (27-39)": (27, 39),
    "QUIC Features (40-43)": (40, 43),
    "Weird Anomaly Features (44-48)": (44, 48),
    "TLS/SSL Features (49-55)": (49, 55),
    "Source Window (56-67)": (56, 67),
    "Dest Window (68-71)": (68, 71),
    "Host-Pair Window (72-77)": (72, 77),
}

for name, (start, end) in subspaces.items():
    active_in_any = False
    active_exps = set()
    for exp in retained_records:
        for r in exp["records"]:
            vec = r["features"]
            if any(vec[k] != 0.0 for k in range(start, end + 1)):
                active_exps.add(exp["experiment_id"])
    print(f"  {name:<32}: Active in {len(active_exps)}/12 experiments -> {sorted(list(active_exps)) if len(active_exps) < 5 else f'{len(active_exps)} experiments'}")

# 5. Temporal Causal Window Validation
print("\n--- TEMPORAL CAUSALITY VALIDATION ---")
causality_violations = []
for exp in retained_records:
    timestamps = [r["timestamp"] for r in exp["records"]]
    # Check monotonicity or chronological sequencing
    is_sorted = all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1))
    # Check if window aggregator logic is backward-looking (t_window in [t - Horizon, t])
    # The WindowAggregator in window_aggregator.py computes filters: (t - Lookback) <= f.timestamp <= t
    print(f"  {exp['experiment_id']:<25}: {len(timestamps)} flows | Timestamps Monotonic: {is_sorted} | Time Span: {min(timestamps):.2f}s to {max(timestamps):.2f}s (Duration: {max(timestamps)-min(timestamps):.2f}s)")

# 6. Shortcut and Data Leakage Audit
print("\n--- SHORTCUT AND DATA LEAKAGE AUDIT ---")
# Check ports, private IP flags, fixed protocol assignments
port_to_classes = defaultdict(set)
ip_flags = defaultdict(set)
for exp in retained_records:
    cls = exp["category"]
    for r in exp["records"]:
        dst_p = r["destination_endpoint"].split(":")[-1]
        port_to_classes[dst_p].add(cls)
        vec = r["features"]
        src_priv = vec[FEATURE_INDICES["is_src_private_ip"]]
        dst_priv = vec[FEATURE_INDICES["is_dst_private_ip"]]
        ip_flags[(src_priv, dst_priv)].add(cls)

print("Port to Class mapping:")
for p, cls_set in sorted(port_to_classes.items()):
    print(f"  Port {p:>5}: {sorted(list(cls_set))}")

print("IP Flag combinations observed:")
for k, cls_set in ip_flags.items():
    print(f"  (src_priv={k[0]}, dst_priv={k[1]}): {sorted(list(cls_set))}")

print("\n=== AUDIT SCRIPT COMPLETED SUCCESSFULLY ===")
