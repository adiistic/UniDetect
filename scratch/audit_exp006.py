import json
import math
import sys
from pathlib import Path

REPO_ROOT = Path('.')
sys.path.insert(0, str(REPO_ROOT))

from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

feat_file = Path("data/experiments/BENIGN/exp_benign_mixed_006/features/features.jsonl")
meta_file = Path("data/experiments/BENIGN/exp_benign_mixed_006/metadata.json")
pcap_file = Path("data/experiments/BENIGN/exp_benign_mixed_006/pcap/capture.pcap")

recs = [json.loads(line) for line in open(feat_file, "r", encoding="utf-8")]
meta = json.load(open(meta_file, "r", encoding="utf-8"))

print("=" * 80)
print(f"AUDIT FOR EXPERIMENT 006: {len(recs)} FLOWS")
print("=" * 80)

# Dimensionality and numerical validity
nan_c = 0
inf_c = 0
missing_c = 0
dim_c = []
missed_bytes_total = 0.0

for i, r in enumerate(recs):
    vec = r["features"]
    dim_c.append(len(vec))
    if len(vec) != 78:
        missing_c += abs(78 - len(vec))
    for v in vec:
        if math.isnan(v): nan_c += 1
        if math.isinf(v): inf_c += 1
    missed_bytes_total += vec[FEATURE_INDICES["missed_bytes"]]

print(f"Total Vectors: {len(recs)}")
print(f"Dimensionality Set: {set(dim_c)} (Expected: {{78}})")
print(f"NaN Count: {nan_c}")
print(f"Inf Count: {inf_c}")
print(f"Missing Values: {missing_c}")
print(f"Total Missed Bytes: {missed_bytes_total}")

# Protocol and Port breakdown
protos = {}
ports = {}
durations = []
orig_bytes = []
resp_bytes = []
ssl_active = 0
dns_active = 0

for r in recs:
    vec = r["features"]
    proto = "TCP" if vec[FEATURE_INDICES["proto_is_tcp"]] == 1.0 else ("UDP" if vec[FEATURE_INDICES["proto_is_udp"]] == 1.0 else "OTHER")
    protos[proto] = protos.get(proto, 0) + 1
    
    p = r["destination_endpoint"].split(":")[-1]
    ports[p] = ports.get(p, 0) + 1
    
    dur = vec[FEATURE_INDICES["flow_duration"]]
    durations.append(dur)
    orig_bytes.append(vec[FEATURE_INDICES["orig_bytes"]])
    resp_bytes.append(vec[FEATURE_INDICES["resp_bytes"]])
    
    if vec[FEATURE_INDICES["has_ssl_context"]] == 1.0:
        ssl_active += 1
    if vec[FEATURE_INDICES["has_dns_context"]] == 1.0:
        dns_active += 1

print(f"Protocols: {protos}")
print(f"Destination Ports: {ports}")
print(f"Duration Min/Max/Mean: {min(durations):.4f}s / {max(durations):.4f}s / {sum(durations)/len(durations):.4f}s")
print(f"Orig Bytes Min/Max: {min(orig_bytes):,.0f} B / {max(orig_bytes):,.0f} B")
print(f"Resp Bytes Min/Max: {min(resp_bytes):,.0f} B / {max(resp_bytes):,.0f} B")
print(f"TLS Active Flows: {ssl_active} / {len(recs)}")
print(f"DNS Active Flows: {dns_active} / {len(recs)}")
print(f"PCAP Size: {pcap_file.stat().st_size:,} bytes")
print(f"Weird Events in metadata: {meta.get('weird_events', [])}")
print("=" * 80)
