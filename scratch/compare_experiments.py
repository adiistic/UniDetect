import json
import sys
sys.path.insert(0, '.')
from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES

recs1 = [json.loads(line) for line in open('data/experiments/BENIGN/exp_benign_iperf_001/features/features.jsonl')]
recs2 = [json.loads(line) for line in open('data/experiments/BENIGN/exp_benign_iperf_002/features/features.jsonl')]

meta1 = json.load(open('data/experiments/BENIGN/exp_benign_iperf_001/metadata.json'))
meta2 = json.load(open('data/experiments/BENIGN/exp_benign_iperf_002/metadata.json'))

print("=== EXPERIMENT 001 vs EXPERIMENT 002 COMPARISON ===")
print(f"Attribute                 | Exp 001 (Unthrottled ~60Gbps) | Exp 002 (Rate-Limited 50Mbps)")
print(f"--------------------------|-------------------------------|---------------------------------")
print(f"Duration                  | {meta1['duration_seconds']}s                         | {meta2['duration_seconds']}s")
print(f"Captured Packets          | {meta1['capture_packet_count']:,} packets                | {meta2['capture_packet_count']:,} packets")
print(f"PCAP File Size            | {meta1['capture_size_bytes']:,} B (~225 MB)     | {meta2['capture_size_bytes']:,} B (~74.6 MB)")
print(f"Total Flows               | {meta1['total_flows']} flows                        | {meta2['total_flows']} flows")
print(f"Total Missed Bytes        | 69,611,823,435 B (~69.6 GB)   | {meta2['total_missed_bytes']:,} B (0.0 B)")
print(f"Weird Events              | ['TCP_seq_underflow...']      | {meta2['weird_events']}")

print("\n=== EXP 002 FLOW RECORDS ===")
for i, r in enumerate(recs2):
    vec = r['features']
    dur = vec[FEATURE_INDICES['flow_duration']]
    ob = vec[FEATURE_INDICES['orig_bytes']]
    rb = vec[FEATURE_INDICES['resp_bytes']]
    mb = vec[FEATURE_INDICES['missed_bytes']]
    asym = vec[FEATURE_INDICES['bytes_asymmetry_ratio']]
    bpp = vec[FEATURE_INDICES['bytes_per_packet']]
    print(f"Flow {i+1} [{r['protocol']:3s} {r['connection_state']:2s}] {r['source_endpoint']:21s} -> {r['destination_endpoint']:14s} | dur={dur:4.2f}s | orig={ob:>10,.0f} B | resp={rb:>10,.0f} B | asym={asym:>6.3f} | B/pkt={bpp:>8,.1f} B | missed={mb}")
