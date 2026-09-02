import json
from pathlib import Path

retained = [
    'data/experiments/BENIGN/exp_benign_iperf_002',
    'data/experiments/BENIGN/exp_benign_multi_003',
    'data/experiments/BENIGN/exp_benign_dns_004',
    'data/experiments/BENIGN/exp_benign_tls_005',
    'data/experiments/BENIGN/exp_benign_mixed_006',
    'data/experiments/BENIGN/exp_benign_periodic_007',
    'data/experiments/DDOS/exp_ddos_syn_001',
    'data/experiments/DDOS/exp_ddos_udp_002',
    'data/experiments/RECON/exp_recon_001',
    'data/experiments/SLOW_HTTP/exp_slow_http_001',
    'data/experiments/DNS_TUNNEL/exp_dns_tunnel_001',
    'data/experiments/C2_BEACON/exp_c2_beacon_001',
]

print(f"{'EXP ID':<26} | {'VECS':>4} | {'PCAP BYTES':>12} | {'PACKETS':>8} | {'MISSED B':>8} | {'WEIRDS':>6}")
print('-' * 76)
tot_v, tot_b, tot_p = 0, 0, 0
for p in retained:
    p_path = Path(p)
    meta = json.load(open(p_path / 'metadata.json', 'r', encoding='utf-8'))
    feats = [json.loads(l) for l in open(p_path / 'features' / 'features.jsonl', 'r', encoding='utf-8')]
    pcap_sz = (p_path / 'pcap' / 'capture.pcap').stat().st_size
    tot_v += len(feats)
    tot_b += pcap_sz
    pkts = meta.get('capture_packet_count', 0)
    tot_p += pkts
    print(f"{p_path.name:<26} | {len(feats):>4d} | {pcap_sz:>12,d} | {pkts:>8,d} | {meta.get('total_missed_bytes', 0.0):>8.1f} | {len(meta.get('weird_events', [])):>6d}")

print('-' * 76)
print(f"{'TOTALS':<26} | {tot_v:>4d} | {tot_b:>12,d} | {tot_p:>8,d} |")
