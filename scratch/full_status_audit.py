import json
from pathlib import Path

base = Path('data/experiments')
print(f"{'CLASS':<15} | {'EXPERIMENT ID':<25} | {'VECTORS':>8} | {'PCAP SIZE':>12} | {'ZEEK LOGS'}")
print('-' * 95)
total_v = 0
category_counts = {}

for cat_dir in sorted(base.iterdir()):
    if not cat_dir.is_dir():
        continue
    for exp_dir in sorted(cat_dir.iterdir()):
        if not exp_dir.is_dir():
            continue
        feat_p = exp_dir / 'features' / 'features.jsonl'
        pcap_p = exp_dir / 'pcap' / 'capture.pcap'
        zeek_d = exp_dir / 'zeek'
        meta_p = exp_dir / 'metadata.json'
        
        vecs = len(list(open(feat_p, 'r', encoding='utf-8'))) if feat_p.exists() else 0
        total_v += vecs
        category_counts[cat_dir.name] = category_counts.get(cat_dir.name, 0) + vecs
        
        pcap_sz = f"{pcap_p.stat().st_size:,} B" if pcap_p.exists() else "None"
        z_logs = ', '.join(sorted([f.name for f in zeek_d.glob('*.log')])) if zeek_d.exists() else "None"
        print(f"{cat_dir.name:<15} | {exp_dir.name:<25} | {vecs:>8d} | {pcap_sz:>12} | {z_logs}")

print('-' * 95)
print(f"TOTAL VECTORS: {total_v}")
print(f"CLASS COUNTS: {category_counts}")
