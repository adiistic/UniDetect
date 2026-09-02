import json
import math
from pathlib import Path

experiments = [
    {
        "id": "exp_benign_iperf_001",
        "dir": Path("data/experiments/BENIGN/exp_benign_iperf_001"),
        "label": "BENIGN",
        "label_id": 0,
        "is_candidate": False,
        "exclusion_reason": "Severe WSL2 loopback capture loss (69.61 GB missed bytes from ~60 Gbps in-memory transfer exceeding disk write speed) and artificial sequence-gap weirds (TCP_seq_underflow_or_misorder)."
    },
    {
        "id": "exp_benign_iperf_002",
        "dir": Path("data/experiments/BENIGN/exp_benign_iperf_002"),
        "label": "BENIGN",
        "label_id": 0,
        "is_candidate": True,
        "exclusion_reason": None
    },
    {
        "id": "exp_benign_multi_003",
        "dir": Path("data/experiments/BENIGN/exp_benign_multi_003"),
        "label": "BENIGN",
        "label_id": 0,
        "is_candidate": True,
        "exclusion_reason": None
    },
    {
        "id": "exp_benign_dns_004",
        "dir": Path("data/experiments/BENIGN/exp_benign_dns_004"),
        "label": "BENIGN",
        "label_id": 0,
        "is_candidate": True,
        "exclusion_reason": None
    },
    {
        "id": "exp_ddos_syn_001",
        "dir": Path("data/experiments/DDOS/exp_ddos_syn_001"),
        "label": "DDOS",
        "label_id": 1,
        "is_candidate": True,
        "exclusion_reason": None
    },
]

print("=" * 100)
print("AUTHORITATIVE RECONCILIATION INVENTORY")
print("=" * 100)

benign_candidate_count = 0
ddos_candidate_count = 0

for exp in experiments:
    exp_dir = exp["dir"]
    pcap_path = exp_dir / "pcap" / "capture.pcap"
    zeek_dir = exp_dir / "zeek"
    feat_path = exp_dir / "features" / "features.jsonl"
    meta_path = exp_dir / "metadata.json"
    audit_path = exp_dir / "AUDIT.md"
    
    # Check artifact preservation
    artifacts = {
        "pcap": pcap_path.exists(),
        "zeek_logs": zeek_dir.exists() and len(list(zeek_dir.glob("*.log"))) > 0,
        "features": feat_path.exists(),
        "metadata": meta_path.exists(),
        "audit_md": audit_path.exists(),
    }
    
    meta = json.load(open(meta_path)) if meta_path.exists() else {}
    recs = [json.loads(line) for line in open(feat_path)] if feat_path.exists() else []
    
    pcap_size = pcap_path.stat().st_size if pcap_path.exists() else 0
    zeek_files = sorted([f.name for f in zeek_dir.glob("*.log")]) if zeek_dir.exists() else []
    
    # Feature quality audit
    nan_count = 0
    inf_count = 0
    missing_count = 0
    dim_set = set()
    total_missed_bytes = 0.0
    
    for r in recs:
        vec = r["features"]
        dim_set.add(len(vec))
        if len(vec) != 78:
            missing_count += abs(78 - len(vec))
        for v in vec:
            if math.isnan(v): nan_count += 1
            if math.isinf(v): inf_count += 1
        total_missed_bytes += vec[11]  # missed_bytes index
        
    weird_events = meta.get("weird_events", [])
    
    if exp["is_candidate"]:
        if exp["label"] == "BENIGN":
            benign_candidate_count += len(recs)
        elif exp["label"] == "DDOS":
            ddos_candidate_count += len(recs)
            
    status_str = "CANDIDATE ML DATA" if exp["is_candidate"] else "EXCLUDED FROM ML"
    
    print(f"\nExperiment ID:         {exp['id']}")
    print(f"Status:                {status_str}")
    if exp["exclusion_reason"]:
        print(f"Exclusion Reason:      {exp['exclusion_reason']}")
    print(f"Label:                 {exp['label']} (label_id = {exp['label_id']})")
    print(f"Traffic Generator:     {meta.get('traffic_generator', 'N/A')}")
    print(f"PCAP Path & Size:      {pcap_path} ({pcap_size:,} bytes)")
    print(f"Captured Packets:      {meta.get('capture_packet_count', 'N/A'):,} packets")
    print(f"Zeek Logs:             {zeek_files}")
    print(f"Flow Count:            {len(recs)} flows")
    print(f"Feature Vector Count:  {len(recs)} vectors")
    print(f"Dimensionality:        {list(dim_set)} (Expected: [78])")
    print(f"Missed Bytes:          {total_missed_bytes:,.0f} bytes")
    print(f"Weird Events:          {weird_events}")
    print(f"NaN / Inf / Missing:   NaN={nan_count}, Inf={inf_count}, Missing={missing_count}")
    print(f"Artifacts Preserved:   pcap={artifacts['pcap']}, zeek={artifacts['zeek_logs']}, features={artifacts['features']}, metadata={artifacts['metadata']}, AUDIT.md={artifacts['audit_md']}")

print("\n" + "=" * 100)
print("AUTHORITATIVE ML CANDIDATE TOTALS")
print("=" * 100)
print(f"BENIGN candidate vectors (Exps 002 + 003 + 004): {benign_candidate_count}")
print(f"DDOS candidate vectors   (Exp 001):              {ddos_candidate_count}")
print(f"TOTAL candidate vectors:                         {benign_candidate_count + ddos_candidate_count}")
print("=" * 100)
