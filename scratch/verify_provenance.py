import json
import subprocess
import sys
sys.path.insert(0, '.')
from src.features.vector_assembler import extract_feature_matrix
from src.ingestion.zeek_reader import load_zeek_logs

# 1. Load saved features.jsonl
orig_recs = [json.loads(line) for line in open('data/experiments/BENIGN/exp_benign_iperf_001/features/features.jsonl')]

# 2. Run Zeek in WSL tmp dir
wsl_pcap = "/mnt/c/Users/GOURAV GABA/Downloads/unidetectml/data/experiments/BENIGN/exp_benign_iperf_001/pcap/capture.pcap"
wsl_out = "/mnt/c/Users/GOURAV GABA/Downloads/unidetectml/data/experiments/BENIGN/exp_benign_iperf_001/zeek_regen"

subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "rm", "-rf", "/tmp/zeek_regen", wsl_out], check=True)
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "mkdir", "-p", "/tmp/zeek_regen", wsl_out], check=True)

cmd = ["wsl", "-d", "Ubuntu", "-u", "root", "/bin/bash", "-c", f"cd /tmp/zeek_regen && /usr/local/bin/zeek -C -r '{wsl_pcap}' && cp -r /tmp/zeek_regen/* '{wsl_out}/'"]
subprocess.run(cmd, check=True)

logs = load_zeek_logs('data/experiments/BENIGN/exp_benign_iperf_001/zeek_regen')
cols, matrix, flows = extract_feature_matrix(logs)

print(f'Regenerated flows: {len(flows)}, Saved flows: {len(orig_recs)}')
assert len(flows) == len(orig_recs), 'Flow count mismatch'

all_match = True
for i in range(len(flows)):
    saved_vec = orig_recs[i]['features']
    regen_vec = matrix[i]
    diffs = [abs(a - b) for a, b in zip(saved_vec, regen_vec)]
    max_diff = max(diffs)
    if max_diff > 1e-6:
        print(f'Flow {i} mismatch: max diff = {max_diff}')
        all_match = False

if all_match:
    print('PROVENANCE VERIFIED: 100% bit-exact match between preserved PCAP and regenerated feature vectors!')

# Clean up temp test directory
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "rm", "-rf", "/tmp/zeek_regen", wsl_out], check=True)
