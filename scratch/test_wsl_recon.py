import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

# Script to run entirely in WSL
wsl_script = """
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

# 1. Listeners on 8080, 9000
s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s1.bind(('127.0.0.1', 8080))
s1.listen(10)

s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s2.bind(('127.0.0.1', 9000))
s2.listen(10)

pcap_path = '/tmp/recon_wsl.pcap'
if os.path.exists(pcap_path):
    os.remove(pcap_path)

# 2. tcpdump
tcpdump_proc = subprocess.Popen(['tcpdump', '-i', 'lo', '-w', pcap_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
time.sleep(1.0)

# 3. Nmap scan
ports = '21,22,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5000,5432,5900,6379,7001,8000,8080,8443,8888,9000,9090,9200,27017,49152,49153,50000,60000'
nmap_res = subprocess.run(['nmap', '-sT', '-Pn', '-n', '-p', ports, '127.0.0.1'], capture_output=True, text=True)
print(nmap_res.stdout)

time.sleep(0.5)
tcpdump_proc.send_signal(signal.SIGINT)
try:
    tcpdump_proc.wait(timeout=5)
except Exception:
    tcpdump_proc.kill()

s1.close()
s2.close()

# 4. Zeek
subprocess.run('rm -rf /tmp/zeek_wsl_recon && mkdir -p /tmp/zeek_wsl_recon && cd /tmp/zeek_wsl_recon && /usr/local/bin/zeek -C -r /tmp/recon_wsl.pcap', shell=True, check=True)
"""

subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "python3", "-c", wsl_script], check=True)

# Copy logs to inspect
subprocess.run(["wsl", "-d", "Ubuntu", "cp", "-r", "/tmp/zeek_wsl_recon", "/mnt/c/Users/GOURAV GABA/Downloads/unidetectml/scratch/zeek_wsl_recon"], check=True)

sys.path.insert(0, '.')
from src.features.vector_assembler import extract_feature_matrix
from src.ingestion.zeek_reader import load_zeek_logs
from src.features.schema import FEATURE_INDICES

logs = load_zeek_logs("scratch/zeek_wsl_recon")
cols, matrix, flows = extract_feature_matrix(logs)
print(f"Extracted {len(flows)} flows from Nmap scan!")

ports = [f.destination.port for f in flows]
states = [f.connection_state for f in flows]
print(f"Distinct Ports Scanned: {len(set(ports))} / Total Flows: {len(flows)}")
print("Port State Breakdown:", {st: states.count(st) for st in set(states)})
print("Max Unique Dst Ports 60s in Window:", max(matrix[i][FEATURE_INDICES["win_src_unique_dst_ports_60s"]] for i in range(len(matrix))))
print("Dynamic Dst Port flags count (>0):", sum(1 for i in range(len(matrix)) if matrix[i][FEATURE_INDICES["is_dynamic_dst_port"]] == 1.0))
print("Well-known Dst Port flags count (>0):", sum(1 for i in range(len(matrix)) if matrix[i][FEATURE_INDICES["is_well_known_dst_port"]] == 1.0))
print("Registered Dst Port flags count (>0):", sum(1 for i in range(len(matrix)) if matrix[i][FEATURE_INDICES["is_registered_dst_port"]] == 1.0))
