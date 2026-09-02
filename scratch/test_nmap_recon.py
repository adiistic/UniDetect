import socket
import subprocess
import time
import sys
from pathlib import Path
sys.path.insert(0, '.')
from src.features.vector_assembler import extract_feature_matrix
from src.ingestion.zeek_reader import load_zeek_logs
from src.features.schema import FEATURE_INDICES

# 1. Start a local listener on 8080 and 9000 to have open ports
s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s1.bind(("127.0.0.1", 8080))
s1.listen(10)

s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s2.bind(("127.0.0.1", 9000))
s2.listen(10)

# 2. tcpdump inside WSL
wsl_pcap = "/tmp/recon_test.pcap"
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "rm", "-f", wsl_pcap], check=True)
tcpdump_proc = subprocess.Popen(
    ["wsl", "-d", "Ubuntu", "-u", "root", "tcpdump", "-i", "lo", "-w", wsl_pcap],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE
)
time.sleep(1.0)

# 3. Run nmap TCP Connect scan
ports_to_scan = "21,22,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5000,5432,5900,6379,7001,8000,8080,8443,8888,9000,9090,9200,27017,49152,49153,50000,60000"
cmd_nmap = ["wsl", "-d", "Ubuntu", "-u", "root", "nmap", "-sT", "-Pn", "-n", "-p", ports_to_scan, "127.0.0.1"]
nmap_res = subprocess.run(cmd_nmap, capture_output=True, text=True)
print("Nmap stdout:\n", nmap_res.stdout)

time.sleep(0.5)
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "pkill", "-2", "tcpdump"])
tcpdump_proc.terminate()
time.sleep(0.5)

s1.close()
s2.close()

# 4. Zeek
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "rm", "-rf", "/tmp/zeek_test_recon"], check=True)
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "mkdir", "-p", "/tmp/zeek_test_recon"], check=True)
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "/bin/bash", "-c", f"cd /tmp/zeek_test_recon && /usr/local/bin/zeek -C -r {wsl_pcap}"], check=True)

# Copy to inspect
subprocess.run(["wsl", "-d", "Ubuntu", "cp", "-r", "/tmp/zeek_test_recon", "/mnt/c/Users/GOURAV GABA/Downloads/unidetectml/scratch/zeek_test_recon"], check=True)

logs = load_zeek_logs("scratch/zeek_test_recon")
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
