import socket
import subprocess
import time
import tempfile
import sys
sys.path.insert(0, '.')
from src.features.vector_assembler import extract_feature_matrix
from src.ingestion.zeek_reader import load_zeek_logs

# 1. Start listener on 9090
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 9090))
s.listen(50)

# 2. Capture with tcpdump
pcap_path = "/tmp/test_syn.pcap"
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "rm", "-f", pcap_path], check=True)
tcpdump_proc = subprocess.Popen(
    ["wsl", "-d", "Ubuntu", "-u", "root", "tcpdump", "-i", "lo", "-w", pcap_path, "port 9090 or port 9091"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE
)
time.sleep(1.0)

# 3. Send hping3 SYN flood against open port (9090) and closed port (9091)
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "hping3", "-S", "-p", "9090", "-c", "25", "-i", "u10000", "127.0.0.1"], check=True)
time.sleep(0.2)
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "hping3", "-S", "-p", "9091", "-c", "25", "-i", "u10000", "127.0.0.1"], check=True)
time.sleep(0.5)

# 4. Stop capture and listener
tcpdump_proc.terminate()
tcpdump_proc.wait(timeout=3)
s.close()

# 5. Run Zeek
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "rm", "-rf", "/tmp/zeek_test_ddos"], check=True)
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "mkdir", "-p", "/tmp/zeek_test_ddos"], check=True)
subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "/bin/bash", "-c", f"cd /tmp/zeek_test_ddos && /usr/local/bin/zeek -C -r {pcap_path}"], check=True)

# Copy to inspect
subprocess.run(["wsl", "-d", "Ubuntu", "cp", "-r", "/tmp/zeek_test_ddos", "/mnt/c/Users/GOURAV GABA/Downloads/unidetectml/scratch/zeek_test_ddos"], check=True)

logs = load_zeek_logs("scratch/zeek_test_ddos")
cols, matrix, flows = extract_feature_matrix(logs)
print(f"Extracted {len(flows)} flows from SYN flood test!")
states = [f.connection_state for f in flows]
print("Connection states distribution:", {st: states.count(st) for st in set(states)})
for i in range(min(5, len(flows))):
    print(f"Flow {i+1}: uid={flows[i].uid}, state={flows[i].connection_state}, history={flows[i].history}")
