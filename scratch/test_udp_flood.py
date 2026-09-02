import subprocess
import time
import sys
sys.path.insert(0, '.')
from src.features.vector_assembler import extract_feature_matrix
from src.ingestion.zeek_reader import load_zeek_logs
from src.features.schema import FEATURE_INDICES

wsl_script = """
import os, subprocess, time, signal

pcap = '/tmp/test_udp.pcap'
if os.path.exists(pcap): os.remove(pcap)

tcpdump_proc = subprocess.Popen(['tcpdump', '-i', 'lo', '-U', '-w', pcap, 'udp or icmp'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
time.sleep(1.0)

# Send 50 UDP packets (256 bytes payload) to 127.0.0.1:9999 at 100 pkts/s
subprocess.run(['hping3', '--udp', '-p', '9999', '-c', '50', '-i', 'u10000', '-d', '256', '127.0.0.1'], capture_output=True)

time.sleep(0.5)
tcpdump_proc.send_signal(signal.SIGINT)
try: tcpdump_proc.wait(timeout=3)
except: tcpdump_proc.kill()

subprocess.run('rm -rf /tmp/zeek_udp_test && mkdir -p /tmp/zeek_udp_test && cd /tmp/zeek_udp_test && /usr/local/bin/zeek -C -r /tmp/test_udp.pcap', shell=True, check=True)
"""

subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "python3", "-c", wsl_script], check=True)
subprocess.run(["wsl", "-d", "Ubuntu", "cp", "-r", "/tmp/zeek_udp_test", "/mnt/c/Users/GOURAV GABA/Downloads/unidetectml/scratch/zeek_udp_test"], check=True)

logs = load_zeek_logs("scratch/zeek_udp_test")
cols, matrix, flows = extract_feature_matrix(logs)
print(f"Extracted {len(flows)} flows from UDP flood test!")

for i in range(min(5, len(flows))):
    vec = matrix[i]
    f = flows[i]
    print(f"Flow {i+1} [{f.network.protocol} {f.connection_state}] {f.source.ip}:{f.source.port} -> {f.destination.ip}:{f.destination.port} | orig_b={vec[FEATURE_INDICES['orig_bytes']]:.0f} B | pkts={vec[FEATURE_INDICES['total_packets']]} | asym={vec[FEATURE_INDICES['bytes_asymmetry_ratio']]:.3f} | proto_udp={vec[FEATURE_INDICES['proto_is_udp']]}")
