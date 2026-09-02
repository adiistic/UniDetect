import subprocess
import time
import sys
from pathlib import Path
sys.path.insert(0, '.')
from src.features.vector_assembler import extract_feature_matrix
from src.ingestion.zeek_reader import load_zeek_logs
from src.features.schema import FEATURE_INDICES

wsl_script = """
import http.server
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request

class SimpleHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status": "ok", "app": "unidetect_local_target"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, format, *args): pass

httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 8080), SimpleHTTPHandler)
httpd.timeout = 0.5

stop_server = threading.Event()
def serve():
    while not stop_server.is_set():
        httpd.handle_request()
    httpd.server_close()

t = threading.Thread(target=serve, daemon=True)
t.start()
time.sleep(0.5)

# Verify normal HTTP request
try:
    with urllib.request.urlopen("http://127.0.0.1:8080/") as resp:
        print("Pre-test verification response:", resp.read().decode('utf-8'))
except Exception as e:
    print("Verification failed:", e)

pcap = '/tmp/test_slow.pcap'
if os.path.exists(pcap): os.remove(pcap)

tcpdump_proc = subprocess.Popen(['tcpdump', '-i', 'lo', '-U', '-w', pcap, 'port 8080'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
time.sleep(1.0)

# Run slowloris with 25 sockets, sleeptime 1s for 4 seconds
slow_proc = subprocess.Popen(['slowloris', '127.0.0.1', '-p', '8080', '-s', '25', '--sleeptime', '1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
time.sleep(4.0)

slow_proc.send_signal(signal.SIGINT)
try: slow_proc.wait(timeout=3)
except: slow_proc.kill()

time.sleep(0.5)
tcpdump_proc.send_signal(signal.SIGINT)
try: tcpdump_proc.wait(timeout=3)
except: tcpdump_proc.kill()

stop_server.set()
t.join(timeout=1.0)

subprocess.run('rm -rf /tmp/zeek_slow_test && mkdir -p /tmp/zeek_slow_test && cd /tmp/zeek_slow_test && /usr/local/bin/zeek -C -r /tmp/test_slow.pcap', shell=True, check=True)
"""

subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "python3", "-c", wsl_script], check=True)
subprocess.run(["wsl", "-d", "Ubuntu", "cp", "-r", "/tmp/zeek_slow_test", "/mnt/c/Users/GOURAV GABA/Downloads/unidetectml/scratch/zeek_slow_test"], check=True)

logs = load_zeek_logs("scratch/zeek_slow_test")
cols, matrix, flows = extract_feature_matrix(logs)
print(f"Extracted {len(flows)} flows from Slowloris test!")

for i in range(min(5, len(flows))):
    vec = matrix[i]
    f = flows[i]
    dur = vec[FEATURE_INDICES['flow_duration']]
    ob = vec[FEATURE_INDICES['orig_bytes']]
    rb = vec[FEATURE_INDICES['resp_bytes']]
    pkts = vec[FEATURE_INDICES['total_packets']]
    st = f.connection_state
    print(f"Flow {i+1} [{f.network.protocol} {st}] {f.source.ip}:{f.source.port} -> {f.destination.ip}:{f.destination.port} | dur={dur:.4f}s | orig_b={ob:.0f} B | resp_b={rb:.0f} B | pkts={pkts} | tcp={vec[FEATURE_INDICES['proto_is_tcp']]}")
