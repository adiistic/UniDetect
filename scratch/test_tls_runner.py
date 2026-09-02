import json
import os
import ssl
import socket
import subprocess
import threading
import time
import sys
sys.path.insert(0, '.')
from src.features.vector_assembler import extract_feature_matrix
from src.ingestion.zeek_reader import load_zeek_logs
from src.features.schema import FEATURE_INDICES

# Run test in WSL
test_script = """
import ssl
import socket
import http.server
import threading
import time
import subprocess

# 1. Generate cert
subprocess.run("mkdir -p /tmp/tls_test && cd /tmp/tls_test && openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=portal.secure.internal.local/O=UniDetect Enterprise/C=IN'", shell=True, check=True)

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status": "secure_authenticated_ok"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, format, *args): pass

server = http.server.ThreadingHTTPServer(('127.0.0.1', 443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/tls_test/cert.pem', '/tmp/tls_test/key.pem')
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.timeout = 0.5

stop_server = threading.Event()
def serve():
    while not stop_server.is_set():
        server.handle_request()
    server.server_close()

t = threading.Thread(target=serve, daemon=True)
t.start()
time.sleep(0.5)

# 2. tcpdump
pcap_path = '/tmp/tls_test/capture.pcap'
tcpdump_proc = subprocess.Popen(['tcpdump', '-i', 'lo', '-w', pcap_path, 'port 443'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
time.sleep(1.0)

# 3. Client requests with diverse SNIs
snis = [
    'portal.secure.internal.local',
    'auth-service.cloud.network.local',
    'metrics.telemetry.infra.internal.local',
    'api.gateway.prod.corp.local',
    'vault.security.admin.local'
]

client_ctx = ssl.create_default_context()
client_ctx.check_hostname = False
client_ctx.verify_mode = ssl.CERT_NONE

for sni in snis:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 443))
    ss = client_ctx.wrap_socket(s, server_hostname=sni)
    ss.sendall(f'GET /api/v1/status HTTP/1.1\\r\\nHost: {sni}\\r\\nConnection: close\\r\\n\\r\\n'.encode('utf-8'))
    resp = ss.recv(4096)
    ss.close()
    time.sleep(0.1)

time.sleep(0.5)
tcpdump_proc.terminate()
tcpdump_proc.wait(timeout=3)
stop_server.set()
t.join(timeout=1.0)

# 4. Zeek
subprocess.run('rm -rf /tmp/tls_zeek && mkdir -p /tmp/tls_zeek && cd /tmp/tls_zeek && /usr/local/bin/zeek -C -r /tmp/tls_test/capture.pcap', shell=True, check=True)
"""

subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "python3", "-c", test_script], check=True)

# Copy logs to inspect
subprocess.run(["wsl", "-d", "Ubuntu", "cp", "-r", "/tmp/tls_zeek", "/mnt/c/Users/GOURAV GABA/Downloads/unidetectml/scratch/tls_zeek"], check=True)

logs = load_zeek_logs("scratch/tls_zeek")
cols, matrix, flows = extract_feature_matrix(logs)
print(f"Extracted {len(flows)} flows!")
print(f"Zeek logs in dir: {list(logs.keys())}")

for i, f in enumerate(flows):
    vec = matrix[i]
    print(f"Flow {i+1}: uid={f.uid}, ssl_context={vec[FEATURE_INDICES['has_ssl_context']]}, sni_len={vec[FEATURE_INDICES['ssl_sni_len']]}, sni_entropy={vec[FEATURE_INDICES['ssl_sni_entropy']]:.2f}, self_signed={vec[FEATURE_INDICES['ssl_is_self_signed']]}, outdated={vec[FEATURE_INDICES['ssl_is_outdated_version']]}")
