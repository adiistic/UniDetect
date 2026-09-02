import json
import os
import ssl
import socket
import struct
import subprocess
import threading
import time
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import sys
sys.path.insert(0, '.')
from src.features.vector_assembler import extract_feature_matrix
from src.ingestion.zeek_reader import load_zeek_logs
from src.features.schema import FEATURE_INDICES

# 1. Generate certs with Subject Alt Names (SAN)
subprocess.run([
    "wsl", "-d", "Ubuntu", "-u", "root", "/bin/bash", "-c",
    "mkdir -p /tmp/tls_test && cd /tmp/tls_test && openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=portal.secure.internal.local/O=UniDetect Enterprise/C=IN'"
], check=True)

# 2. Python HTTPS server script
server_script = """
import ssl
import http.server
import time

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if '/static/bundle.bin' in self.path:
            body = b'SECURE_ENCRYPTED_ASSET_PAYLOAD_' * 1024  # 32 KB
            ct = 'application/octet-stream'
        else:
            body = b'{"status": "authenticated", "session_id": "tls_sess_99482"}'
            ct = 'application/json'
        self.send_response(200)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        if length > 0:
            _ = self.rfile.read(length)
        resp = b'{"status": "uploaded", "received_bytes": ' + str(length).encode('ascii') + b'}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(resp)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, format, *args):
        pass

server = http.server.ThreadingHTTPServer(('127.0.0.1', 443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/tls_test/cert.pem', '/tmp/tls_test/key.pem')
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.timeout = 0.5
server.serve_forever()
"""

with open("scratch/https_server.py", "w") as f:
    f.write(server_script)

print("Saved scratch/https_server.py")
