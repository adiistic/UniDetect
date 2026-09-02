import http.server
import json
import os
import random
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, '.')
from src.features.vector_assembler import extract_feature_matrix
from src.ingestion.zeek_reader import load_zeek_logs
from src.features.schema import FEATURE_INDICES, FEATURE_COLUMNS

class C2Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        len_h = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(len_h) if len_h > 0 else b""
        resp = b'{"status": "idle", "task": null}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(resp)
    def log_message(self, format, *args): pass

httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 8443), C2Handler)
httpd.timeout = 0.5
stop_srv = threading.Event()
def serve():
    while not stop_srv.is_set():
        httpd.handle_request()
    httpd.server_close()

t_srv = threading.Thread(target=serve, daemon=True)
t_srv.start()
time.sleep(0.5)

# Test beacon loop (5 beacons)
for i in range(5):
    req = urllib.request.Request("http://127.0.0.1:8443/api/v1/heartbeat", data=b'{"beacon_id": "test01"}', headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        _ = resp.read()
    time.sleep(0.2)

stop_srv.set()
t_srv.join(timeout=1.0)
print("C2 test server and client ran cleanly!")
