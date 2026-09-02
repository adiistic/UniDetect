import ssl
import socket
import subprocess
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# 1. Generate self-signed cert
subprocess.run([
    "wsl", "-d", "Ubuntu", "-u", "root", "/bin/bash", "-c",
    "mkdir -p /tmp/tls_test && cd /tmp/tls_test && openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 30 -nodes -subj '/CN=secure-portal.internal.local/O=UniDetect/C=IN'"
], check=True)

# 2. Python HTTPS server
class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "secure_ok"}')
    def log_message(self, format, *args):
        pass

def run_server():
    server = HTTPServer(("127.0.0.1", 8443), SimpleHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # We can run in WSL or Windows
    # Let's run server in WSL
    server.close()

print("Ready to run full TLS test inside WSL!")
