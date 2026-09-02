import base64
import binascii
import math
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, '.')
from src.features.vector_assembler import extract_feature_matrix
from src.ingestion.zeek_reader import load_zeek_logs
from src.features.schema import FEATURE_INDICES, FEATURE_COLUMNS

# 1. DNS Server supporting A and TXT tunnel responses on port 53
def run_tunnel_dns_server(host: str, port: int, stop_event: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)

    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(512)
            if len(data) < 12:
                continue

            tx_id = data[:2]
            qdcount = struct.unpack("!H", data[4:6])[0]

            idx = 12
            labels = []
            while idx < len(data) and data[idx] != 0:
                length = data[idx]
                idx += 1
                labels.append(data[idx : idx + length].decode("ascii", errors="ignore"))
                idx += length
            idx += 1
            qtype = struct.unpack("!H", data[idx : idx + 2])[0] if idx + 2 <= len(data) else 1
            query_name = ".".join(labels).lower()
            question = data[12 : idx + 4]

            resp_flags = 0x8180  # Standard query response, No error
            answer_ptr = b"\xc0\x0c"

            if qtype == 16:  # TXT Tunnel Response
                txt_payload = b"ENC_DOWNSTREAM_TUNNEL_CHUNK_" + os.urandom(16).hex().encode("ascii")
                rdata = bytes([len(txt_payload)]) + txt_payload
                header = tx_id + struct.pack("!HHHHH", resp_flags, qdcount, 1, 0, 0)
                answer = answer_ptr + struct.pack("!HHIH", 16, 1, 60, len(rdata)) + rdata
                sock.sendto(header + question + answer, addr)
            else:  # Standard / Encoded A response
                header = tx_id + struct.pack("!HHHHH", resp_flags, qdcount, 1, 0, 0)
                answer = answer_ptr + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("127.0.0.1")
                sock.sendto(header + question + answer, addr)

        except (socket.timeout, OSError):
            pass

    sock.close()


def send_dns_query(host: str, port: int, domain: str, qtype: int = 1) -> None:
    tx_id = os.urandom(2)
    flags = b"\x01\x00"
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    qname = b""
    for part in domain.split("."):
        b_part = part.encode("ascii")
        qname += bytes([len(b_part)]) + b_part
    qname += b"\x00"
    qtype_class = struct.pack("!HH", qtype, 1)
    packet = tx_id + flags + counts + qname + qtype_class

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1.0)
        s.sendto(packet, (host, port))
        try:
            _ = s.recvfrom(512)
        except Exception:
            pass


# Test Workload
stop_event = threading.Event()
t_srv = threading.Thread(target=run_tunnel_dns_server, args=("127.0.0.1", 5354, stop_event), daemon=True)
t_srv.start()
time.sleep(0.5)

# Test single query
send_dns_query("127.0.0.1", 5354, "test.local", 1)
send_dns_query("127.0.0.1", 5354, "chunk1.a8f2c3d4e5f6g7h8.tunnel.local", 16)

stop_event.set()
t_srv.join(timeout=1.0)
print("DNS server test completed successfully!")
