"""
UniDetect Phase 5 Pilot Dataset Generator (8 Core Threat Classes)

Executes controlled, isolated in-lab experiments inside WSL2 for:
1. BENIGN
2. DDOS
3. RECON
4. DGA
5. DNS_TUNNEL
6. C2_BEACON
7. SLOW_HTTP
8. EXFILTRATION

Preserves exact raw Zeek logs, metadata.json, and 78-feature labeled jsonl outputs.
"""

import json
import logging
import math
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.features.schema import (
    FEATURE_COLUMNS,
    FEATURE_INDICES,
    NUM_FEATURES,
    THREAT_CLASSES,
)
from src.features.vector_assembler import extract_feature_matrix
from src.ingestion.zeek_reader import load_zeek_logs
from src.models.flow_record import FlowRecord

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# 1. Local Mock Server Implementations (HTTP, DNS, Slowloris, Sinks)
# ------------------------------------------------------------------------------
class BenignHTTPHandler(BaseHTTPRequestHandler):
    """Standard HTTP server returning diverse, realistic HTML and JSON payloads."""

    def do_GET(self) -> None:
        if "small" in self.path:
            body = b'{"status": "ok", "service": "health"}'
            content_type = "application/json"
        elif "large" in self.path:
            body = (b"<html><body><h1>Document Repository</h1><p>" + b"Data payload block. " * 50 + b"</p></body></html>")
            content_type = "text/html"
        else:
            body = b"<html><head><title>UniDetect Benign Portal</title></head><body><h1>Welcome</h1></body></html>"
            content_type = "text/html"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            _ = self.rfile.read(min(length, 65536))
        resp = b'{"status": "accepted", "records_stored": 1}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def run_simple_http_server(host: str, port: int, stop_event: threading.Event) -> None:
    server = ThreadingHTTPServer((host, port), BenignHTTPHandler)
    server.timeout = 0.5
    server.daemon_threads = True
    while not stop_event.is_set():
        server.handle_request()
    server.server_close()


def run_mock_dns_server(host: str, port: int, stop_event: threading.Event) -> None:
    """Lightweight UDP DNS server parsing RFC1035 headers and replying with A/TXT/NXDOMAIN."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)

    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(512)
            if len(data) < 12:
                continue

            # Parse transaction ID and flags
            tx_id = data[:2]
            flags = struct.unpack("!H", data[2:4])[0]
            qdcount = struct.unpack("!H", data[4:6])[0]

            # Parse query name
            idx = 12
            labels = []
            while idx < len(data) and data[idx] != 0:
                length = data[idx]
                idx += 1
                labels.append(data[idx : idx + length].decode("ascii", errors="ignore"))
                idx += length
            idx += 1  # Skip terminating 0 byte
            qtype = struct.unpack("!H", data[idx : idx + 2])[0] if idx + 2 <= len(data) else 1
            query_name = ".".join(labels)

            # Determine response: DGA domains produce NXDOMAIN (rcode=3)
            is_dga = any(kw in query_name for kw in ["dga", "conficker", "matsnu", "cryptolocker", "x8q9z3p4"])
            rcode = 3 if is_dga else 0
            resp_flags = 0x8180 | rcode  # Standard response + Recursion Available + RCODE

            # Construct DNS Header
            header = tx_id + struct.pack("!HHHHH", resp_flags, qdcount, 1 if rcode == 0 else 0, 0, 0)
            question = data[12 : idx + 4]

            if rcode == 0:
                # Answer: A record (127.0.0.1) or TXT record
                answer_name = b"\xc0\x0c"  # Pointer to query name
                if qtype == 16:  # TXT
                    txt_data = b"tunnel-ack-payload-sequence-received"
                    rdata = bytes([len(txt_data)]) + txt_data
                    answer = answer_name + struct.pack("!HHIH", 16, 1, 300, len(rdata)) + rdata
                else:  # A
                    rdata = socket.inet_aton("127.0.0.1")
                    answer = answer_name + struct.pack("!HHIH", 1, 1, 300, 4) + rdata
                resp_packet = header + question + answer
            else:
                resp_packet = header + question

            sock.sendto(resp_packet, addr)
        except (socket.timeout, OSError):
            pass

    sock.close()


# ------------------------------------------------------------------------------
# 2. In-Lab Traffic Generators (Safe, Non-Attack, Isolated Local Sockets)
# ------------------------------------------------------------------------------
def generate_benign_traffic(http_host: str, http_port: int, count: int = 30) -> None:
    """Generate normal web GET/POST transactions with variable sizes."""
    logger.info(f"[BENIGN] Generating {count} normal HTTP GET/POST requests to {http_host}:{http_port}...")
    for i in range(count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((http_host, http_port))
                path = "/small" if i % 2 == 0 else "/large"
                req = f"GET {path} HTTP/1.1\r\nHost: {http_host}:{http_port}\r\nConnection: close\r\n\r\n".encode("utf-8")
                s.sendall(req)
                _ = s.recv(4096)
        except Exception:
            pass
        time.sleep(0.04)


def generate_ddos_traffic(target_host: str, target_port: int, count: int = 150) -> None:
    """Generate high-rate TCP connection flood targeting closed port producing non-SF state bursts."""
    logger.info(f"[DDOS] Generating {count} high-rate connection burst attempts to {target_host}:{target_port}...")
    for _ in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            try:
                s.connect((target_host, target_port))
            except (BlockingIOError, socket.error):
                pass
            time.sleep(0.003)
            s.close()
        except Exception:
            pass


def generate_recon_traffic(target_host: str, start_port: int = 1000, end_port: int = 1060) -> None:
    """Generate vertical port scan across sequential destination ports with microsecond probes."""
    logger.info(f"[RECON] Generating port scan across ports {start_port} to {end_port} on {target_host}...")
    for port in range(start_port, end_port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.02)
            s.connect_ex((target_host, port))
            s.close()
        except Exception:
            pass
        time.sleep(0.005)


def generate_dga_traffic(dns_host: str, dns_port: int, count: int = 35) -> None:
    """Generate high-entropy DGA domain queries using published pseudo-random algorithms."""
    logger.info(f"[DGA] Generating {count} algorithmic high-entropy DGA queries to {dns_host}:{dns_port}...")
    # Published Conficker/Matsnu style algorithmic consonant and alphanumeric sequences
    dga_seeds = [
        "vqpzklmxwt49.conficker.local", "9x3p4m1k2v7w.cryptolocker.local",
        "bqzxcvbnmkjh.dga.local", "matsnu789qazws.matsnu.local",
        "plmoknijbuhv.dga.local", "zxcvbnmasdfg.dga.local",
        "qwertyuioplk.dga.local", "mnbvcxzlkjhg.dga.local",
        "1a2b3c4d5e6f.dga.local", "9876543210zy.dga.local"
    ]
    for i in range(count):
        domain = dga_seeds[i % len(dga_seeds)]
        _send_dns_query(dns_host, dns_port, domain, qtype=1)
        time.sleep(0.05)


def generate_dns_tunnel_traffic(dns_host: str, dns_port: int, count: int = 25) -> None:
    """Generate chunked Base64 DNS tunneling payload queries on TXT and NULL records."""
    logger.info(f"[DNS_TUNNEL] Generating {count} deep-subdomain Base64 tunnel queries to {dns_host}:{dns_port}...")
    sample_b64_payloads = [
        "dGhpcy1pcy1hLWtleWxvZ2dlci1leGZpbHRyYXRpb24tcGFja2V0LTE",
        "cGFzc3dvcmRfaGFzaGVzX2R1bXBfY2h1bmtfMDI=",
        "ZXhmaWx0cmF0aW9uX292ZXJfZG5zX3R1bm5lbF9jaHVuazAz",
        "c2VjcmV0X3Byb2plY3RfZmlsZV9jaHVua18wNA==",
    ]
    for i in range(count):
        payload = sample_b64_payloads[i % len(sample_b64_payloads)]
        # Construct deep tunneling label: <b64_chunk>.seq<N>.tunnel.test.local
        domain = f"{payload}.seq{i}.tunnel.test.local"
        qtype = 16 if i % 2 == 0 else 10  # TXT (16) or NULL (10)
        _send_dns_query(dns_host, dns_port, domain, qtype=qtype)
        time.sleep(0.06)


def _send_dns_query(dns_host: str, dns_port: int, domain: str, qtype: int = 1) -> None:
    """Helper to build and send a raw UDP DNS query."""
    tx_id = os.urandom(2)
    flags = b"\x01\x00"  # Standard query with recursion desired
    qdcount = b"\x00\x01"
    counts = b"\x00\x00\x00\x00\x00\x00"

    qname_parts = b""
    for part in domain.split("."):
        b_part = part.encode("ascii")
        qname_parts += bytes([len(b_part)]) + b_part
    qname_parts += b"\x00"
    qtype_class = struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS IN (1)

    packet = tx_id + flags + qdcount + counts + qname_parts + qtype_class
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.sendto(packet, (dns_host, dns_port))
            _ = s.recvfrom(512)
    except Exception:
        pass


def generate_c2_beacon_traffic(target_host: str, target_port: int, count: int = 15) -> None:
    """Generate rigid periodic C2 check-in heartbeats with low delta-T variance."""
    logger.info(f"[C2_BEACON] Generating {count} periodic C2 heartbeats (interval=0.35s) to {target_host}:{target_port}...")
    for _ in range(count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                s.connect((target_host, target_port))
                # Uniform 128-byte heartbeat check-in
                payload = b"C2_HEARTBEAT_AGENT_ID_007_CHECKIN_STATUS_OK_TIMESTAMP_" + str(time.time()).encode("ascii")
                payload = payload.ljust(128, b"#")
                s.sendall(payload)
        except Exception:
            pass
        time.sleep(0.35)  # Rigid periodic interval


def generate_slow_http_traffic(target_host: str, target_port: int, count: int = 15) -> None:
    """Generate Slowloris slow-drip partial HTTP headers holding sockets open."""
    logger.info(f"[SLOW_HTTP] Generating {count} Slowloris slow-drip connections to {target_host}:{target_port}...")
    sockets: List[socket.socket] = []
    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((target_host, target_port))
            initial_req = f"GET /slow_{i} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nUser-Agent: Mozilla/5.0\r\n".encode("utf-8")
            s.sendall(initial_req)
            sockets.append(s)
        except Exception:
            pass
        time.sleep(0.02)

    # Send slow header drips
    for drip in range(2):
        time.sleep(0.15)
        for s in sockets:
            try:
                s.sendall(f"X-Drip-{drip}: keep-alive-slot\r\n".encode("utf-8"))
            except Exception:
                pass

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass


def generate_exfiltration_traffic(target_host: str, target_port: int, count: int = 10) -> None:
    """Generate high-volume outbound byte stream with extreme upload-to-download asymmetry."""
    logger.info(f"[EXFILTRATION] Generating {count} bulk outbound transfers (50KB each) to {target_host}:{target_port}...")
    for i in range(count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3.0)
                s.connect((target_host, target_port))
                # 50 KB outbound data payload
                chunk = b"EXFILTRATED_CORPORATE_DATA_BLOCK_" * 1500
                s.sendall(chunk)
        except Exception:
            pass
        time.sleep(0.1)


# ------------------------------------------------------------------------------
# 3. Experiment Runner & Artifact Generation
# ------------------------------------------------------------------------------
def run_single_experiment(
    class_name: str,
    experiment_id: str,
    generator_name: str,
    traffic_fn: Any,
) -> Dict[str, Any]:
    """Execute a single experiment under Zeek on loopback, extract features, apply ground-truth labels."""
    exp_dir = REPO_ROOT / "data" / "experiments" / class_name / experiment_id
    zeek_dir = exp_dir / "zeek_logs"
    if exp_dir.exists():
        shutil.rmtree(exp_dir)
    zeek_dir.mkdir(parents=True, exist_ok=True)

    # Ports
    http_port = 8088
    dns_port = 5353
    c2_port = 9443
    exfil_port = 9090
    ddos_port = 9099

    # Start background servers
    stop_servers = threading.Event()
    t_http = threading.Thread(target=run_simple_http_server, args=("127.0.0.1", http_port, stop_servers), daemon=True)
    t_dns = threading.Thread(target=run_mock_dns_server, args=("127.0.0.1", dns_port, stop_servers), daemon=True)
    t_http.start()
    t_dns.start()

    # Raw socket sink for raw TCP connections (C2, Exfiltration, Slowloris)
    sink_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sink_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sink_sock.bind(("127.0.0.1", exfil_port))
    sink_sock.listen(50)
    sink_sock.settimeout(0.5)

    def run_sink() -> None:
        while not stop_servers.is_set():
            try:
                conn, _ = sink_sock.accept()
                while not stop_servers.is_set():
                    data = conn.recv(16384)
                    if not data:
                        break
                conn.close()
            except (socket.timeout, OSError):
                pass

    t_sink = threading.Thread(target=run_sink, daemon=True)
    t_sink.start()

    # Find Zeek binary
    zeek_bin = "/opt/zeek/bin/zeek" if os.path.isfile("/opt/zeek/bin/zeek") else shutil.which("zeek")
    if not zeek_bin:
        raise RuntimeError("Zeek binary not found on system.")

    logger.info(f"Starting Zeek on 'lo' in {zeek_dir}...")
    zeek_proc = subprocess.Popen(
        [zeek_bin, "-C", "-i", "lo"],
        cwd=str(zeek_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.5)  # Allow Zeek pcap hooks to initialize

    start_time = time.time()
    logger.info(f"=== Starting Experiment [{experiment_id}] ({class_name}) ===")

    # Execute designated traffic generator
    traffic_fn()

    end_time = time.time()
    logger.info(f"=== Experiment [{experiment_id}] traffic completed in {end_time - start_time:.2f}s ===")

    # Stop Zeek gracefully via SIGINT to flush logs
    zeek_proc.send_signal(signal.SIGINT)
    try:
        zeek_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        zeek_proc.kill()
    time.sleep(1.0)

    # Stop servers
    stop_servers.set()
    sink_sock.close()
    t_http.join(timeout=1.0)
    t_dns.join(timeout=1.0)
    t_sink.join(timeout=1.0)

    # Ingest generated Zeek logs
    logs = load_zeek_logs(zeek_dir)
    cols, matrix, flows = extract_feature_matrix(logs)

    # Ground-truth non-blind labeling
    labeled_records: List[Dict[str, Any]] = []
    class_counts: Dict[str, int] = {}
    label_id = THREAT_CLASSES.index(class_name) if class_name in THREAT_CLASSES else 0

    for i, flow in enumerate(flows):
        vec = matrix[i]

        # In multi-modal experiments, verify flow attribution
        if class_name == "BENIGN":
            flow_label = "BENIGN"
            flow_label_id = 0
        elif class_name == "DDOS":
            flow_label = "DDOS" if (flow.destination.port == ddos_port or flow.connection_state in ("S0", "REJ")) else "BENIGN"
            flow_label_id = 1 if flow_label == "DDOS" else 0
        else:
            flow_label = class_name
            flow_label_id = label_id

        class_counts[flow_label] = class_counts.get(flow_label, 0) + 1

        rec = {
            "experiment_id": experiment_id,
            "flow_uid": flow.uid,
            "timestamp": flow.timestamp,
            "source_endpoint": f"{flow.source.ip}:{flow.source.port}",
            "destination_endpoint": f"{flow.destination.ip}:{flow.destination.port}",
            "protocol": flow.network.protocol,
            "connection_state": flow.connection_state,
            "resolution": "flow",
            "label": flow_label,
            "label_id": flow_label_id,
            "features": vec,
        }
        labeled_records.append(rec)

    # Export features.jsonl
    features_jsonl_path = exp_dir / "features.jsonl"
    with open(features_jsonl_path, "w", encoding="utf-8") as f:
        for r in labeled_records:
            f.write(json.dumps(r) + "\n")

    # Export metadata.json
    metadata = {
        "experiment_id": experiment_id,
        "label": class_name,
        "label_id": label_id,
        "traffic_generator": generator_name,
        "start_time": start_time,
        "end_time": end_time,
        "duration_seconds": round(end_time - start_time, 3),
        "source_endpoints": ["127.0.0.1"],
        "destination_endpoints": [f"127.0.0.1:{http_port}", f"127.0.0.1:{dns_port}", f"127.0.0.1:{exfil_port}", f"127.0.0.1:{ddos_port}"],
        "capture_file": None,
        "zeek_log_directory": str(zeek_dir.relative_to(REPO_ROOT)),
        "total_flows": len(flows),
        "total_features": NUM_FEATURES,
        "label_distribution": class_counts,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    metadata_path = exp_dir / "metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return {
        "experiment_id": experiment_id,
        "class_name": class_name,
        "flows_count": len(flows),
        "features_count": len(matrix),
        "class_counts": class_counts,
        "metadata": metadata,
        "matrix": matrix,
        "logs_found": {k: len(v) for k, v in logs.items() if len(v) > 0},
    }


def main() -> None:
    """Dispatch execution into WSL Ubuntu namespace or run directly on Linux."""
    if sys.platform == "win32":
        logger.info("Windows detected. Delegating pilot dataset execution into WSL Ubuntu network namespace...")
        res = subprocess.run(
            ["wsl", "-d", "Ubuntu", "python3", "scripts/generate_pilot_dataset.py"],
            capture_output=False,
        )
        sys.exit(res.returncode)

    logger.info("==================================================================")
    logger.info(" UniDetect - Phase 5 Pilot Multi-Class Dataset Generation")
    logger.info("==================================================================")

    experiments_plan = [
        ("BENIGN", "exp_benign_001", "python_http_benign_client", lambda: generate_benign_traffic("127.0.0.1", 8088, 30)),
        ("DDOS", "exp_ddos_001", "python_syn_flood_emulator", lambda: generate_ddos_traffic("127.0.0.1", 9099, 120)),
        ("RECON", "exp_recon_001", "python_port_scanner", lambda: generate_recon_traffic("127.0.0.1", 1000, 1050)),
        ("DGA", "exp_dga_001", "python_dga_algorithm_emitter", lambda: generate_dga_traffic("127.0.0.1", 5353, 30)),
        ("DNS_TUNNEL", "exp_dnstunnel_001", "python_dns_tunnel_synthesizer", lambda: generate_dns_tunnel_traffic("127.0.0.1", 5353, 25)),
        ("C2_BEACON", "exp_c2beacon_001", "python_c2_periodic_beacon", lambda: generate_c2_beacon_traffic("127.0.0.1", 9090, 15)),
        ("SLOW_HTTP", "exp_slowhttp_001", "python_slowloris_emulator", lambda: generate_slow_http_traffic("127.0.0.1", 8088, 20)),
        ("EXFILTRATION", "exp_exfil_001", "python_bulk_exfiltration_client", lambda: generate_exfiltration_traffic("127.0.0.1", 9090, 10)),
    ]

    all_results = []
    for class_name, exp_id, gen_name, fn in experiments_plan:
        res = run_single_experiment(class_name, exp_id, gen_name, fn)
        all_results.append(res)

    print("\n==================================================================")
    print(" 8-CLASS PILOT EXPERIMENT GENERATION SUMMARY")
    print("==================================================================")
    for r in all_results:
        print(f"[{r['class_name']:12s} - {r['experiment_id']}]")
        print(f"  • Flows:        {r['flows_count']}")
        print(f"  • Zeek Logs:    {r['logs_found']}")
        print(f"  • Distribution: {r['class_counts']}")
    print("==================================================================")


if __name__ == "__main__":
    main()
