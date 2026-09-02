"""
UniDetect Pilot Dataset Experiment Runner (Person 2 - Phase 5)

Executes controlled, isolated local pilot experiments for BENIGN and DDOS classes,
records exact experiment metadata and network endpoints, executes Zeek on loopback,
runs the 78-feature engineering pipeline, and exports labeled dataset records.
"""

import json
import logging
import math
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
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
# 1. Local Mock Server Utilities (HTTP)
# ------------------------------------------------------------------------------
class SimpleBenignHTTPHandler(BaseHTTPRequestHandler):
    """Handles standard HTTP GET and POST requests with varying realistic payloads."""

    def do_GET(self) -> None:
        content = b"<html><body><h1>UniDetect Pilot Benign Server</h1><p>Normal payload data.</p></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self) -> None:
        content_len = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(content_len)
        resp = b'{"status": "ok", "message": "payload accepted"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def run_http_server(host: str, port: int, stop_event: threading.Event) -> None:
    """Run lightweight HTTP server in a worker thread until stop_event is set."""
    server = HTTPServer((host, port), SimpleBenignHTTPHandler)
    server.timeout = 0.5
    while not stop_event.is_set():
        server.handle_request()
    server.server_close()


# ------------------------------------------------------------------------------
# 2. Controlled Traffic Generators
# ------------------------------------------------------------------------------
def generate_benign_traffic(
    http_host: str,
    http_port: int,
    num_requests: int = 35,
    stop_event: Optional[threading.Event] = None,
) -> None:
    """Generate structured benign HTTP requests with natural timing intervals."""
    logger.info(f"Generating {num_requests} benign HTTP transactions to {http_host}:{http_port}...")
    for i in range(num_requests):
        if stop_event and stop_event.is_set():
            break
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((http_host, http_port))
                if i % 3 == 0:
                    body = f"client_param_test_data_{i}".encode("utf-8")
                    req = (
                        f"POST /api/telemetry HTTP/1.1\r\n"
                        f"Host: {http_host}:{http_port}\r\n"
                        f"Content-Type: text/plain\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode("utf-8") + body
                else:
                    req = (
                        f"GET /page_{i}.html HTTP/1.1\r\n"
                        f"Host: {http_host}:{http_port}\r\n"
                        f"User-Agent: Mozilla/5.0 (UniDetect-Pilot-Client)\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode("utf-8")
                s.sendall(req)
                _ = s.recv(4096)
        except Exception as e:
            logger.debug(f"Benign client request notice: {e}")
        time.sleep(0.06)


def generate_ddos_traffic(
    target_host: str,
    target_port: int,
    num_floods: int = 150,
    stop_event: Optional[threading.Event] = None,
) -> None:
    """Generate high-rate TCP connection burst (SYN flood simulation) causing non-SF states."""
    logger.info(f"Generating {num_floods} rapid connection flood bursts targeting {target_host}:{target_port}...")
    for i in range(num_floods):
        if stop_event and stop_event.is_set():
            break
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            try:
                s.connect((target_host, target_port))
            except (BlockingIOError, socket.error):
                pass
            time.sleep(0.004)
            s.close()
        except Exception:
            pass


# ------------------------------------------------------------------------------
# 3. Pilot Experiment Execution (Linux / WSL Native Execution)
# ------------------------------------------------------------------------------
def execute_pilot_experiment(
    class_name: str,
    experiment_id: str,
    traffic_type: str,
) -> Dict[str, Any]:
    """Execute experiment directly within Linux/WSL network namespace."""
    exp_dir = REPO_ROOT / "data" / "experiments" / class_name / experiment_id
    zeek_dir = exp_dir / "zeek_logs"
    if exp_dir.exists():
        shutil.rmtree(exp_dir)
    zeek_dir.mkdir(parents=True, exist_ok=True)

    http_host = "127.0.0.1"
    http_port = 8088
    ddos_port = 9099

    # Start local HTTP server
    stop_server = threading.Event()
    server_thread = threading.Thread(
        target=run_http_server,
        args=(http_host, http_port, stop_server),
        daemon=True,
    )
    server_thread.start()

    # Find Zeek binary
    zeek_bin = "/opt/zeek/bin/zeek" if os.path.isfile("/opt/zeek/bin/zeek") else shutil.which("zeek")
    if not zeek_bin:
        raise RuntimeError("Zeek binary not found on system.")

    logger.info(f"Starting Zeek with -C (ignore checksums for loopback) on 'lo' in {zeek_dir} using {zeek_bin}...")
    zeek_proc = subprocess.Popen(
        [zeek_bin, "-C", "-i", "lo"],
        cwd=str(zeek_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.5)  # Allow Zeek to initialize pcap hooks

    start_time = time.time()
    logger.info(f"=== Starting Pilot Traffic for [{experiment_id}] ({class_name}) ===")

    if class_name == "BENIGN":
        generate_benign_traffic(http_host, http_port, num_requests=35)
    elif class_name == "DDOS":
        # Background benign health-check flows concurrent with flood
        bg_thread = threading.Thread(
            target=generate_benign_traffic,
            args=(http_host, http_port, 8),
            daemon=True,
        )
        bg_thread.start()
        generate_ddos_traffic(http_host, ddos_port, num_floods=140)
        bg_thread.join(timeout=3.0)

    end_time = time.time()
    logger.info(f"=== Traffic finished in {end_time - start_time:.2f}s ===")

    # Stop Zeek gracefully via SIGINT to flush all logs
    logger.info("Stopping Zeek and flushing logs...")
    zeek_proc.send_signal(signal.SIGINT)
    try:
        zeek_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        zeek_proc.kill()
    time.sleep(1.0)

    # Stop HTTP server
    stop_server.set()
    server_thread.join(timeout=1.0)

    # Ingest generated Zeek logs
    logs = load_zeek_logs(zeek_dir)
    cols, matrix, flows = extract_feature_matrix(logs)

    # Ground-truth non-blind labeling
    labeled_records: List[Dict[str, Any]] = []
    class_counts: Dict[str, int] = {}

    for i, flow in enumerate(flows):
        vec = matrix[i]

        if class_name == "BENIGN":
            flow_label = "BENIGN"
            flow_label_id = 0
        elif class_name == "DDOS":
            if flow.destination.port == ddos_port or flow.connection_state in ("S0", "REJ", "RSTO", "RSTR"):
                flow_label = "DDOS"
                flow_label_id = 1
            else:
                flow_label = "BENIGN"
                flow_label_id = 0
        else:
            flow_label = class_name
            flow_label_id = THREAT_CLASSES.index(class_name) if class_name in THREAT_CLASSES else -1

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
        "label_id": 0 if class_name == "BENIGN" else 1,
        "traffic_generator": traffic_type,
        "start_time": start_time,
        "end_time": end_time,
        "duration_seconds": round(end_time - start_time, 3),
        "source_endpoints": ["127.0.0.1"],
        "destination_endpoints": [f"127.0.0.1:{http_port}", f"127.0.0.1:{ddos_port}"],
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
    """Main dispatch: forwards to WSL when on Windows, or runs directly on Linux."""
    if sys.platform == "win32":
        logger.info("Detected Windows host. Delegating execution into WSL Ubuntu network namespace...")
        res = subprocess.run(
            ["wsl", "-d", "Ubuntu", "python3", "scripts/pilot_experiment_runner.py"],
            capture_output=False,
        )
        sys.exit(res.returncode)

    # Running inside Linux / WSL
    logger.info("==================================================================")
    logger.info(" UniDetect - Phase 5 Small Pilot Dataset Generation")
    logger.info("==================================================================")

    # 1. Run BENIGN Pilot
    benign_results = execute_pilot_experiment(
        class_name="BENIGN",
        experiment_id="exp_benign_pilot_001",
        traffic_type="python_http_benign_client",
    )

    # 2. Run DDOS Pilot
    ddos_results = execute_pilot_experiment(
        class_name="DDOS",
        experiment_id="exp_ddos_pilot_001",
        traffic_type="python_syn_flood_emulator",
    )

    print("\n==================================================================")
    print(" PILOT EXPERIMENT EXECUTION RESULTS")
    print("==================================================================")
    print(f"1. BENIGN Experiment (exp_benign_pilot_001):")
    print(f"   - Flows Captured:       {benign_results['flows_count']}")
    print(f"   - Feature Vectors:      {benign_results['features_count']} x {NUM_FEATURES}D")
    print(f"   - Zeek Logs Generated:  {benign_results['logs_found']}")
    print(f"   - Label Distribution:   {benign_results['class_counts']}")

    print(f"\n2. DDOS Experiment (exp_ddos_pilot_001):")
    print(f"   - Flows Captured:       {ddos_results['flows_count']}")
    print(f"   - Feature Vectors:      {ddos_results['features_count']} x {NUM_FEATURES}D")
    print(f"   - Zeek Logs Generated:  {ddos_results['logs_found']}")
    print(f"   - Label Distribution:   {ddos_results['class_counts']}")
    print("==================================================================")


if __name__ == "__main__":
    main()
