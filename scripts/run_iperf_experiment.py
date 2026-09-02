"""
UniDetect Experiment Runner: BENIGN iperf3 Traffic Generation (exp_benign_iperf_001)

Executes an isolated, end-to-end controlled laboratory experiment:
1. Captures live localhost traffic with tcpdump to pcap/capture.pcap
2. Generates real multi-stream TCP and UDP traffic with iperf3
3. Processes raw PCAP with Zeek to produce zeek/*.log
4. Derives 78-dimensional feature vectors via UniDetect feature pipeline
5. Exports features/features.jsonl and metadata.json
"""

import json
import logging
import math
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES, NUM_FEATURES
from src.features.vector_assembler import extract_feature_matrix
from src.ingestion.zeek_reader import load_zeek_logs

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def run_iperf_experiment() -> Dict[str, Any]:
    """Execute the end-to-end iperf3 experiment inside WSL2."""
    exp_id = "exp_benign_iperf_001"
    exp_dir = REPO_ROOT / "data" / "experiments" / "BENIGN" / exp_id
    pcap_dir = exp_dir / "pcap"
    zeek_dir = exp_dir / "zeek"
    features_dir = exp_dir / "features"

    # Clean / initialize experiment directories
    if exp_dir.exists():
        shutil.rmtree(exp_dir)
    pcap_dir.mkdir(parents=True, exist_ok=True)
    zeek_dir.mkdir(parents=True, exist_ok=True)
    features_dir.mkdir(parents=True, exist_ok=True)

    pcap_file = pcap_dir / "capture.pcap"

    logger.info(f"=== Starting Experiment: {exp_id} ===")
    logger.info(f"Target Directory: {exp_dir}")

    # 1. Start iperf3 server on port 5201
    logger.info("Starting iperf3 server on 127.0.0.1:5201...")
    server_proc = subprocess.Popen(
        ["iperf3", "-s", "-p", "5201"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.5)

    # 2. Start tcpdump to capture traffic on loopback
    logger.info(f"Starting tcpdump packet capture -> {pcap_file}...")
    tcpdump_proc = subprocess.Popen(
        ["tcpdump", "-i", "lo", "-w", str(pcap_file), "port", "5201"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.0)  # Wait for tcpdump to initialize capture buffer

    start_time = time.time()
    logger.info("Generating iperf3 multi-stream TCP traffic (2 streams, 5s)...")
    # Multi-stream TCP traffic
    subprocess.run(["iperf3", "-c", "127.0.0.1", "-p", "5201", "-t", "5", "-P", "2"], capture_output=True)

    time.sleep(0.5)
    logger.info("Generating iperf3 UDP burst traffic (10Mbps, 3s)...")
    # UDP traffic stream
    subprocess.run(["iperf3", "-c", "127.0.0.1", "-p", "5201", "-u", "-b", "10M", "-t", "3"], capture_output=True)

    end_time = time.time()
    logger.info(f"Traffic completed in {end_time - start_time:.2f}s.")

    # 3. Stop tcpdump and iperf3 server
    logger.info("Stopping tcpdump and iperf3 server...")
    time.sleep(0.5)
    tcpdump_proc.send_signal(signal.SIGINT)
    try:
        tcpdump_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        tcpdump_proc.kill()

    server_proc.terminate()
    try:
        server_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server_proc.kill()

    time.sleep(0.5)

    # 4. Verify PCAP file
    if not pcap_file.exists() or pcap_file.stat().st_size == 0:
        raise RuntimeError(f"PCAP capture failed or empty: {pcap_file}")
    pcap_size = pcap_file.stat().st_size
    logger.info(f"PCAP captured: {pcap_file} ({pcap_size} bytes)")

    # Count packets using tcpdump -r
    pkt_count_res = subprocess.run(["tcpdump", "-r", str(pcap_file), "-q"], capture_output=True, text=True)
    packet_count = len(pkt_count_res.stdout.splitlines())
    logger.info(f"Total Packets in PCAP: {packet_count}")

    # 5. Run Zeek against the captured PCAP
    logger.info(f"Running Zeek on {pcap_file} -> logs into {zeek_dir}...")
    zeek_bin = "/usr/local/bin/zeek" if os.path.isfile("/usr/local/bin/zeek") else "/opt/zeek/bin/zeek"
    zeek_res = subprocess.run(
        [zeek_bin, "-C", "-r", str(pcap_file)],
        cwd=str(zeek_dir),
        capture_output=True,
        text=True,
    )
    if zeek_res.returncode != 0:
        logger.warning(f"Zeek stderr: {zeek_res.stderr}")

    # List generated Zeek logs
    zeek_logs_generated = [f.name for f in zeek_dir.glob("*.log")]
    logger.info(f"Zeek Logs Generated: {zeek_logs_generated}")

    # 6. Run UniDetect 78-Feature Extraction Pipeline
    logger.info("Extracting 78-dimensional feature vectors from Zeek logs...")
    logs = load_zeek_logs(zeek_dir)
    cols, matrix, flows = extract_feature_matrix(logs)

    logger.info(f"Extracted {len(matrix)} feature vectors across {len(flows)} flows.")

    # 7. Quality Validation on Feature Vectors
    assert len(cols) == NUM_FEATURES == 78, f"Expected 78 feature columns, got {len(cols)}"
    labeled_records: List[Dict[str, Any]] = []

    for i, flow in enumerate(flows):
        vec = matrix[i]
        assert len(vec) == 78, f"Vector {i} length is {len(vec)}, expected 78"

        # Check for NaN / Inf / String types in vector
        for j, val in enumerate(vec):
            assert isinstance(val, (int, float)), f"Feature {cols[j]} has non-numeric type {type(val)}"
            assert not math.isnan(val), f"Feature {cols[j]} is NaN"
            assert not math.isinf(val), f"Feature {cols[j]} is Inf"

        rec = {
            "experiment_id": exp_id,
            "flow_uid": flow.uid,
            "timestamp": flow.timestamp,
            "source_endpoint": f"{flow.source.ip}:{flow.source.port}",
            "destination_endpoint": f"{flow.destination.ip}:{flow.destination.port}",
            "protocol": flow.network.protocol,
            "connection_state": flow.connection_state,
            "resolution": "flow",
            "label": "BENIGN",
            "label_id": 0,
            "features": vec,
        }
        labeled_records.append(rec)

    # 8. Export features/features.jsonl
    features_jsonl_path = features_dir / "features.jsonl"
    with open(features_jsonl_path, "w", encoding="utf-8") as f:
        for r in labeled_records:
            f.write(json.dumps(r) + "\n")
    logger.info(f"Exported features to: {features_jsonl_path}")

    # 9. Create and Export metadata.json
    metadata = {
        "experiment_id": exp_id,
        "label": "BENIGN",
        "label_id": 0,
        "traffic_generator": "iperf3",
        "description": "Baseline benign high-throughput TCP multi-stream and UDP burst traffic generated via iperf3 in isolated WSL2 laboratory",
        "start_time": start_time,
        "end_time": end_time,
        "duration_seconds": round(end_time - start_time, 3),
        "source_endpoints": ["127.0.0.1"],
        "destination_endpoints": ["127.0.0.1:5201"],
        "capture_file": str(pcap_file.relative_to(REPO_ROOT)),
        "capture_size_bytes": pcap_size,
        "capture_packet_count": packet_count,
        "zeek_log_directory": str(zeek_dir.relative_to(REPO_ROOT)),
        "feature_file": str(features_jsonl_path.relative_to(REPO_ROOT)),
        "total_flows": len(flows),
        "total_features": NUM_FEATURES,
        "label_distribution": {"BENIGN": len(flows)},
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    metadata_path = exp_dir / "metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"Exported metadata to: {metadata_path}")

    return {
        "experiment_id": exp_id,
        "exp_dir": exp_dir,
        "pcap_file": pcap_file,
        "pcap_size": pcap_size,
        "packet_count": packet_count,
        "zeek_logs": zeek_logs_generated,
        "flows_count": len(flows),
        "features_count": len(matrix),
        "metadata": metadata,
        "sample_vector": matrix[0] if matrix else [],
        "cols": cols,
    }


def main() -> None:
    if sys.platform == "win32":
        logger.info("Windows detected. Delegating experiment execution into WSL Ubuntu network namespace...")
        res = subprocess.run(
            ["wsl", "-d", "Ubuntu", "-u", "root", "python3", "scripts/run_iperf_experiment.py"],
            capture_output=False,
        )
        sys.exit(res.returncode)

    res = run_iperf_experiment()
    print("\n==================================================================")
    print(" IPERF3 BENIGN EXPERIMENT COMPLETED SUCCESSFULLY")
    print("==================================================================")
    print(f"Experiment ID:        {res['experiment_id']}")
    print(f"PCAP Capture:         {res['pcap_size']} bytes ({res['packet_count']} packets)")
    print(f"Zeek Logs:            {res['zeek_logs']}")
    print(f"Flows Extracted:      {res['flows_count']}")
    print(f"Feature Vectors:      {res['features_count']} x 78D")
    print(f"Label:                BENIGN (0)")
    print("==================================================================")


if __name__ == "__main__":
    main()
