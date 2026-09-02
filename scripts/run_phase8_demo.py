"""
UniDetect Phase 8: FastAPI Backend & Dashboard Integration Demo Script

Replays retained experiment traffic through the streaming ML inference pipeline,
transmits AlertEvents via HTTP POST to the running FastAPI server on port 8000,
validates real-time WebSocket broadcasting, and verifies all REST endpoints and SOC metrics.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import websockets.sync.client as ws_sync

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.features.schema import THREAT_CLASSES
from src.inference.pipeline import RealtimeInferencePipeline

DEMO_EXPERIMENTS = [
    ("exp_benign_periodic_007", "BENIGN", REPO_ROOT / "data/experiments/BENIGN/exp_benign_periodic_007/zeek"),
    ("exp_ddos_syn_001", "DDOS", REPO_ROOT / "data/experiments/DDOS/exp_ddos_syn_001/zeek"),
    ("exp_recon_001", "RECON", REPO_ROOT / "data/experiments/RECON/exp_recon_001/zeek"),
    ("exp_slow_http_001", "SLOW_HTTP", REPO_ROOT / "data/experiments/SLOW_HTTP/exp_slow_http_001/zeek"),
    ("exp_dns_tunnel_001", "DNS_TUNNEL", REPO_ROOT / "data/experiments/DNS_TUNNEL/exp_dns_tunnel_001/zeek"),
    ("exp_c2_beacon_001", "C2_BEACON", REPO_ROOT / "data/experiments/C2_BEACON/exp_c2_beacon_001/zeek"),
]


def run_phase8_demo(
    host: str = "127.0.0.1",
    port: int = 8000,
    model_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Runs the full Phase 8 backend integration demonstration against the running FastAPI server."""
    base_url = f"http://{host}:{port}"
    ws_url = f"ws://{host}:{port}/ws/alerts"

    print("=" * 80)
    print("UniDetect Phase 8: FastAPI Backend & Dashboard Integration Demo")
    print(f"Target Server: {base_url}")
    print(f"WebSocket URL: {ws_url}")
    print("=" * 80)

    reports_dir = REPO_ROOT / "reports" / "phase8"
    reports_dir.mkdir(parents=True, exist_ok=True)

    client = httpx.Client(base_url=base_url, timeout=15.0)

    # 1. Pre-flight Check: Verify Real FastAPI Server is Running
    print("\n1. Initial Health & Status Verification against Running Server:")
    try:
        t0 = time.perf_counter()
        health_res = client.get("/health")
        health_lat_ms = (time.perf_counter() - t0) * 1000.0
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RequestError) as ex:
        print(f"\n[ERROR] Cannot connect to UniDetect backend at {base_url}.")
        print(f"Details: {ex}")
        print("\nPlease start the backend server with:")
        print(f"python src/main.py --dashboard --port {port}\n")
        sys.exit(1)

    if health_res.status_code != 200:
        print(f"\n[ERROR] Backend at {base_url} returned HTTP {health_res.status_code}.")
        print(f"Response: {health_res.text}")
        sys.exit(1)

    print(f"  GET /health -> HTTP {health_res.status_code} ({health_lat_ms:.2f}ms): {health_res.json()}")

    status_res = client.get("/api/v1/status")
    print(f"  GET /api/v1/status -> HTTP {status_res.status_code}: {status_res.json()}")

    model_res = client.get("/api/v1/model")
    print(f"  GET /api/v1/model -> HTTP {model_res.status_code}: Model={model_res.json()['model_version']} (Features={model_res.json()['feature_count']})")

    # 2. Open WebSocket Stream Listener & Replay Multi-Class Threat Traffic
    print("\n2. Replaying Multi-Class Traffic into Real Backend via POST /api/v1/demo/alerts:")
    m_dir = model_dir or (REPO_ROOT / "models" / "phase6e")
    pipeline = RealtimeInferencePipeline(model_dir=m_dir)
    total_replayed = 0
    ws_broadcast_verified = False
    first_verified_alert: Optional[Dict[str, Any]] = None

    try:
        with ws_sync.connect(ws_url, max_queue=None, close_timeout=2) as ws:
            print(f"  [WebSocket] Connected to {ws_url} - listening for real-time alert broadcasts...")
            for exp_id, ground_truth, log_dir in DEMO_EXPERIMENTS:
                if not log_dir.exists():
                    print(f"  Warning: Log directory missing: {log_dir}")
                    continue

                pipeline.reset_state()
                alerts, perf = pipeline.replay_directory(log_dir)

                # Ingest alerts into running backend AlertStore via HTTP POST
                for a in alerts:
                    post_res = client.post("/api/v1/demo/alerts", json=a.to_dict())
                    if post_res.status_code != 201:
                        print(f"  Error ingesting alert {a.alert_id}: HTTP {post_res.status_code} - {post_res.text}")
                    else:
                        total_replayed += 1
                        if not ws_broadcast_verified:
                            try:
                                ws_msg = ws.recv(timeout=2.0)
                                ws_payload = json.loads(ws_msg)
                                if ws_payload.get("alert_id") == a.alert_id:
                                    ws_broadcast_verified = True
                                    first_verified_alert = ws_payload
                                    print(f"  [WebSocket Live Stream Verified] Received broadcast alert: {ws_payload['alert_id'][:8]}... (Label: {ws_payload['predicted_label']})")
                            except Exception:
                                pass

                print(f"  [{exp_id:<24} | {ground_truth:<11}] Ingested {len(alerts)} alerts -> Threats: {perf['threats_detected']}, Benign: {perf['benign_flows']}")
    except Exception as ws_err:
        print(f"  [WebSocket Notice] Could not establish WebSocket test connection ({ws_err}), proceeding with HTTP replay...")
        for exp_id, ground_truth, log_dir in DEMO_EXPERIMENTS:
            if not log_dir.exists():
                continue
            pipeline.reset_state()
            alerts, perf = pipeline.replay_directory(log_dir)
            for a in alerts:
                post_res = client.post("/api/v1/demo/alerts", json=a.to_dict())
                if post_res.status_code == 201:
                    total_replayed += 1
            print(f"  [{exp_id:<24} | {ground_truth:<11}] Ingested {len(alerts)} alerts -> Threats: {perf['threats_detected']}, Benign: {perf['benign_flows']}")

    print(f"\nTotal Replayed Alerts Stored on Server: {total_replayed}")

    # 3. Query REST API Endpoints with Filters and Pagination
    print("\n3. Testing REST API Query Endpoints on Real Server:")

    # Test GET /api/v1/alerts
    t0 = time.perf_counter()
    alerts_all = client.get("/api/v1/alerts?limit=10")
    rest_lat_ms = (time.perf_counter() - t0) * 1000.0
    data_all = alerts_all.json()
    print(f"  GET /api/v1/alerts?limit=10 -> HTTP {alerts_all.status_code} ({rest_lat_ms:.2f}ms) | Total in Store: {data_all['total']}, Items Returned: {len(data_all['items'])}")

    # Test Class Filtering: GET /api/v1/alerts?threat_class=C2_BEACON
    c2_res = client.get("/api/v1/alerts?threat_class=C2_BEACON&limit=5")
    c2_data = c2_res.json()
    print(f"  GET /api/v1/alerts?threat_class=C2_BEACON -> HTTP {c2_res.status_code} | Matching Alerts: {c2_data['total']}")

    # Test Single Alert Fetch: GET /api/v1/alerts/{alert_id}
    if data_all["items"]:
        sample_id = data_all["items"][0]["alert_id"]
        single_res = client.get(f"/api/v1/alerts/{sample_id}")
        print(f"  GET /api/v1/alerts/{sample_id[:8]}... -> HTTP {single_res.status_code} | Label: {single_res.json()['predicted_label']} (Confidence: {single_res.json()['confidence']:.2f})")

    # Test Metrics Endpoint: GET /api/v1/metrics
    metrics_res = client.get("/api/v1/metrics")
    metrics_data = metrics_res.json()
    print(f"  GET /api/v1/metrics -> HTTP {metrics_res.status_code} | Total Flows: {metrics_data['total_flows']} | Threats: {metrics_data['total_threats']} | Latency Avg: {metrics_data['average_inference_latency_ms']}ms")

    # Test Status Endpoint: GET /api/v1/status
    final_status_res = client.get("/api/v1/status")
    final_status_data = final_status_res.json()
    print(f"  GET /api/v1/status -> HTTP {final_status_res.status_code} | Processed Flows: {final_status_data['processed_flow_count']} | Threat Alerts: {final_status_data['alert_count']}")

    # 4. Standalone WebSocket Stream Summary
    print("\n4. WebSocket Streaming Summary:")
    if ws_broadcast_verified and first_verified_alert:
        print(f"  [SUCCESS] Real-time WebSocket streaming verified! Sample broadcast received: {first_verified_alert['alert_id'][:8]}... ({first_verified_alert['predicted_label']})")
    else:
        print(f"  [INFO] WebSocket stream active at {ws_url}")

    # Export demo summary report
    summary = {
        "health_status": health_res.json(),
        "total_alerts_stored": total_replayed,
        "rest_metrics": metrics_data,
        "rest_latency_sample_ms": round(rest_lat_ms, 2),
        "active_classes": model_res.json()["active_classes"],
        "server_status": final_status_data,
        "websocket_stream_verified": ws_broadcast_verified,
    }
    demo_out = reports_dir / "demo_summary.json"
    with open(demo_out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved Phase 8 demo results to: {demo_out}")

    client.close()
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="UniDetect Phase 8 Demo Replay Script")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Target server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Target server port (default: 8000)")
    args = parser.parse_args()

    run_phase8_demo(host=args.host, port=args.port)


if __name__ == "__main__":
    main()

