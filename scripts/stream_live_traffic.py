"""
Continuous Traffic Streamer for UniDetect SOC Dashboard Demonstration

Reads retained experiments chronologically and replays them through the RealtimeInferencePipeline,
broadcasting AlertEvents to the active dashboard server or injecting them with pacing.
"""

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import List

import websockets

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.inference.pipeline import RealtimeInferencePipeline

DEMO_EXPERIMENTS = [
    ("exp_benign_periodic_007", "BENIGN", REPO_ROOT / "data/experiments/BENIGN/exp_benign_periodic_007/zeek"),
    ("exp_ddos_syn_001", "DDOS", REPO_ROOT / "data/experiments/DDOS/exp_ddos_syn_001/zeek"),
    ("exp_recon_001", "RECON", REPO_ROOT / "data/experiments/RECON/exp_recon_001/zeek"),
    ("exp_slow_http_001", "SLOW_HTTP", REPO_ROOT / "data/experiments/SLOW_HTTP/exp_slow_http_001/zeek"),
    ("exp_dns_tunnel_001", "DNS_TUNNEL", REPO_ROOT / "data/experiments/DNS_TUNNEL/exp_dns_tunnel_001/zeek"),
    ("exp_c2_beacon_001", "C2_BEACON", REPO_ROOT / "data/experiments/C2_BEACON/exp_c2_beacon_001/zeek"),
]


async def stream_to_dashboard(server_ws_url: str = "ws://127.0.0.1:8000/ws/alerts", pace_ms: int = 120):
    """Streams replayed alerts directly into the live WebSocket or backend."""
    print("=" * 80)
    print("UniDetect Real-Time Traffic Streamer for SOC Dashboard")
    print(f"Target WebSocket: {server_ws_url}")
    print(f"Pacing: {pace_ms}ms between flow events")
    print("=" * 80)

    pipeline = RealtimeInferencePipeline()

    print("\nExtracting and scoring flows from retained experiments...")
    all_alerts = []
    for exp_id, ground_truth, log_dir in DEMO_EXPERIMENTS:
        if not log_dir.exists():
            continue
        pipeline.reset_state()
        alerts, _ = pipeline.replay_directory(log_dir)
        all_alerts.extend(alerts)
        print(f"  Loaded {len(alerts)} alerts from [{exp_id} - {ground_truth}]")

    print(f"\nTotal Flow Alerts Ready to Stream: {len(all_alerts)}")

    # Sort alerts chronologically
    all_alerts.sort(key=lambda a: a.timestamp)

    print("\nConnecting to live WebSocket stream...")
    try:
        async with websockets.connect(server_ws_url) as ws:
            print("Connected! Streaming live events to dashboard subscribers...")
            for i, alert in enumerate(all_alerts):
                # Send alert payload
                payload = alert.to_dict()
                await ws.send(json.dumps(payload))
                tag = f"[{alert.decision}]"
                print(f"  [{i+1}/{len(all_alerts)}] {tag:<22} {alert.predicted_label:<14} | {alert.source_ip}:{alert.source_port} -> {alert.destination_ip}:{alert.destination_port} ({alert.protocol}) | Conf: {alert.confidence*100:.1f}%")
                await asyncio.sleep(pace_ms / 1000.0)

            print("\nStream completed successfully!")
    except Exception as e:
        print(f"Streaming error (ensure dashboard is running on port 8000): {e}")


def main():
    asyncio.run(stream_to_dashboard())


if __name__ == "__main__":
    main()
