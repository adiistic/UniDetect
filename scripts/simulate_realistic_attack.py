"""
UniDetect Realistic Traffic & Targeted Attack Simulation Script

Demonstrates a realistic SOC scenario:
1. Replays a steady baseline of NORMAL / BENIGN network traffic (e.g. 10-15 flows).
2. Injects ONE SINGLE TARGETED ATTACK (e.g. DDoS SYN Flood, Port Scan Recon, or DNS Tunnel).
3. Resumes normal baseline traffic (e.g. 5-10 flows).
4. Streams events live into the FastAPI backend (and broadcasts via WebSocket to the React SOC Dashboard).

Usage:
  python scripts/simulate_realistic_attack.py
  python scripts/simulate_realistic_attack.py --attack RECON --normal-before 12 --normal-after 6 --delay 0.8
  python scripts/simulate_realistic_attack.py --analyst-review
"""

import argparse
import sys
import time
from pathlib import Path

# pyrefly: ignore [missing-import]
import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.inference.alert import AlertEvent
from src.inference.pipeline import RealtimeInferencePipeline

# Experiment data paths
EXPERIMENT_PATHS: dict[str, Path] = {
    "BENIGN": REPO_ROOT / "data/experiments/BENIGN/exp_benign_periodic_007/zeek",
    "DDOS": REPO_ROOT / "data/experiments/DDOS/exp_ddos_syn_001/zeek",
    "RECON": REPO_ROOT / "data/experiments/RECON/exp_recon_001/zeek",
    "DNS_TUNNEL": REPO_ROOT / "data/experiments/DNS_TUNNEL/exp_dns_tunnel_001/zeek",
    "C2_BEACON": REPO_ROOT / "data/experiments/C2_BEACON/exp_c2_beacon_001/zeek",
    "SLOW_HTTP": REPO_ROOT / "data/experiments/SLOW_HTTP/exp_slow_http_001/zeek",
}


def load_alerts_from_experiment(
    exp_dir: Path,
    max_count: int | None = None,
    filter_label: str | None = None,
) -> list[AlertEvent]:
    """Scores flows from an experiment directory using the real ML pipeline."""
    if not exp_dir.exists():
        raise FileNotFoundError(f"Experiment log directory does not exist: {exp_dir}")

    pipeline = RealtimeInferencePipeline()
    alerts, _ = pipeline.replay_directory(exp_dir)

    if filter_label:
        alerts = [a for a in alerts if a.predicted_label.upper() == filter_label.upper()]

    if max_count is not None:
        alerts = alerts[:max_count]

    return alerts


def simulate_scenario(
    host: str = "127.0.0.1",
    port: int = 8000,
    attack_type: str = "DDOS",
    normal_before: int = 10,
    normal_after: int = 5,
    delay: float = 0.8,
    analyst_review: bool = False,
) -> None:
    """Runs the full simulation of normal traffic with one injected attack."""
    base_url = f"http://{host}:{port}"
    attack_key = attack_type.strip().upper()

    if attack_key not in EXPERIMENT_PATHS or attack_key == "BENIGN":
        valid = [k for k in EXPERIMENT_PATHS if k != "BENIGN"]
        print(f"[ERROR] Invalid attack type '{attack_type}'. Choose from: {valid}")
        sys.exit(1)

    print("=" * 80)
    print("UniDetect - Realistic Traffic Scenario & Single Attack Simulation")
    print(f"Target Server:         {base_url}")
    print(f"Dashboard UI:          {base_url}")
    print(f"Baseline Traffic:      {normal_before} Benign flows -> 1 {attack_key} Attack -> {normal_after} Benign flows")
    print(f"Flow Delay:            {delay:.2f} seconds (for clear visual observation on SOC UI)")
    print("=" * 80)

    # 1. Check if backend is reachable
    client = httpx.Client(base_url=base_url, timeout=10.0)
    try:
        health = client.get("/health")
        if health.status_code != 200:
            print(f"[ERROR] Server returned HTTP {health.status_code}. Is UniDetect running?")
            sys.exit(1)
    except (httpx.RequestError, httpx.HTTPError) as ex:
        print(f"\n[ERROR] Could not connect to UniDetect server at {base_url}: {ex}")
        print("Please start the backend in another terminal first:")
        print(f"    python src/main.py --dashboard --port {port}\n")
        sys.exit(1)

    print("[1/3] Loading and scoring baseline benign flows with ML pipeline...")
    benign_alerts = load_alerts_from_experiment(
        EXPERIMENT_PATHS["BENIGN"],
        max_count=normal_before + normal_after + 5,
        filter_label="BENIGN",
    )
    if len(benign_alerts) < (normal_before + normal_after):
        # Fallback without filter if needed
        benign_alerts = load_alerts_from_experiment(
            EXPERIMENT_PATHS["BENIGN"],
            max_count=normal_before + normal_after + 5,
        )

    print(f"[2/3] Loading and scoring targeted {attack_key} attack flow...")
    attack_alerts = load_alerts_from_experiment(
        EXPERIMENT_PATHS[attack_key],
        max_count=5,
        filter_label=attack_key,
    )
    if not attack_alerts:
        # If strict label filter had 0, grab the first attack flow
        attack_alerts = load_alerts_from_experiment(EXPERIMENT_PATHS[attack_key], max_count=5)

    if not attack_alerts:
        print(f"[ERROR] Could not generate attack alerts for {attack_key}.")
        sys.exit(1)

    # Pick the target attack alert
    target_attack_alert = attack_alerts[0]

    if analyst_review:
        # Create an ambiguous / borderline traffic flow that triggers selective abstention
        target_attack_alert.confidence = 0.3850
        target_attack_alert.abstained = True
        target_attack_alert.decision = "ANALYST_REVIEW"
        target_attack_alert.predicted_label = "RECON"
        target_attack_alert.predicted_class_id = 2
        target_attack_alert.probabilities = {
            "RECON": 0.3850,
            "BENIGN": 0.3200,
            "DDOS": 0.1450,
            "SLOW_HTTP": 0.0800,
            "C2_BEACON": 0.0400,
            "DNS_TUNNEL": 0.0300,
        }

    # Partition benign alerts
    before_flows = benign_alerts[:normal_before]
    after_flows = benign_alerts[normal_before : normal_before + normal_after]

    print("\n[3/3] Beginning Live Simulation Stream to Dashboard...")
    print(">>> Open http://127.0.0.1:8000 in your browser to watch live! <<<\n")
    time.sleep(1.0)

    sent_count = 0

    # Phase 1: Stream normal baseline traffic
    print(f"--- PHASE 1: Streaming {len(before_flows)} Normal Baseline Flows ---")
    for i, alert in enumerate(before_flows, start=1):
        resp = client.post("/api/v1/demo/alerts", json=alert.to_dict())
        if resp.status_code == 201:
            sent_count += 1
            print(
                f"  [{i:02d}/{normal_before:02d}] NORMAL: {alert.source_ip}:{alert.source_port} -> "
                f"{alert.destination_ip}:{alert.destination_port} ({alert.protocol.upper()}) | "
                f"Label: {alert.predicted_label} | Conf: {alert.confidence*100:.1f}% | Verdict: {alert.decision}"
            )
        else:
            print(f"  Failed to post alert: {resp.status_code}")
        time.sleep(delay)

    # Phase 2: Inject the single attack flow
    print("\n" + "!" * 80)
    verdict_tag = "ANALYST_REVIEW (ABSTAINED)" if target_attack_alert.abstained else "AUTOMATED_DETECTION"
    print(f"[!] --- PHASE 2: INJECTING TARGETED {target_attack_alert.predicted_label} ({verdict_tag}) --- [!]")
    resp = client.post("/api/v1/demo/alerts", json=target_attack_alert.to_dict())
    if resp.status_code == 201:
        sent_count += 1
        print(
            f"  >>> FLOW INJECTED! <<< \n"
            f"      Source:      {target_attack_alert.source_ip}:{target_attack_alert.source_port}\n"
            f"      Destination: {target_attack_alert.destination_ip}:{target_attack_alert.destination_port}\n"
            f"      Protocol:    {target_attack_alert.protocol.upper()}\n"
            f"      Threat Type: {target_attack_alert.predicted_label}\n"
            f"      Confidence:  {target_attack_alert.confidence*100:.1f}% (Abstained: {target_attack_alert.abstained})\n"
            f"      Decision:    {target_attack_alert.decision}\n"
            f"      Alert ID:    {target_attack_alert.alert_id}"
        )
    else:
        print(f"  Failed to post attack alert: {resp.status_code}")
    print("!" * 80 + "\n")
    time.sleep(delay * 1.5)

    # Phase 3: Resume normal baseline traffic
    print(f"--- PHASE 3: Resuming {len(after_flows)} Normal Baseline Flows ---")
    for i, alert in enumerate(after_flows, start=1):
        resp = client.post("/api/v1/demo/alerts", json=alert.to_dict())
        if resp.status_code == 201:
            sent_count += 1
            print(
                f"  [{i:02d}/{normal_after:02d}] NORMAL: {alert.source_ip}:{alert.source_port} -> "
                f"{alert.destination_ip}:{alert.destination_port} ({alert.protocol.upper()}) | "
                f"Label: {alert.predicted_label} | Conf: {alert.confidence*100:.1f}% | Verdict: {alert.decision}"
            )
        else:
            print(f"  Failed to post alert: {resp.status_code}")
        time.sleep(delay)

    # Final summary
    metrics_res = client.get("/api/v1/metrics").json()
    print("\n" + "=" * 80)
    print("Simulation Complete!")
    print(f"  Total Flows Sent:      {sent_count}")
    print(f"  Total Flows on UI:     {metrics_res.get('total_flows')}")
    print(f"  Active Threats on UI:  {metrics_res.get('total_threats')}")
    print(f"  Analyst Reviews on UI: {metrics_res.get('analyst_review_count')}")
    print(f"  Benign Flows on UI:    {metrics_res.get('benign_count')}")
    print(f"  Average ML Latency:    {metrics_res.get('average_inference_latency_ms')} ms")
    print(f"  Class Distribution:    {metrics_res.get('per_class_counts')}")
    print("=" * 80)
    client.close()


def main():
    parser = argparse.ArgumentParser(
        description="Simulate realistic network traffic with a single injected threat."
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Backend host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Backend port (default: 8000)",
    )
    parser.add_argument(
        "--attack",
        type=str,
        default="DDOS",
        choices=["DDOS", "RECON", "DNS_TUNNEL", "C2_BEACON", "SLOW_HTTP"],
        help="Type of attack to inject (default: DDOS)",
    )
    parser.add_argument(
        "--analyst-review",
        action="store_true",
        help="Inject an ambiguous/borderline flow that triggers 'ANALYST_REVIEW' (selective abstention)",
    )
    parser.add_argument(
        "--normal-before",
        type=int,
        default=10,
        help="Number of normal flows before the attack (default: 10)",
    )
    parser.add_argument(
        "--normal-after",
        type=int,
        default=5,
        help="Number of normal flows after the attack (default: 5)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.8,
        help="Delay in seconds between flows for visual demo (default: 0.8)",
    )
    args = parser.parse_args()

    simulate_scenario(
        host=args.host,
        port=args.port,
        attack_type=args.attack,
        normal_before=args.normal_before,
        normal_after=args.normal_after,
        delay=args.delay,
        analyst_review=args.analyst_review,
    )


if __name__ == "__main__":
    main()
