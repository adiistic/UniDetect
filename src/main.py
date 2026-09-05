"""
UniDetect Main Entry Point

UniDetect is a university cybersecurity prototype for passive network traffic analysis.
It ingests Zeek log files from disk, extracts behavioral features, and performs
offline, replay, and near-real-time passive threat detection using frozen ML models,
with an interactive SOC dashboard and FastAPI streaming interface.
"""

import argparse
import json
import sys
from pathlib import Path

# Ensure project root is in sys.path when running script directly
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.features.extractor import extract_all_features
from src.inference.pipeline import RealtimeInferencePipeline
from src.ingestion.live_pipeline import LiveZeekPipeline
from src.ingestion.zeek_reader import SUPPORTED_LOG_TYPES, load_zeek_logs


def main() -> None:
    """CLI entry point for UniDetect passive log analysis, ML threat detection, and SOC dashboard."""
    parser = argparse.ArgumentParser(
        description="UniDetect - Passive Network Traffic Analysis & SOC Dashboard"
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch the interactive SOC dashboard and FastAPI backend server on http://127.0.0.1:8000",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind the dashboard web server (default: 8000)",
    )
    parser.add_argument(
        "--log-dir",
        type=str,
        default="data/zeek_logs",
        help="Path to directory containing offline Zeek log files (default: data/zeek_logs)",
    )
    parser.add_argument(
        "--predict",
        action="store_true",
        help="Run real-time ML threat detection across flows in the target log directory",
    )
    parser.add_argument(
        "--show-features",
        action="store_true",
        help="Extract and display structured network behavior features summary",
    )
    parser.add_argument(
        "--live-log-dir",
        type=str,
        default=None,
        help="Path to an active Zeek log directory to poll incrementally with live ML detection",
    )

    args = parser.parse_args()

    # 1. Interactive SOC Dashboard & Backend Web Server
    if args.dashboard:
        import uvicorn
        print("=" * 80)
        print("Launching UniDetect SOC Dashboard & FastAPI Streaming Backend")
        print(f"  Dashboard UI:           http://127.0.0.1:{args.port}")
        print(f"  REST API:               http://127.0.0.1:{args.port}/api/v1/alerts")
        print(f"  WebSocket Stream:       ws://127.0.0.1:{args.port}/ws/alerts")
        print(f"  Interactive OpenAPI:    http://127.0.0.1:{args.port}/docs")
        print("=" * 80)
        uvicorn.run("src.api.app:app", host="127.0.0.1", port=args.port, reload=False)
        return

    # 2. Controlled Live / Replay ML Inference Mode
    if args.predict or args.live_log_dir:
        target_dir = Path(args.live_log_dir) if args.live_log_dir else Path(args.log_dir)
        print("=" * 80)
        print("UniDetect Passive Traffic Analysis & ML Threat Detection Pipeline")
        print(f"Target Directory: {target_dir.resolve()}")
        print("=" * 80)

        pipeline = RealtimeInferencePipeline()

        if args.live_log_dir:
            print("[LIVE STREAMING MODE]")
            live_pipe = LiveZeekPipeline(log_dir=target_dir)
            
            def alert_cb(alert):
                tag = f"[{alert.decision}]"
                status = f"THREAT: {alert.predicted_label}" if alert.is_threat else ("REVIEW" if alert.abstained else "BENIGN")
                print(f"  {tag:<22} {status:<18} | {alert.source_ip}:{alert.source_port} -> {alert.destination_ip}:{alert.destination_port} ({alert.protocol}) | Conf: {alert.confidence:.2f} ({alert.processing_time_ms:.1f}ms)")

            poll_fn = pipeline.attach_to_live_pipeline(live_pipe, alert_callback=alert_cb)
            print("Executing incremental poll pass...")
            alerts = poll_fn()
            perf = pipeline.get_performance_summary()
            print("\nLive Polling Summary:")
            print(f"  Flows Processed:   {perf['total_flows_processed']}")
            print(f"  Threats Detected:  {perf['threats_detected']}")
            print(f"  Analyst Reviews:   {perf['abstained_reviews']}")
            print(f"  Benign Flows:      {perf['benign_flows']}")
            print(f"  Mean Latency:      {perf['mean_latency_ms']} ms/flow")
            return

        else:
            print("[OFFLINE REPLAY MODE]")
            alerts, perf = pipeline.replay_directory(target_dir)
            print("\nReplay Execution Complete:")
            print(f"  Flows Processed:   {perf['total_flows_processed']}")
            print(f"  Threats Detected:  {perf['threats_detected']}")
            print(f"  Analyst Reviews:   {perf['abstained_reviews']}")
            print(f"  Benign Flows:      {perf['benign_flows']}")
            print(f"  Mean Latency:      {perf['mean_latency_ms']} ms/flow")
            print(f"  P95 Latency:       {perf['p95_latency_ms']} ms/flow")
            print(f"  Throughput:        {perf['throughput_flows_per_sec']} flows/second")

            if alerts:
                print("\nSample Emitted Alert:")
                sample = alerts[0]
                print(json.dumps(sample.to_dict(), indent=2))
            return

    # 3. Standard Offline Batch Inspection Mode
    log_dir = Path(args.log_dir)

    print("UniDetect Passive Traffic Analysis")
    print("----------------------------------")

    logs = load_zeek_logs(log_dir)

    for log_name in SUPPORTED_LOG_TYPES:
        records = logs.get(log_name, [])
        print(f"{log_name}.log records: {len(records)}")

    if args.show_features:
        features_data = extract_all_features(logs)
        summary = features_data["summary"]

        print("\nFeature Extraction Summary")
        print("--------------------------")
        print(f"Total connections: {summary['total_connections']}")
        print(f"Total DNS queries: {summary['total_dns_queries']}")
        print(f"Unique source IPs: {summary['unique_source_ips']}")
        print(f"Unique destination IPs: {summary['unique_destination_ips']}")
        print(f"Total bytes observed: {summary['total_bytes_observed']}")
        print(f"Total packets observed: {summary['total_packets_observed']}")

        if summary["protocols"]:
            print("\nProtocols:")
            for proto, count in summary["protocols"].items():
                print(f"{proto}: {count}")

        if summary["services"]:
            print("\nServices:")
            for srv, count in summary["services"].items():
                print(f"{srv}: {count}")

        if summary["connection_states"]:
            print("\nConnection States:")
            for state, count in summary["connection_states"].items():
                print(f"{state}: {count}")


if __name__ == "__main__":
    main()
