"""
UniDetect Main Entry Point

UniDetect is a university cybersecurity prototype for passive network traffic analysis.
It ingests Zeek log files from disk, extracts behavioral features, and performs
offline and near-real-time passive analysis without interacting directly with live network traffic.
"""

import argparse
import sys
from pathlib import Path

# Ensure project root is in sys.path when running script directly
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.features.extractor import extract_all_features
from src.ingestion.live_pipeline import LiveZeekPipeline
from src.ingestion.zeek_reader import load_zeek_logs, SUPPORTED_LOG_TYPES


def main() -> None:
    """CLI entry point for UniDetect passive log analysis."""
    parser = argparse.ArgumentParser(
        description="UniDetect - Passive Network Traffic Analysis"
    )
    parser.add_argument(
        "--log-dir",
        type=str,
        default="data/zeek_logs",
        help="Path to directory containing offline Zeek log files (default: data/zeek_logs)",
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
        help="Path to an active Zeek log directory to poll incrementally (demonstration mode; reads existing log files from disk)",
    )

    args = parser.parse_args()

    # Controlled Demonstration Mode for Live Zeek Log Directory
    if args.live_log_dir:
        live_dir = Path(args.live_log_dir)
        print("UniDetect Passive Traffic Analysis (Live Log Directory Polling)")
        print(f"Target Directory: {live_dir}")
        print("------------------------------------------------------------------")

        pipeline = LiveZeekPipeline(log_dir=live_dir)
        results = pipeline.poll_once()
        summary = results["summary"]

        print(f"Newly observed flow records (conn.log):   {summary['flows_count']}")
        print(f"Newly observed DNS records (dns.log):     {summary.get('dns_count', 0)}")
        print(f"Newly observed weird records (weird.log): {summary.get('weird_count', 0)}")
        print(f"Total newly observed records:            {summary['total_records']}")

        if results["flows"]:
            print("\nSample Newly Parsed FlowRecord:")
            sample = results["flows"][0]
            print(f"  UID:              {sample.uid}")
            print(f"  Source:           {sample.source.ip}:{sample.source.port}")
            print(f"  Destination:      {sample.destination.ip}:{sample.destination.port}")
            print(f"  Protocol:         {sample.network.protocol} (Service: {sample.network.service or 'unknown'})")
            print(f"  Bytes / Packets:  {sample.metrics.total_bytes} bytes / {sample.metrics.total_packets} packets")
            print(f"  State:            {sample.connection_state}")
        return

    # Standard Offline Batch Mode
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
