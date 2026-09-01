"""
UniDetect Main Entry Point

UniDetect is a university cybersecurity prototype for passive network traffic analysis.
It ingests Zeek log files from disk, extracts behavioral features, and performs
offline passive analysis without interacting directly with live network traffic.
"""

import argparse
import sys
from pathlib import Path

# Ensure project root is in sys.path when running script directly
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.features.extractor import extract_all_features
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
        help="Path to directory containing Zeek log files (default: data/zeek_logs)",
    )
    parser.add_argument(
        "--show-features",
        action="store_true",
        help="Extract and display structured network behavior features summary",
    )

    args = parser.parse_args()
    log_dir = Path(args.log_dir)

    print("UniDetect Passive Traffic Analysis")
    print("----------------------------------")

    logs = load_zeek_logs(log_dir)

    for log_name in SUPPORTED_LOG_TYPES:
        records = logs.get(log_name, [])
        print(f"{log_name}.log records: {len(records)}")

    if args.show-features if False else args.show_features:
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
