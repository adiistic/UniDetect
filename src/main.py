"""
UniDetect Main Entry Point

UniDetect is a university cybersecurity prototype for passive network traffic analysis.
It ingests Zeek log files from disk and performs offline passive analysis without
interacting directly with live network traffic.
"""

import argparse
import sys
from pathlib import Path

# Ensure project root is in sys.path when running script directly
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

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

    args = parser.parse_args()
    log_dir = Path(args.log_dir)

    print("UniDetect Passive Traffic Analysis")
    print("----------------------------------")

    logs = load_zeek_logs(log_dir)

    for log_name in SUPPORTED_LOG_TYPES:
        records = logs.get(log_name, [])
        print(f"{log_name}.log records: {len(records)}")


if __name__ == "__main__":
    main()
