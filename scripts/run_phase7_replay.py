"""
UniDetect Phase 7: Real-Time Inference Replay Benchmark Across All 12 Retained Experiments

Replays all 12 authoritative Phase 5 experiments through RealtimeInferencePipeline,
measuring end-to-end ingestion, causal window aggregation, feature vector assembly,
calibrated threat inference, decision thresholding, latency (mean, p50, p95, max),
and throughput (flows/sec).
"""

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.inference.pipeline import RealtimeInferencePipeline

RETAINED_EXPERIMENTS = [
    ("exp_benign_iperf_002", "BENIGN", REPO_ROOT / "data/experiments/BENIGN/exp_benign_iperf_002/zeek"),
    ("exp_benign_multi_003", "BENIGN", REPO_ROOT / "data/experiments/BENIGN/exp_benign_multi_003/zeek"),
    ("exp_benign_dns_004", "BENIGN", REPO_ROOT / "data/experiments/BENIGN/exp_benign_dns_004/zeek"),
    ("exp_benign_tls_005", "BENIGN", REPO_ROOT / "data/experiments/BENIGN/exp_benign_tls_005/zeek"),
    ("exp_benign_mixed_006", "BENIGN", REPO_ROOT / "data/experiments/BENIGN/exp_benign_mixed_006/zeek"),
    ("exp_benign_periodic_007", "BENIGN", REPO_ROOT / "data/experiments/BENIGN/exp_benign_periodic_007/zeek"),
    ("exp_ddos_syn_001", "DDOS", REPO_ROOT / "data/experiments/DDOS/exp_ddos_syn_001/zeek"),
    ("exp_ddos_udp_002", "DDOS", REPO_ROOT / "data/experiments/DDOS/exp_ddos_udp_002/zeek"),
    ("exp_recon_001", "RECON", REPO_ROOT / "data/experiments/RECON/exp_recon_001/zeek"),
    ("exp_slow_http_001", "SLOW_HTTP", REPO_ROOT / "data/experiments/SLOW_HTTP/exp_slow_http_001/zeek"),
    ("exp_dns_tunnel_001", "DNS_TUNNEL", REPO_ROOT / "data/experiments/DNS_TUNNEL/exp_dns_tunnel_001/zeek"),
    ("exp_c2_beacon_001", "C2_BEACON", REPO_ROOT / "data/experiments/C2_BEACON/exp_c2_beacon_001/zeek"),
]


def run_phase7_replay() -> Dict[str, Any]:
    """Executes full replay benchmark across all retained experiments."""
    print("=" * 80)
    print("UniDetect Phase 7: Real-Time / Replay Inference Pipeline Benchmark")
    print("=" * 80)

    reports_dir = REPO_ROOT / "reports" / "phase7"
    reports_dir.mkdir(parents=True, exist_ok=True)

    pipeline = RealtimeInferencePipeline()
    benchmark_results: List[Dict[str, Any]] = []
    all_sample_alerts: List[Dict[str, Any]] = []

    total_corpus_flows = 0
    all_latencies_ms: List[float] = []

    print(f"{'EXPERIMENT ID':<26} | {'CLASS':<11} | {'FLOWS':<6} | {'THREATS':<8} | {'BENIGN':<7} | {'REVIEW':<7} | {'MEAN (ms)':<10} | {'THROUGHPUT':<14}")
    print("-" * 105)

    for exp_id, ground_truth, log_dir in RETAINED_EXPERIMENTS:
        if not log_dir.exists():
            print(f"Warning: Directory missing: {log_dir}")
            continue

        pipeline.reset_state()
        alerts, perf = pipeline.replay_directory(log_dir)

        total_corpus_flows += perf["total_flows_processed"]
        all_latencies_ms.extend(pipeline.latency_records_ms)

        # Store sample alert for demonstration
        if alerts:
            all_sample_alerts.append(alerts[0].to_dict())

        row = {
            "experiment_id": exp_id,
            "ground_truth_class": ground_truth,
            "flows_count": perf["total_flows_processed"],
            "threats_detected": perf["threats_detected"],
            "benign_detected": perf["benign_flows"],
            "analyst_reviews": perf["abstained_reviews"],
            "inference_errors": perf["inference_errors"],
            "mean_latency_ms": perf["mean_latency_ms"],
            "p50_latency_ms": perf["p50_latency_ms"],
            "p95_latency_ms": perf["p95_latency_ms"],
            "max_latency_ms": perf["max_latency_ms"],
            "throughput_flows_sec": perf["throughput_flows_per_sec"],
        }
        benchmark_results.append(row)

        print(f"{exp_id:<26} | {ground_truth:<11} | {perf['total_flows_processed']:<6} | {perf['threats_detected']:<8} | {perf['benign_flows']:<7} | {perf['abstained_reviews']:<7} | {perf['mean_latency_ms']:<10.3f} | {perf['throughput_flows_per_sec']:<10.1f} flows/s")

    print("-" * 105)
    all_lats = np.array(all_latencies_ms)
    overall_mean_lat = round(float(np.mean(all_lats)), 3)
    overall_p50_lat = round(float(np.percentile(all_lats, 50)), 3)
    overall_p95_lat = round(float(np.percentile(all_lats, 95)), 3)
    overall_p99_lat = round(float(np.percentile(all_lats, 99)), 3)
    overall_max_lat = round(float(np.max(all_lats)), 3)

    print(f"\nCorpus Aggregate Performance Summary:")
    print(f"  Total Flows Processed: {total_corpus_flows}")
    print(f"  Overall Mean Latency:  {overall_mean_lat} ms / flow")
    print(f"  Overall P50 Latency:   {overall_p50_lat} ms / flow")
    print(f"  Overall P95 Latency:   {overall_p95_lat} ms / flow")
    print(f"  Overall P99 Latency:   {overall_p99_lat} ms / flow")
    print(f"  Overall Max Latency:   {overall_max_lat} ms / flow")
    print(f"  Estimated In-Memory Throughput: ~{round(1000.0 / overall_mean_lat, 1)} flows / second (single-threaded CPU)")

    # Export CSV and JSON results
    df_res = pd.DataFrame(benchmark_results)
    csv_out = reports_dir / "replay_benchmark.csv"
    df_res.to_csv(csv_out, index=False)
    print(f"\nSaved benchmark metrics to: {csv_out}")

    alerts_out = reports_dir / "sample_alerts.json"
    with open(alerts_out, "w", encoding="utf-8") as f:
        json.dump(all_sample_alerts, f, indent=2)
    print(f"Saved sample alert schema representations to: {alerts_out}")

    return {
        "benchmark_summary": benchmark_results,
        "overall_mean_latency_ms": overall_mean_lat,
        "overall_p95_latency_ms": overall_p95_lat,
        "total_flows": total_corpus_flows,
    }


def main() -> None:
    run_phase7_replay()


if __name__ == "__main__":
    main()
