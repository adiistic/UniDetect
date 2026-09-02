"""
UniDetect Sliding-Window Behavioral Aggregator (Person 2 - Phase 4)

Computes sliding-window behavioral metrics across 10-second, 60-second,
and 300-second windows for Source IP, Destination IP, and Host Pairs.
"""

import math
from typing import Any, Dict, List, Optional, Tuple, Union

from src.features.correlator import LogCorrelator
from src.models.flow_record import FlowRecord, normalize_conn_record


def _safe_float(val: Any, default: float = 0.0) -> float:
    if val is None or val in ("-", "(empty)", ""):
        return default
    try:
        return float(str(val).strip())
    except (ValueError, TypeError):
        return default


def _calc_std(values: List[float], mean_val: float) -> float:
    if len(values) < 2:
        return 0.0
    var = sum((x - mean_val) ** 2 for x in values) / len(values)
    return math.sqrt(max(0.0, var))


class WindowAggregator:
    """Computes behavioral window features for connection flows and host entities."""

    def __init__(
        self,
        flows: Optional[List[FlowRecord]] = None,
        correlator: Optional[LogCorrelator] = None,
    ) -> None:
        """Initialize WindowAggregator.

        Args:
            flows: Historical or batch list of FlowRecord objects.
            correlator: LogCorrelator instance holding auxiliary DNS and weird records.
        """
        self.flows: List[FlowRecord] = flows if flows is not None else []
        self.correlator: Optional[LogCorrelator] = correlator

    def add_flow(self, flow: Union[FlowRecord, Dict[str, Any]]) -> None:
        """Append a flow to the aggregator's history."""
        if isinstance(flow, FlowRecord):
            self.flows.append(flow)
        elif isinstance(flow, dict):
            self.flows.append(normalize_conn_record(flow))

    def compute_window_features(
        self, flow: Union[FlowRecord, Dict[str, Any]]
    ) -> Dict[str, float]:
        """Compute all 22 Section 6 window features for a target flow record.

        Args:
            flow: The FlowRecord (or raw dict) being evaluated.

        Returns:
            Dictionary containing computed window features.
        """
        if not isinstance(flow, FlowRecord):
            flow = normalize_conn_record(flow)

        t = flow.timestamp
        src_ip = flow.source.ip
        dst_ip = flow.destination.ip

        # Filter relevant flows within lookback horizons
        # If the target flow isn't in self.flows, include it as the current event
        eval_flows = self.flows if self.flows else [flow]
        if not any(f.uid == flow.uid for f in eval_flows):
            eval_flows = eval_flows + [flow]

        # ----------------------------------------------------------------------
        # Group A: Source IP Window Features (60s, 10s, 300s)
        # ----------------------------------------------------------------------
        src_flows_60 = [
            f for f in eval_flows
            if f.source.ip == src_ip and (t - 60.0) <= f.timestamp <= t
        ]
        src_flows_10 = [
            f for f in eval_flows
            if f.source.ip == src_ip and (t - 10.0) <= f.timestamp <= t
        ]
        src_flows_300 = [
            f for f in eval_flows
            if f.source.ip == src_ip and (t - 300.0) <= f.timestamp <= t
        ]

        count_src_60 = len(src_flows_60)
        win_src_flow_count_60s = float(max(1, count_src_60))
        win_src_flow_rate_10s = round(float(len(src_flows_10)) / 10.0, 4)

        dst_ips_60 = {f.destination.ip for f in src_flows_60}
        win_src_unique_dst_ips_60s = float(max(1, len(dst_ips_60)))

        dst_ports_60 = {f.destination.port for f in src_flows_60}
        win_src_unique_dst_ports_60s = float(max(1, len(dst_ports_60)))

        non_sf_count = sum(1 for f in src_flows_60 if f.connection_state.upper() != "SF")
        win_src_failed_conn_ratio_60s = (
            round(float(non_sf_count) / count_src_60, 4) if count_src_60 > 0 else 0.0
        )

        s0_count = sum(1 for f in src_flows_60 if f.connection_state.upper() == "S0")
        win_src_s0_syn_ratio_60s = (
            round(float(s0_count) / count_src_60, 4) if count_src_60 > 0 else 0.0
        )

        total_orig_bytes_300 = sum(f.metrics.orig_bytes for f in src_flows_300)
        win_src_total_orig_bytes_300s = float(total_orig_bytes_300)

        total_orig_bytes_60 = sum(f.metrics.orig_bytes for f in src_flows_60)
        win_src_outbound_byte_rate_60s = round(float(total_orig_bytes_60) / 60.0, 4)

        # DNS queries for source IP in 60s
        dns_records = []
        if self.correlator and src_ip in self.correlator.dns_by_src:
            dns_records = [
                d for d in self.correlator.dns_by_src[src_ip]
                if (t - 60.0) <= _safe_float(d.get("ts")) <= t
            ]

        win_src_dns_query_count_60s = float(len(dns_records))
        if dns_records:
            nx_count = sum(
                1 for d in dns_records if str(d.get("rcode_name", "")).upper() == "NXDOMAIN"
            )
            win_src_dns_nxdomain_ratio_60s = round(float(nx_count) / len(dns_records), 4)
            domains = {str(d.get("query", "")) for d in dns_records if d.get("query")}
            win_src_dns_unique_domains_60s = float(len(domains))
        else:
            win_src_dns_nxdomain_ratio_60s = 0.0
            win_src_dns_unique_domains_60s = 0.0

        # Weird anomalies for source IP in 60s
        weird_records = []
        if self.correlator and src_ip in self.correlator.weird_by_src:
            weird_records = [
                w for w in self.correlator.weird_by_src[src_ip]
                if (t - 60.0) <= _safe_float(w.get("ts")) <= t
            ]
        win_src_weird_count_60s = float(len(weird_records))

        # ----------------------------------------------------------------------
        # Group B: Destination IP Window Features (10s, 60s)
        # ----------------------------------------------------------------------
        dst_flows_10 = [
            f for f in eval_flows
            if f.destination.ip == dst_ip and (t - 10.0) <= f.timestamp <= t
        ]
        dst_flows_60 = [
            f for f in eval_flows
            if f.destination.ip == dst_ip and (t - 60.0) <= f.timestamp <= t
        ]

        win_dst_inbound_flow_rate_10s = round(float(len(dst_flows_10)) / 10.0, 4)

        src_set_60 = {f.source.ip for f in dst_flows_60}
        win_dst_unique_sources_60s = float(max(1, len(src_set_60)))

        dst_s0_10 = sum(1 for f in dst_flows_10 if f.connection_state.upper() == "S0")
        win_dst_s0_syn_ratio_10s = (
            round(float(dst_s0_10) / len(dst_flows_10), 4) if dst_flows_10 else 0.0
        )

        total_bytes_dst_60 = sum(f.metrics.total_bytes for f in dst_flows_60)
        win_dst_avg_bytes_per_flow_60s = (
            round(float(total_bytes_dst_60) / len(dst_flows_60), 4)
            if dst_flows_60 else float(flow.metrics.total_bytes)
        )

        # ----------------------------------------------------------------------
        # Group C: Host-Pair Window Features (300s)
        # ----------------------------------------------------------------------
        pair_flows_300 = sorted(
            [
                f for f in eval_flows
                if f.source.ip == src_ip
                and f.destination.ip == dst_ip
                and (t - 300.0) <= f.timestamp <= t
            ],
            key=lambda x: x.timestamp,
        )

        pair_count = len(pair_flows_300)
        win_pair_flow_count_300s = float(max(1, pair_count))
        win_pair_total_orig_bytes_300s = float(
            sum(f.metrics.orig_bytes for f in pair_flows_300)
        )

        if pair_count >= 2:
            # Inter-arrival intervals delta_t
            delta_ts = [
                max(0.0, pair_flows_300[i + 1].timestamp - pair_flows_300[i].timestamp)
                for i in range(pair_count - 1)
            ]
            mean_dt = sum(delta_ts) / len(delta_ts) if delta_ts else 0.0
            std_dt = _calc_std(delta_ts, mean_dt)
            cv_dt = std_dt / (mean_dt + 1e-6)

            orig_bytes_list = [float(f.metrics.orig_bytes) for f in pair_flows_300]
            mean_bytes = sum(orig_bytes_list) / len(orig_bytes_list)
            std_bytes = _calc_std(orig_bytes_list, mean_bytes)

            win_pair_delta_t_mean = round(mean_dt, 4)
            win_pair_delta_t_std = round(std_dt, 4)
            win_pair_delta_t_cv = round(min(5.0, cv_dt), 4)
            win_pair_orig_bytes_std = round(std_bytes, 4)
        else:
            win_pair_delta_t_mean = 0.0
            win_pair_delta_t_std = 0.0
            win_pair_delta_t_cv = 1.0  # Default neutral
            win_pair_orig_bytes_std = 0.0

        return {
            "win_src_flow_count_60s": win_src_flow_count_60s,
            "win_src_flow_rate_10s": win_src_flow_rate_10s,
            "win_src_unique_dst_ips_60s": win_src_unique_dst_ips_60s,
            "win_src_unique_dst_ports_60s": win_src_unique_dst_ports_60s,
            "win_src_failed_conn_ratio_60s": win_src_failed_conn_ratio_60s,
            "win_src_s0_syn_ratio_60s": win_src_s0_syn_ratio_60s,
            "win_src_total_orig_bytes_300s": win_src_total_orig_bytes_300s,
            "win_src_outbound_byte_rate_60s": win_src_outbound_byte_rate_60s,
            "win_src_dns_query_count_60s": win_src_dns_query_count_60s,
            "win_src_dns_nxdomain_ratio_60s": win_src_dns_nxdomain_ratio_60s,
            "win_src_dns_unique_domains_60s": win_src_dns_unique_domains_60s,
            "win_src_weird_count_60s": win_src_weird_count_60s,
            "win_dst_inbound_flow_rate_10s": win_dst_inbound_flow_rate_10s,
            "win_dst_unique_sources_60s": win_dst_unique_sources_60s,
            "win_dst_s0_syn_ratio_10s": win_dst_s0_syn_ratio_10s,
            "win_dst_avg_bytes_per_flow_60s": win_dst_avg_bytes_per_flow_60s,
            "win_pair_flow_count_300s": win_pair_flow_count_300s,
            "win_pair_delta_t_mean": win_pair_delta_t_mean,
            "win_pair_delta_t_std": win_pair_delta_t_std,
            "win_pair_delta_t_cv": win_pair_delta_t_cv,
            "win_pair_orig_bytes_std": win_pair_orig_bytes_std,
            "win_pair_total_orig_bytes_300s": win_pair_total_orig_bytes_300s,
        }
