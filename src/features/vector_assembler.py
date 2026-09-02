"""
UniDetect Feature Vector Assembler (Person 2 - Phase 4)

Transforms normalized FlowRecord objects and correlated Zeek event logs
into deterministic 78-dimensional numerical feature vectors strictly following the approved schema.
"""

from typing import Any, Dict, List, Optional, Tuple, Union

from src.features.correlator import LogCorrelator
from src.features.math_utils import (
    dns_max_label_len,
    dns_numeric_ratio,
    dns_subdomain_depth,
    dns_vowel_ratio,
    is_private_ip,
    shannon_entropy,
)
from src.features.schema import (
    FEATURE_COLUMNS,
    FEATURE_DEFAULTS,
    NUM_FEATURES,
)
from src.features.window_aggregator import WindowAggregator
from src.models.flow_record import FlowRecord, normalize_conn_record


def _safe_float(val: Any, default: float = 0.0) -> float:
    if val is None or val in ("-", "(empty)", ""):
        return default
    try:
        return float(str(val).strip())
    except (ValueError, TypeError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    if val is None or val in ("-", "(empty)", ""):
        return default
    try:
        return int(float(str(val).strip()))
    except (ValueError, TypeError):
        return default


class FeatureVectorAssembler:
    """Extracts, normalizes, and assembles the 78-feature numerical vector for every connection flow."""

    def __init__(
        self,
        correlator: Optional[LogCorrelator] = None,
        window_aggregator: Optional[WindowAggregator] = None,
    ) -> None:
        """Initialize FeatureVectorAssembler.

        Args:
            correlator: LogCorrelator instance with auxiliary log records.
            window_aggregator: WindowAggregator instance for time-window metrics.
        """
        self.correlator = correlator
        self.window_aggregator = window_aggregator

    def extract_flow_features(self, flow: FlowRecord) -> Dict[str, float]:
        """Extract all 27 Flow-level numerical features from a FlowRecord (Indices 0 - 26)."""
        m = flow.metrics
        flow_duration = max(0.0, float(m.duration))
        orig_bytes = float(max(0, m.orig_bytes))
        resp_bytes = float(max(0, m.resp_bytes))
        total_bytes = float(max(0, m.total_bytes))
        orig_pkts = float(max(0, m.orig_packets))
        resp_pkts = float(max(0, m.resp_packets))
        total_pkts = float(max(0, m.total_packets))
        bytes_per_pkt = float(m.bytes_per_packet)

        orig_bytes_ratio = round(orig_bytes / (total_bytes + 1.0), 4)
        orig_pkts_ratio = round(orig_pkts / (total_pkts + 1.0), 4)
        bytes_asym = round((orig_bytes - resp_bytes) / (orig_bytes + resp_bytes + 1.0), 4)
        missed_bytes = float(max(0, m.missed_bytes))

        resp_p = flow.destination.port
        is_well_known = 1.0 if resp_p < 1024 else 0.0
        is_registered = 1.0 if 1024 <= resp_p <= 49151 else 0.0
        is_dynamic = 1.0 if resp_p > 49151 else 0.0

        is_src_priv = 1.0 if is_private_ip(flow.source.ip) else 0.0
        is_dst_priv = 1.0 if is_private_ip(flow.destination.ip) else 0.0

        proto = flow.network.protocol.lower()
        proto_tcp = 1.0 if proto == "tcp" else 0.0
        proto_udp = 1.0 if proto == "udp" else 0.0
        proto_icmp = 1.0 if proto == "icmp" else 0.0

        state = flow.connection_state.upper()
        state_sf = 1.0 if state == "SF" else 0.0
        state_s0 = 1.0 if state == "S0" else 0.0
        state_rej = 1.0 if state == "REJ" else 0.0
        state_rsto = 1.0 if state in ("RSTO", "RSTOS0", "RSTR") else 0.0

        history = str(flow.metadata.get("history", ""))
        history_len = float(len(history))
        history_syn = 1.0 if ("S" in history or "s" in history) else 0.0
        history_reset = 1.0 if ("R" in history or "r" in history) else 0.0

        return {
            "flow_duration": flow_duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "total_bytes": total_bytes,
            "orig_packets": orig_pkts,
            "resp_packets": resp_pkts,
            "total_packets": total_pkts,
            "bytes_per_packet": bytes_per_pkt,
            "orig_bytes_ratio": orig_bytes_ratio,
            "orig_packets_ratio": orig_pkts_ratio,
            "bytes_asymmetry_ratio": bytes_asym,
            "missed_bytes": missed_bytes,
            "is_well_known_dst_port": is_well_known,
            "is_registered_dst_port": is_registered,
            "is_dynamic_dst_port": is_dynamic,
            "is_src_private_ip": is_src_priv,
            "is_dst_private_ip": is_dst_priv,
            "proto_is_tcp": proto_tcp,
            "proto_is_udp": proto_udp,
            "proto_is_icmp": proto_icmp,
            "conn_state_is_SF": state_sf,
            "conn_state_is_S0": state_s0,
            "conn_state_is_REJ": state_rej,
            "conn_state_is_RSTO": state_rsto,
            "history_len": history_len,
            "history_has_syn": history_syn,
            "history_has_reset": history_reset,
        }

    def extract_dns_features(self, dns_rec: Optional[Dict[str, Any]]) -> Dict[str, float]:
        """Extract all 13 DNS numerical features (Indices 27 - 39). Defaults to 0.0 if absent."""
        if not dns_rec:
            return {
                "has_dns_context": 0.0,
                "dns_query_len": 0.0,
                "dns_query_entropy": 0.0,
                "dns_subdomain_depth": 0.0,
                "dns_max_label_len": 0.0,
                "dns_numeric_ratio": 0.0,
                "dns_vowel_ratio": 0.0,
                "dns_qtype_is_A": 0.0,
                "dns_qtype_is_TXT": 0.0,
                "dns_qtype_is_NULL": 0.0,
                "dns_is_nxdomain": 0.0,
                "dns_answer_count": 0.0,
                "dns_rtt": 0.0,
            }

        query = str(dns_rec.get("query", "")).strip()
        if query in ("-", "(empty)"):
            query = ""

        qtype = str(dns_rec.get("qtype_name", "")).upper()
        rcode = str(dns_rec.get("rcode_name", "")).upper()

        raw_answers = dns_rec.get("answers", [])
        if isinstance(raw_answers, list):
            ans_count = len(raw_answers)
        elif raw_answers and raw_answers not in ("-", "(empty)"):
            ans_count = len([a for a in str(raw_answers).split(",") if a.strip() not in ("-", "")])
        else:
            ans_count = 0

        rtt = _safe_float(dns_rec.get("rtt"), default=0.0)

        return {
            "has_dns_context": 1.0,
            "dns_query_len": float(len(query)),
            "dns_query_entropy": shannon_entropy(query),
            "dns_subdomain_depth": float(dns_subdomain_depth(query)),
            "dns_max_label_len": float(dns_max_label_len(query)),
            "dns_numeric_ratio": dns_numeric_ratio(query),
            "dns_vowel_ratio": dns_vowel_ratio(query),
            "dns_qtype_is_A": 1.0 if qtype == "A" else 0.0,
            "dns_qtype_is_TXT": 1.0 if qtype == "TXT" else 0.0,
            "dns_qtype_is_NULL": 1.0 if qtype in ("NULL", "CNAME", "ANY") else 0.0,
            "dns_is_nxdomain": 1.0 if rcode == "NXDOMAIN" else 0.0,
            "dns_answer_count": float(ans_count),
            "dns_rtt": round(max(0.0, rtt), 4),
        }

    def extract_quic_features(self, quic_rec: Optional[Dict[str, Any]]) -> Dict[str, float]:
        """Extract all 4 QUIC numerical features (Indices 40 - 43). Defaults to 0.0 if absent."""
        if not quic_rec:
            return {
                "has_quic_context": 0.0,
                "quic_sni_len": 0.0,
                "quic_sni_entropy": 0.0,
                "quic_dcid_len": 0.0,
            }

        sni = str(quic_rec.get("server_name", "")).strip()
        if sni in ("-", "(empty)"):
            sni = ""

        dcid = str(quic_rec.get("client_initial_dcid", "")).strip()
        if dcid in ("-", "(empty)"):
            dcid = ""

        return {
            "has_quic_context": 1.0,
            "quic_sni_len": float(len(sni)),
            "quic_sni_entropy": shannon_entropy(sni),
            "quic_dcid_len": float(len(dcid)),
        }

    def extract_weird_features(self, weird_recs: List[Dict[str, Any]]) -> Dict[str, float]:
        """Extract all 5 weird.log anomaly features (Indices 44 - 48). Defaults to 0.0 if absent."""
        if not weird_recs:
            return {
                "has_weird_anomaly": 0.0,
                "weird_anomaly_count_flow": 0.0,
                "weird_is_bad_syn_ack": 0.0,
                "weird_is_bad_http": 0.0,
                "weird_notice_flag": 0.0,
            }

        count = len(weird_recs)
        names = [str(r.get("name", "")) for r in weird_recs]
        has_bad_syn = any(n in ("bad_SYN_ack", "SYN_inside_connection") for n in names)
        has_bad_http = any("HTTP" in n or n == "bad_HTTP_request" for n in names)
        has_notice = any(str(r.get("notice", "")).upper() == "T" for r in weird_recs)

        return {
            "has_weird_anomaly": 1.0,
            "weird_anomaly_count_flow": float(count),
            "weird_is_bad_syn_ack": 1.0 if has_bad_syn else 0.0,
            "weird_is_bad_http": 1.0 if has_bad_http else 0.0,
            "weird_notice_flag": 1.0 if has_notice else 0.0,
        }

    def extract_ssl_features(self, ssl_rec: Optional[Dict[str, Any]]) -> Dict[str, float]:
        """Extract all 7 TLS/SSL numerical features (Indices 49 - 55). Defaults to 0.0 if absent."""
        if not ssl_rec:
            return {
                "has_ssl_context": 0.0,
                "ssl_sni_len": 0.0,
                "ssl_sni_entropy": 0.0,
                "ssl_is_outdated_version": 0.0,
                "ssl_is_self_signed": 0.0,
                "ssl_has_ja3_fingerprint": 0.0,
                "ssl_resumed_flag": 0.0,
            }

        sni = str(ssl_rec.get("server_name", "")).strip()
        if sni in ("-", "(empty)"):
            sni = ""

        version = str(ssl_rec.get("version", "")).strip()
        is_outdated = 1.0 if version in ("SSLv3", "TLSv10", "TLSv11", "TLS 1.0", "TLS 1.1") else 0.0

        val_stat = str(ssl_rec.get("validation_status", "")).lower()
        subj = str(ssl_rec.get("subject", "")).strip()
        issuer = str(ssl_rec.get("issuer", "")).strip()
        is_self_signed = 1.0 if ("self signed" in val_stat or (subj == issuer and subj != "" and subj != "-")) else 0.0

        ja3 = str(ssl_rec.get("ja3", "")).strip()
        has_ja3 = 1.0 if (ja3 and ja3 not in ("-", "(empty)")) else 0.0

        resumed = 1.0 if str(ssl_rec.get("resumed", "")).upper() == "T" else 0.0

        return {
            "has_ssl_context": 1.0,
            "ssl_sni_len": float(len(sni)),
            "ssl_sni_entropy": shannon_entropy(sni),
            "ssl_is_outdated_version": is_outdated,
            "ssl_is_self_signed": is_self_signed,
            "ssl_has_ja3_fingerprint": has_ja3,
            "ssl_resumed_flag": resumed,
        }

    def assemble_feature_dict(
        self,
        flow: FlowRecord,
        dns_rec: Optional[Dict[str, Any]] = None,
        quic_rec: Optional[Dict[str, Any]] = None,
        weird_recs: Optional[List[Dict[str, Any]]] = None,
        ssl_rec: Optional[Dict[str, Any]] = None,
        window_features: Optional[Dict[str, float]] = None,
    ) -> Dict[str, float]:
        """Assemble a complete dictionary containing all 78 features for a single flow."""
        feat_dict: Dict[str, float] = dict(FEATURE_DEFAULTS)

        # 1. Flow features
        flow_feats = self.extract_flow_features(flow)
        feat_dict.update(flow_feats)

        # 2. DNS features
        dns_feats = self.extract_dns_features(dns_rec)
        feat_dict.update(dns_feats)

        # 3. QUIC features
        quic_feats = self.extract_quic_features(quic_rec)
        feat_dict.update(quic_feats)

        # 4. Weird features
        weird_feats = self.extract_weird_features(weird_recs or [])
        feat_dict.update(weird_feats)

        # 5. SSL features
        ssl_feats = self.extract_ssl_features(ssl_rec)
        feat_dict.update(ssl_feats)

        # 6. Window features
        if window_features:
            feat_dict.update(window_features)
        elif self.window_aggregator:
            win_feats = self.window_aggregator.compute_window_features(flow)
            feat_dict.update(win_feats)

        return feat_dict

    def assemble_feature_vector(
        self,
        flow: FlowRecord,
        dns_rec: Optional[Dict[str, Any]] = None,
        quic_rec: Optional[Dict[str, Any]] = None,
        weird_recs: Optional[List[Dict[str, Any]]] = None,
        ssl_rec: Optional[Dict[str, Any]] = None,
        window_features: Optional[Dict[str, float]] = None,
    ) -> List[float]:
        """Assemble a 1D numerical feature vector of exactly 78 floats in schema order."""
        feat_dict = self.assemble_feature_dict(
            flow=flow,
            dns_rec=dns_rec,
            quic_rec=quic_rec,
            weird_recs=weird_recs,
            ssl_rec=ssl_rec,
            window_features=window_features,
        )
        return [float(feat_dict.get(col, FEATURE_DEFAULTS.get(col, 0.0))) for col in FEATURE_COLUMNS]

    def assemble_for_flow(self, flow: Union[FlowRecord, Dict[str, Any]]) -> List[float]:
        """Extract and assemble a 78-feature vector for a FlowRecord using attached correlators."""
        if not isinstance(flow, FlowRecord):
            flow = normalize_conn_record(flow)

        dns_rec = self.correlator.get_dns_for_flow(flow) if self.correlator else None
        quic_rec = self.correlator.get_quic_for_flow(flow) if self.correlator else None
        weird_recs = self.correlator.get_weird_for_flow(flow) if self.correlator else []
        ssl_rec = self.correlator.get_ssl_for_flow(flow) if self.correlator else None

        win_feats = (
            self.window_aggregator.compute_window_features(flow)
            if self.window_aggregator
            else None
        )

        return self.assemble_feature_vector(
            flow=flow,
            dns_rec=dns_rec,
            quic_rec=quic_rec,
            weird_recs=weird_recs,
            ssl_rec=ssl_rec,
            window_features=win_feats,
        )


def extract_feature_matrix(
    log_data: Dict[str, List[Dict[str, Any]]]
) -> Tuple[List[str], List[List[float]], List[FlowRecord]]:
    """Extract a complete 2D feature matrix (N x 78) across all connections in loaded Zeek logs.

    Args:
        log_data: Loaded Zeek logs mapping log name ('conn', 'dns', etc.) to parsed records.

    Returns:
        Tuple of (feature_columns, feature_matrix, flows):
        - feature_columns: List of 78 column header names.
        - feature_matrix: List of N vectors, each having 78 float elements.
        - flows: List of corresponding normalized FlowRecord objects.
    """
    correlator = LogCorrelator(log_data)
    window_aggregator = WindowAggregator(flows=correlator.flows, correlator=correlator)
    assembler = FeatureVectorAssembler(
        correlator=correlator, window_aggregator=window_aggregator
    )

    matrix: List[List[float]] = []
    for flow in correlator.flows:
        vec = assembler.assemble_for_flow(flow)
        matrix.append(vec)

    return FEATURE_COLUMNS, matrix, correlator.flows
