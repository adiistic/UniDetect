"""
UniDetect Feature Extractor

Extracts structured network behavior features from ingested Zeek log records
safely and passively without modifying original files or network state.
"""

from collections import Counter
from typing import Any, Dict, List, Set


def safe_int(val: Any, default: int = 0) -> int:
    """Safely convert a raw Zeek log field to an integer.

    Handles missing values ('-', '(empty)', None, blank strings) gracefully.
    """
    if val is None or val in ("-", "(empty)", ""):
        return default
    try:
        return int(float(str(val).strip()))
    except (ValueError, TypeError):
        return default


def safe_float(val: Any, default: float = 0.0) -> float:
    """Safely convert a raw Zeek log field to a float.

    Handles missing values ('-', '(empty)', None, blank strings) gracefully.
    """
    if val is None or val in ("-", "(empty)", ""):
        return default
    try:
        return float(str(val).strip())
    except (ValueError, TypeError):
        return default


def clean_str(val: Any, default: str = "") -> str:
    """Clean a raw Zeek string field by removing placeholders like '-' or '(empty)'."""
    if val is None or val in ("-", "(empty)"):
        return default
    return str(val).strip()


def extract_connection_features(conn_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract structured features from conn.log records.

    Args:
        conn_records: Raw dictionaries parsed from conn.log.

    Returns:
        List of structured connection feature dictionaries.
    """
    features: List[Dict[str, Any]] = []

    for rec in conn_records:
        orig_bytes = safe_int(rec.get("orig_bytes"))
        resp_bytes = safe_int(rec.get("resp_bytes"))
        total_bytes = orig_bytes + resp_bytes

        orig_pkts = safe_int(rec.get("orig_pkts"))
        resp_pkts = safe_int(rec.get("resp_pkts"))
        total_packets = orig_pkts + resp_pkts

        bytes_per_packet = (
            float(total_bytes) / total_packets if total_packets > 0 else 0.0
        )

        feat = {
            "uid": clean_str(rec.get("uid")),
            "timestamp": safe_float(rec.get("ts")),
            "source_ip": clean_str(rec.get("id.orig_h")),
            "source_port": safe_int(rec.get("id.orig_p")),
            "destination_ip": clean_str(rec.get("id.resp_h")),
            "destination_port": safe_int(rec.get("id.resp_p")),
            "protocol": clean_str(rec.get("proto")),
            "service": clean_str(rec.get("service")),
            "duration": safe_float(rec.get("duration")),
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "total_bytes": total_bytes,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
            "total_packets": total_packets,
            "bytes_per_packet": round(bytes_per_packet, 4),
            "connection_state": clean_str(rec.get("conn_state")),
            "missed_bytes": safe_int(rec.get("missed_bytes")),
        }
        features.append(feat)

    return features


def extract_dns_features(dns_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract structured features from dns.log records.

    Args:
        dns_records: Raw dictionaries parsed from dns.log.

    Returns:
        List of structured DNS feature dictionaries.
    """
    features: List[Dict[str, Any]] = []

    for rec in dns_records:
        raw_answers = rec.get("answers")
        answers: List[str] = []

        if raw_answers and raw_answers not in ("-", "(empty)"):
            if isinstance(raw_answers, list):
                answers = [str(a).strip() for a in raw_answers if str(a).strip() not in ("-", "")]
            else:
                answers = [
                    a.strip()
                    for a in str(raw_answers).split(",")
                    if a.strip() not in ("-", "")
                ]

        feat = {
            "uid": clean_str(rec.get("uid")),
            "timestamp": safe_float(rec.get("ts")),
            "source_ip": clean_str(rec.get("id.orig_h")),
            "destination_ip": clean_str(rec.get("id.resp_h")),
            "query": clean_str(rec.get("query")),
            "qtype_name": clean_str(rec.get("qtype_name")),
            "rcode_name": clean_str(rec.get("rcode_name")),
            "answers": answers,
            "answer_count": len(answers),
        }
        features.append(feat)

    return features


def extract_all_features(log_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Extract all features from loaded Zeek logs and compute overall summary statistics.

    Args:
        log_data: Dictionary mapping log types ('conn', 'dns', etc.) to raw records.

    Returns:
        Dictionary containing extracted connection features, DNS features, and summary stats.
    """
    conn_records = log_data.get("conn", [])
    dns_records = log_data.get("dns", [])

    conn_features = extract_connection_features(conn_records)
    dns_features = extract_dns_features(dns_records)

    source_ips: Set[str] = set()
    destination_ips: Set[str] = set()
    total_bytes_observed = 0
    total_packets_observed = 0

    proto_counter: Counter = Counter()
    service_counter: Counter = Counter()
    state_counter: Counter = Counter()

    for c in conn_features:
        if c["source_ip"]:
            source_ips.add(c["source_ip"])
        if c["destination_ip"]:
            destination_ips.add(c["destination_ip"])

        total_bytes_observed += c["total_bytes"]
        total_packets_observed += c["total_packets"]

        if c["protocol"]:
            proto_counter[c["protocol"]] += 1
        if c["service"]:
            service_counter[c["service"]] += 1
        if c["connection_state"]:
            state_counter[c["connection_state"]] += 1

    for d in dns_features:
        if d["source_ip"]:
            source_ips.add(d["source_ip"])
        if d["destination_ip"]:
            destination_ips.add(d["destination_ip"])

    summary = {
        "total_connections": len(conn_features),
        "total_dns_queries": len(dns_features),
        "unique_source_ips": len(source_ips),
        "unique_destination_ips": len(destination_ips),
        "total_bytes_observed": total_bytes_observed,
        "total_packets_observed": total_packets_observed,
        "protocols": dict(proto_counter),
        "services": dict(service_counter),
        "connection_states": dict(state_counter),
    }

    return {
        "connections": conn_features,
        "dns": dns_features,
        "summary": summary,
    }


# High-Level Numerical Matrix Extraction API (Person 2 - Phase 4)
from src.features.vector_assembler import (
    FeatureVectorAssembler,
    extract_feature_matrix,
)
from src.features.schema import FEATURE_COLUMNS, NUM_FEATURES
