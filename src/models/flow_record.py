"""
FlowRecord Model for UniDetect

Defines clean, structured Data Transfer Objects (DTOs) for normalized
network connection flows extracted from Zeek conn.log records.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict


def _safe_int(val: Any, default: int = 0) -> int:
    """Safely parse integer value from raw Zeek field."""
    if val is None or val in ("-", "(empty)", ""):
        return default
    try:
        return int(float(str(val).strip()))
    except (ValueError, TypeError):
        return default


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Safely parse float value from raw Zeek field."""
    if val is None or val in ("-", "(empty)", ""):
        return default
    try:
        return float(str(val).strip())
    except (ValueError, TypeError):
        return default


def _clean_str(val: Any, default: str = "") -> str:
    """Clean string values by removing Zeek placeholders like '-' or '(empty)'."""
    if val is None or val in ("-", "(empty)"):
        return default
    return str(val).strip()


@dataclass
class Endpoint:
    """Represents a network IP and port endpoint."""

    ip: str
    port: int


@dataclass
class NetworkContext:
    """Represents network transport protocol and application service context."""

    protocol: str
    service: str


@dataclass
class FlowMetrics:
    """Represents quantitative traffic volume metrics for a connection flow."""

    duration: float
    orig_bytes: int
    resp_bytes: int
    total_bytes: int
    orig_packets: int
    resp_packets: int
    total_packets: int
    bytes_per_packet: float
    missed_bytes: int


@dataclass
class FlowRecord:
    """Normalized network flow record representing a Zeek connection (conn.log)."""

    timestamp: float
    uid: str
    source: Endpoint
    destination: Endpoint
    network: NetworkContext
    metrics: FlowMetrics
    connection_state: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert FlowRecord and nested dataclasses into a plain Python dictionary."""
        return asdict(self)


# Explicit primary normalized keys used in conn.log parsing
EXPLICIT_CONN_KEYS = {
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "conn_state",
    "missed_bytes",
}


def normalize_conn_record(record: Dict[str, Any]) -> FlowRecord:
    """Safely normalize a raw Zeek conn.log record into a structured FlowRecord DTO.

    Handles missing fields, '-' / '(empty)' placeholders, invalid numbers, and zero-packet states safely.
    Preserves all additional raw Zeek fields in the metadata dictionary.

    Args:
        record: Raw dictionary representing a single conn.log entry.

    Returns:
        Instantiated FlowRecord object.
    """
    ts = _safe_float(record.get("ts"))
    uid = _clean_str(record.get("uid"))

    source = Endpoint(
        ip=_clean_str(record.get("id.orig_h")),
        port=_safe_int(record.get("id.orig_p")),
    )
    destination = Endpoint(
        ip=_clean_str(record.get("id.resp_h")),
        port=_safe_int(record.get("id.resp_p")),
    )

    network = NetworkContext(
        protocol=_clean_str(record.get("proto")),
        service=_clean_str(record.get("service")),
    )

    duration = _safe_float(record.get("duration"))
    orig_bytes = _safe_int(record.get("orig_bytes"))
    resp_bytes = _safe_int(record.get("resp_bytes"))
    total_bytes = orig_bytes + resp_bytes

    orig_packets = _safe_int(record.get("orig_pkts"))
    resp_packets = _safe_int(record.get("resp_pkts"))
    total_packets = orig_packets + resp_packets

    bytes_per_packet = (
        round(float(total_bytes) / total_packets, 4) if total_packets > 0 else 0.0
    )
    missed_bytes = _safe_int(record.get("missed_bytes"))

    metrics = FlowMetrics(
        duration=duration,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
        total_bytes=total_bytes,
        orig_packets=orig_packets,
        resp_packets=resp_packets,
        total_packets=total_packets,
        bytes_per_packet=bytes_per_packet,
        missed_bytes=missed_bytes,
    )

    connection_state = _clean_str(record.get("conn_state"))

    # Preserve additional Zeek fields in metadata
    raw_metadata = {
        k: v for k, v in record.items() if k not in EXPLICIT_CONN_KEYS
    }

    return FlowRecord(
        timestamp=ts,
        uid=uid,
        source=source,
        destination=destination,
        network=network,
        metrics=metrics,
        connection_state=connection_state,
        metadata=raw_metadata,
    )
