"""
UniDetect Multi-Log Correlator (Person 2 - Phase 4)

Provides high-performance in-memory indexing to correlate conn.log / FlowRecord
instances with event logs (dns.log, weird.log, quic.log, ssl.log) via UID and IP endpoints.
"""

from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple, Union

from src.models.flow_record import FlowRecord, normalize_conn_record


class LogCorrelator:
    """Indexes and correlates heterogeneous Zeek log entries for unified feature extraction."""

    def __init__(self, log_data: Optional[Dict[str, List[Dict[str, Any]]]] = None) -> None:
        """Initialize LogCorrelator.

        Args:
            log_data: Optional dictionary mapping log type ('conn', 'dns', etc.) to parsed records.
        """
        # Primary index: UID -> { "dns": dict, "weird": [dict], "quic": dict, "ssl": dict }
        self.by_uid: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"dns": None, "weird": [], "quic": None, "ssl": None}
        )

        # Host-level secondary indices for window and context queries
        self.dns_by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.weird_by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.weird_by_pair: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)

        # Stored normalized flow records
        self.flows: List[FlowRecord] = []

        if log_data:
            self.index_all(log_data)

    def index_all(self, log_data: Dict[str, List[Dict[str, Any]]]) -> None:
        """Index all log records from a loaded log dictionary."""
        # 1. Index DNS records
        for d in log_data.get("dns", []):
            uid = str(d.get("uid", "")).strip()
            if uid and uid not in ("-", "(empty)"):
                self.by_uid[uid]["dns"] = d
            src_ip = str(d.get("id.orig_h", "")).strip()
            if src_ip and src_ip not in ("-", "(empty)"):
                self.dns_by_src[src_ip].append(d)

        # 2. Index QUIC records
        for q in log_data.get("quic", []):
            uid = str(q.get("uid", "")).strip()
            if uid and uid not in ("-", "(empty)"):
                self.by_uid[uid]["quic"] = q

        # 3. Index Weird records (can be multiple anomalies per UID)
        for w in log_data.get("weird", []):
            uid = str(w.get("uid", "")).strip()
            if uid and uid not in ("-", "(empty)"):
                self.by_uid[uid]["weird"].append(w)
            src_ip = str(w.get("id.orig_h", "")).strip()
            dst_ip = str(w.get("id.resp_h", "")).strip()
            if src_ip and src_ip not in ("-", "(empty)"):
                self.weird_by_src[src_ip].append(w)
                if dst_ip and dst_ip not in ("-", "(empty)"):
                    self.weird_by_pair[(src_ip, dst_ip)].append(w)

        # 4. Index SSL records (when available)
        for s in log_data.get("ssl", []):
            uid = str(s.get("uid", "")).strip()
            if uid and uid not in ("-", "(empty)"):
                self.by_uid[uid]["ssl"] = s

        # 5. Ingest and normalize connection flows
        raw_conn = log_data.get("conn", [])
        for c in raw_conn:
            if isinstance(c, FlowRecord):
                self.flows.append(c)
            elif isinstance(c, dict):
                self.flows.append(normalize_conn_record(c))

    def get_dns_for_flow(self, flow: Union[FlowRecord, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Retrieve correlated DNS record for a connection flow by UID."""
        uid = flow.uid if isinstance(flow, FlowRecord) else str(flow.get("uid", ""))
        return self.by_uid.get(uid, {}).get("dns")

    def get_quic_for_flow(self, flow: Union[FlowRecord, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Retrieve correlated QUIC record for a connection flow by UID."""
        uid = flow.uid if isinstance(flow, FlowRecord) else str(flow.get("uid", ""))
        return self.by_uid.get(uid, {}).get("quic")

    def get_weird_for_flow(self, flow: Union[FlowRecord, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Retrieve correlated weird.log anomaly records for a connection flow by UID."""
        uid = flow.uid if isinstance(flow, FlowRecord) else str(flow.get("uid", ""))
        return self.by_uid.get(uid, {}).get("weird", [])

    def get_ssl_for_flow(self, flow: Union[FlowRecord, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Retrieve correlated ssl.log record for a connection flow by UID."""
        uid = flow.uid if isinstance(flow, FlowRecord) else str(flow.get("uid", ""))
        return self.by_uid.get(uid, {}).get("ssl")
