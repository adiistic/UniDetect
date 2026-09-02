"""
Standardized Alert Schema and Event Representation for UniDetect
"""

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class AlertEvent:
    """
    Standardized passive threat detection alert event emitted by UniDetect.
    Encapsulates flow-level telemetry, calibrated class probabilities,
    operational decision verdicts, and execution performance metrics
    without exposing raw packet payloads or decrypted payloads.
    """
    alert_id: str
    flow_uid: str
    timestamp: float
    timestamp_iso: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    predicted_class_id: int
    predicted_label: str
    confidence: float
    probabilities: Dict[str, float]
    abstained: bool
    decision: str  # "AUTOMATED_DETECTION" | "ANALYST_REVIEW" | "INFERENCE_ERROR"
    model_version: str
    schema_version: str
    processing_time_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        flow_uid: str,
        timestamp: float,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: str,
        predicted_class_id: int,
        predicted_label: str,
        confidence: float,
        probabilities: Dict[str, float],
        abstained: bool,
        decision: str,
        model_version: str,
        schema_version: str,
        processing_time_ms: float,
        metadata: Optional[Dict[str, Any]] = None,
        alert_id: Optional[str] = None,
    ) -> "AlertEvent":
        """Factory constructor creating an AlertEvent with deterministic ID and ISO timestamp."""
        aid = alert_id or str(uuid.uuid4())
        ts_iso = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        return cls(
            alert_id=aid,
            flow_uid=flow_uid,
            timestamp=float(timestamp),
            timestamp_iso=ts_iso,
            source_ip=str(source_ip),
            destination_ip=str(destination_ip),
            source_port=int(source_port),
            destination_port=int(destination_port),
            protocol=str(protocol).lower(),
            predicted_class_id=int(predicted_class_id),
            predicted_label=str(predicted_label),
            confidence=round(float(confidence), 4),
            probabilities={k: round(float(v), 4) for k, v in probabilities.items()},
            abstained=bool(abstained),
            decision=str(decision),
            model_version=str(model_version),
            schema_version=str(schema_version),
            processing_time_ms=round(float(processing_time_ms), 3),
            metadata=metadata or {},
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AlertEvent":
        """Reconstructs an AlertEvent from a serialized dictionary representation."""
        ts = float(data["timestamp"])
        ts_iso = data.get("timestamp_iso")
        if not ts_iso:
            ts_iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

        return cls(
            alert_id=str(data["alert_id"]),
            flow_uid=str(data["flow_uid"]),
            timestamp=ts,
            timestamp_iso=str(ts_iso),
            source_ip=str(data["source_ip"]),
            destination_ip=str(data["destination_ip"]),
            source_port=int(data["source_port"]),
            destination_port=int(data["destination_port"]),
            protocol=str(data["protocol"]).lower(),
            predicted_class_id=int(data["predicted_class_id"]),
            predicted_label=str(data["predicted_label"]),
            confidence=round(float(data["confidence"]), 4),
            probabilities={str(k): round(float(v), 4) for k, v in data.get("probabilities", {}).items()},
            abstained=bool(data["abstained"]),
            decision=str(data["decision"]),
            model_version=str(data["model_version"]),
            schema_version=str(data["schema_version"]),
            processing_time_ms=round(float(data["processing_time_ms"]), 3),
            metadata=data.get("metadata") or {},
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes alert event into a clean dictionary."""
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serializes alert event into a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @property
    def is_threat(self) -> bool:
        """Returns True if the flow was classified as a threat and not abstained."""
        return self.predicted_label != "BENIGN" and not self.abstained and self.decision == "AUTOMATED_DETECTION"
