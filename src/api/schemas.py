"""
Pydantic Schemas for UniDetect FastAPI REST API and WebSocket Events
"""

from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str = Field(..., example="ok")
    model_loaded: bool = Field(..., example=True)
    model_version: str = Field(..., example="unidetect-hgb-calibrated-v1.0.0")
    schema_version: str = Field(..., example="1.0.0")


class StatusResponse(BaseModel):
    """Overall system and pipeline status schema."""
    model_status: str = Field(..., example="LOADED_AND_ACTIVE")
    inference_status: str = Field(..., example="READY")
    pipeline_status: str = Field(..., example="PASSIVE_INGESTION_STANDBY")
    processed_flow_count: int = Field(..., example=655)
    alert_count: int = Field(..., example=457)
    analyst_review_count: int = Field(..., example=21)
    uptime_seconds: float = Field(..., example=120.5)


class AlertResponse(BaseModel):
    """Standardized threat detection alert event schema."""
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
    probabilities: dict[str, float]
    abstained: bool
    decision: str
    model_version: str
    schema_version: str
    processing_time_ms: float
    metadata: dict[str, Any] = Field(default_factory=dict)


class AlertsListResponse(BaseModel):
    """Paginated list of threat detection alerts."""
    total: int = Field(..., example=100)
    offset: int = Field(..., example=0)
    limit: int = Field(..., example=50)
    items: list[AlertResponse]


class MetricsResponse(BaseModel):
    """System inference performance and telemetry metrics."""
    total_flows: int = Field(..., example=655)
    total_predictions: int = Field(..., example=655)
    total_threats: int = Field(..., example=457)
    benign_count: int = Field(..., example=177)
    analyst_review_count: int = Field(..., example=21)
    per_class_counts: dict[str, int]
    average_inference_latency_ms: float = Field(..., example=15.8)
    p95_latency_ms: float = Field(..., example=19.9)


class ModelInfoResponse(BaseModel):
    """Metadata and feature contract specification for the active ML model."""
    model_version: str = Field(..., example="unidetect-hgb-calibrated-v1.0.0")
    model_type: str = Field(..., example="CalibratedClassifierCV(HistGradientBoostingClassifier, method='sigmoid')")
    feature_count: int = Field(..., example=78)
    schema_version: str = Field(..., example="1.0.0")
    calibration_method: str = Field(..., example="sigmoid")
    thresholds: dict[str, float]
    active_classes: list[str]


class DemoAlertIngestRequest(BaseModel):
    """
    Schema for controlled demo / replay telemetry ingestion into UniDetect backend.
    Accepts serialized AlertEvent representations produced by offline/replay inference.
    """
    alert_id: str = Field(..., description="Unique UUID for the alert event")
    flow_uid: str = Field(..., description="Zeek connection UID")
    timestamp: float = Field(..., description="UNIX epoch timestamp of the flow")
    timestamp_iso: str | None = Field(None, description="ISO-8601 UTC timestamp")
    source_ip: str = Field(..., description="Source IPv4/IPv6 address")
    destination_ip: str = Field(..., description="Destination IPv4/IPv6 address")
    source_port: int = Field(..., ge=0, le=65535, description="Source transport port")
    destination_port: int = Field(..., ge=0, le=65535, description="Destination transport port")
    protocol: str = Field(..., description="Transport protocol (e.g. tcp, udp, icmp)")
    predicted_class_id: int = Field(..., description="ML predicted integer class identifier")
    predicted_label: str = Field(..., description="ML predicted threat class label")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Calibrated confidence score (0.0 - 1.0)")
    probabilities: dict[str, float] = Field(default_factory=dict, description="Calibrated class probability distribution")
    abstained: bool = Field(..., description="Whether inference policy abstained (analyst review required)")
    decision: str = Field(..., description="Operational decision verdict (AUTOMATED_DETECTION | ANALYST_REVIEW | INFERENCE_ERROR)")
    model_version: str = Field(..., description="Version of the model that generated the inference")
    schema_version: str = Field(..., description="Feature schema contract version")
    processing_time_ms: float = Field(..., ge=0.0, description="Pipeline processing latency in milliseconds")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Flow summary metadata (duration, bytes, conn_state)")


class DecisionUpdateRequest(BaseModel):
    decision: str = Field(..., example="ANALYST_REVIEW", description="Updated triage decision (ANALYST_REVIEW | AUTOMATED_DETECTION | FALSE_POSITIVE)")


