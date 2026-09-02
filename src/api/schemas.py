"""
Pydantic Schemas for UniDetect FastAPI REST API and WebSocket Events
"""

from typing import Any, Dict, List, Optional
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
    probabilities: Dict[str, float]
    abstained: bool
    decision: str
    model_version: str
    schema_version: str
    processing_time_ms: float
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AlertsListResponse(BaseModel):
    """Paginated list of threat detection alerts."""
    total: int = Field(..., example=100)
    offset: int = Field(..., example=0)
    limit: int = Field(..., example=50)
    items: List[AlertResponse]


class MetricsResponse(BaseModel):
    """System inference performance and telemetry metrics."""
    total_flows: int = Field(..., example=655)
    total_predictions: int = Field(..., example=655)
    total_threats: int = Field(..., example=457)
    benign_count: int = Field(..., example=177)
    analyst_review_count: int = Field(..., example=21)
    per_class_counts: Dict[str, int]
    average_inference_latency_ms: float = Field(..., example=15.8)
    p95_latency_ms: float = Field(..., example=19.9)


class ModelInfoResponse(BaseModel):
    """Metadata and feature contract specification for the active ML model."""
    model_version: str = Field(..., example="unidetect-hgb-calibrated-v1.0.0")
    model_type: str = Field(..., example="CalibratedClassifierCV(HistGradientBoostingClassifier, method='sigmoid')")
    feature_count: int = Field(..., example=78)
    schema_version: str = Field(..., example="1.0.0")
    calibration_method: str = Field(..., example="sigmoid")
    thresholds: Dict[str, float]
    active_classes: List[str]
