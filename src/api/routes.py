"""
FastAPI REST API Routes for UniDetect Monitoring & Threat Alerting
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from src.api.dependencies import get_alert_store, get_app_state, get_inference_pipeline
from src.api.schemas import (
    AlertResponse,
    AlertsListResponse,
    HealthResponse,
    MetricsResponse,
    ModelInfoResponse,
    StatusResponse,
)
from src.api.state import AlertStore, AppState
from src.features.schema import NUM_FEATURES, THREAT_CLASSES
from src.inference.pipeline import RealtimeInferencePipeline

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health & Model Readiness Check",
    tags=["System"],
)
def get_health(app_state: AppState = Depends(get_app_state)) -> HealthResponse:
    """Returns the operational health and model loading readiness of the UniDetect backend."""
    model_version = "unknown"
    schema_version = "1.0.0"

    if app_state.pipeline and app_state.pipeline.detector:
        model_version = app_state.pipeline.detector.model_version
        schema_version = app_state.pipeline.detector.schema_version

    return HealthResponse(
        status="ok" if app_state.model_loaded else "degraded",
        model_loaded=app_state.model_loaded,
        model_version=model_version,
        schema_version=schema_version,
    )


@router.get(
    "/api/v1/status",
    response_model=StatusResponse,
    summary="Overall Pipeline Telemetry & Uptime Status",
    tags=["System"],
)
def get_status(
    app_state: AppState = Depends(get_app_state),
    store: AlertStore = Depends(get_alert_store),
) -> StatusResponse:
    """Returns real-time processing counts, model state, and uptime telemetry."""
    metrics = store.get_metrics()
    return StatusResponse(
        model_status="LOADED_AND_ACTIVE" if app_state.model_loaded else "UNAVAILABLE",
        inference_status="READY" if app_state.model_loaded else "ERROR",
        pipeline_status="PASSIVE_INGESTION_READY",
        processed_flow_count=metrics["total_flows"],
        alert_count=metrics["total_threats"],
        analyst_review_count=metrics["analyst_review_count"],
        uptime_seconds=app_state.uptime_seconds,
    )


@router.get(
    "/api/v1/alerts",
    response_model=AlertsListResponse,
    summary="Paginated Threat Alerts Stream",
    tags=["Alerts"],
)
def get_alerts(
    limit: int = Query(50, ge=1, le=500, description="Maximum number of alerts to return (1-500)"),
    offset: int = Query(0, ge=0, description="Offset index for pagination"),
    threat_class: Optional[str] = Query(None, description="Optional class filter (e.g. DDOS, RECON, C2_BEACON, BENIGN)"),
    decision: Optional[str] = Query(None, description="Optional decision filter (e.g. AUTOMATED_DETECTION, ANALYST_REVIEW)"),
    store: AlertStore = Depends(get_alert_store),
) -> AlertsListResponse:
    """Returns a paginated list of recently observed threat alerts in reverse chronological order."""
    if threat_class:
        valid_classes = [c.upper() for c in THREAT_CLASSES]
        if threat_class.strip().upper() not in valid_classes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid threat class '{threat_class}'. Must be one of: {valid_classes}",
            )

    if decision:
        valid_decisions = ["AUTOMATED_DETECTION", "ANALYST_REVIEW", "INFERENCE_ERROR"]
        if decision.strip().upper() not in valid_decisions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid decision filter '{decision}'. Must be one of: {valid_decisions}",
            )

    items, total = store.get_alerts(
        offset=offset,
        limit=limit,
        class_filter=threat_class,
        decision_filter=decision,
    )

    return AlertsListResponse(
        total=total,
        offset=offset,
        limit=limit,
        items=[AlertResponse(**a.to_dict()) for a in items],
    )


@router.get(
    "/api/v1/alerts/{alert_id}",
    response_model=AlertResponse,
    summary="Get Detailed Alert by ID",
    tags=["Alerts"],
)
def get_alert_by_id(
    alert_id: str,
    store: AlertStore = Depends(get_alert_store),
) -> AlertResponse:
    """Retrieves a single threat detection alert record by its unique alert UUID."""
    alert = store.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found in active alert store.",
        )
    return AlertResponse(**alert.to_dict())


@router.get(
    "/api/v1/metrics",
    response_model=MetricsResponse,
    summary="Inference Latency & Class Distribution Metrics",
    tags=["Metrics"],
)
def get_metrics(store: AlertStore = Depends(get_alert_store)) -> MetricsResponse:
    """Returns aggregate flow counters, threat distribution, and inference latency percentiles."""
    m = store.get_metrics()
    return MetricsResponse(
        total_flows=m["total_flows"],
        total_predictions=m["total_predictions"],
        total_threats=m["total_threats"],
        benign_count=m["benign_count"],
        analyst_review_count=m["analyst_review_count"],
        per_class_counts=m["per_class_counts"],
        average_inference_latency_ms=m["average_inference_latency_ms"],
        p95_latency_ms=m["p95_latency_ms"],
    )


@router.get(
    "/api/v1/model",
    response_model=ModelInfoResponse,
    summary="Frozen ML Model & Feature Contract Specification",
    tags=["Model"],
)
def get_model_info(app_state: AppState = Depends(get_app_state)) -> ModelInfoResponse:
    """Returns technical specifications for the active frozen ML model and decision policy."""
    if not app_state.pipeline or not app_state.pipeline.detector:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML Model inference engine is not currently loaded.",
        )

    detector = app_state.pipeline.detector
    policy = detector.policy

    return ModelInfoResponse(
        model_version=detector.model_version,
        model_type="CalibratedClassifierCV(HistGradientBoostingClassifier, method='sigmoid', cv=3)",
        feature_count=NUM_FEATURES,
        schema_version=detector.schema_version,
        calibration_method="sigmoid",
        thresholds={
            "abstain_confidence_threshold": policy.abstain_threshold,
            "recon_threshold": policy.recon_threshold,
        },
        active_classes=policy.classes,
    )
