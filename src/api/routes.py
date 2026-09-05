"""
FastAPI REST API Routes for UniDetect Monitoring & Threat Alerting
"""

import csv
import io
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from src.api.dependencies import (
    get_alert_store,
    get_app_state,
    get_websocket_manager,
)
from src.api.schemas import (
    AlertResponse,
    AlertsListResponse,
    DecisionUpdateRequest,
    DemoAlertIngestRequest,
    HealthResponse,
    MetricsResponse,
    ModelInfoResponse,
    StatusResponse,
)
from src.api.state import AlertStore, AppState
from src.api.websocket import WebSocketManager
from src.features.schema import NUM_FEATURES, THREAT_CLASSES
from src.inference.alert import AlertEvent

router = APIRouter()

# Type aliases for FastAPI Annotated dependency injection
AppStateDep = Annotated[AppState, Depends(get_app_state)]
AlertStoreDep = Annotated[AlertStore, Depends(get_alert_store)]
WebSocketManagerDep = Annotated[WebSocketManager, Depends(get_websocket_manager)]


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health & Model Readiness Check",
    tags=["System"],
)
def get_health(app_state: AppStateDep) -> HealthResponse:
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
    app_state: AppStateDep,
    store: AlertStoreDep,
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
    store: AlertStoreDep,
    limit: int = Query(50, ge=1, le=500, description="Maximum number of alerts to return (1-500)"),
    offset: int = Query(0, ge=0, description="Offset index for pagination"),
    threat_class: str | None = Query(None, description="Optional class filter (e.g. DDOS, RECON, C2_BEACON, BENIGN)"),
    decision: str | None = Query(None, description="Optional decision filter (e.g. AUTOMATED_DETECTION, ANALYST_REVIEW)"),
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
    "/api/v1/alerts/export",
    summary="Export Alerts as CSV or JSON",
    tags=["Alerts"],
)
def export_alerts(
    store: AlertStoreDep,
    format: str = Query("csv", pattern="^(csv|json)$", description="Export file format: csv or json"),
    limit: int = Query(500, ge=1, le=2000, description="Max alerts to export"),
    threat_class: str | None = Query(None, description="Optional class filter"),
    decision: str | None = Query(None, description="Optional decision filter"),
) -> Response:
    """Exports filtered alert records as a downloadable CSV or JSON file."""
    items, _ = store.get_alerts(
        offset=0,
        limit=limit,
        class_filter=threat_class,
        decision_filter=decision,
    )

    if format == "json":
        import json
        payload = json.dumps([a.to_dict() for a in items], indent=2)
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=unidetect_alerts.json"},
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "alert_id", "timestamp_iso", "flow_uid", "source_ip", "source_port",
        "destination_ip", "destination_port", "protocol", "predicted_label",
        "confidence", "decision", "abstained", "processing_time_ms"
    ])
    for a in items:
        writer.writerow([
            a.alert_id,
            a.timestamp_iso,
            a.flow_uid,
            a.source_ip,
            a.source_port,
            a.destination_ip,
            a.destination_port,
            a.protocol,
            a.predicted_label,
            round(a.confidence, 4),
            a.decision,
            a.abstained,
            round(a.processing_time_ms, 2),
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=unidetect_alerts.csv"},
    )


@router.get(
    "/api/v1/alerts/{alert_id}",
    response_model=AlertResponse,
    summary="Get Detailed Alert by ID",
    tags=["Alerts"],
)
def get_alert_by_id(
    alert_id: str,
    store: AlertStoreDep,
) -> AlertResponse:
    """Retrieves a single threat detection alert record by its unique alert UUID."""
    alert = store.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found in active alert store.",
        )
    return AlertResponse(**alert.to_dict())


@router.patch(
    "/api/v1/alerts/{alert_id}/decision",
    response_model=AlertResponse,
    summary="Update Alert Triage Decision",
    tags=["Alerts"],
)
def update_alert_decision(
    alert_id: str,
    req: DecisionUpdateRequest,
    store: AlertStoreDep,
) -> AlertResponse:
    """Updates the triage decision verdict for an alert (e.g. sending to Analyst Review or dismissing FP)."""
    alert = store.update_alert_decision(alert_id, req.decision.strip().upper())
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
def get_metrics(store: AlertStoreDep) -> MetricsResponse:
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
def get_model_info(app_state: AppStateDep) -> ModelInfoResponse:
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


@router.post(
    "/api/v1/demo/alerts",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Controlled Demo & Replay Telemetry Ingestion",
    tags=["Demo"],
)
async def ingest_demo_alert(
    payload: DemoAlertIngestRequest,
    store: AlertStoreDep,
    ws_manager: WebSocketManagerDep,
) -> AlertResponse:
    """
    Controlled demo and replay telemetry ingestion endpoint.
    Safely receives pre-computed AlertEvent telemetry, stores it in the active AlertStore,
    updates system counters, and broadcasts the event over WebSocket to connected dashboard clients.
    Preserves passive security: performs no active packet transmission or network probing.
    """
    alert = AlertEvent.from_dict(payload.model_dump())
    store.add_alert(alert)
    await ws_manager.broadcast_alert(alert)
    return AlertResponse(**alert.to_dict())


@router.post(
    "/api/v1/alerts/clear",
    summary="Clear All In-Memory Alerts & Reset Telemetry",
    tags=["Alerts"],
)
def clear_all_alerts(
    store: AlertStoreDep,
) -> dict[str, str]:
    """
    Clears all in-memory alerts and resets all telemetry counters (flows, threats, reviews)
    back to clean initial state.
    """
    store.clear()
    return {"status": "ok", "message": "Alert store and telemetry reset to zero"}
