"""FastAPI route handlers for UniDetect threat classification API."""

from fastapi import APIRouter, Depends
from backend.api.schemas import (
    BatchPredictRequest,
    BatchPredictResponse,
    HealthResponse,
    ModelStatusResponse,
    PredictRequest,
    PredictResponse,
    ReadinessResponse,
)
from backend.services.inference_service import InferenceService

router = APIRouter(prefix="/api/v1", tags=["Threat Classification"])


def get_inference_service() -> InferenceService:
    """Dependency injection provider for InferenceService."""
    return InferenceService()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness Probe",
    description="Returns service status to indicate whether the backend process is running.",
)
async def health_check(
    service: InferenceService = Depends(get_inference_service)
) -> HealthResponse:
    """Checks if the backend process is healthy."""
    return HealthResponse(
        status="ok",
        service="unidetect-backend",
        model_loaded=service.is_ready(),
    )


@router.get(
    "/readiness",
    response_model=ReadinessResponse,
    summary="Readiness Probe",
    description="Indicates whether the backend is ready to perform model inference.",
)
async def readiness_check(
    service: InferenceService = Depends(get_inference_service)
) -> ReadinessResponse:
    """Checks if the model is ready to serve inference requests."""
    is_ready = service.is_ready()
    provider = service.adapter.provider

    if is_ready:
        return ReadinessResponse(
            ready=True,
            status="READY",
            reason=None,
            provider=provider,
        )
    return ReadinessResponse(
        ready=False,
        status="NOT_READY",
        reason="Model artifact is not loaded. If running in local mode, model file has not yet been placed.",
        provider=provider,
    )


@router.get(
    "/model/status",
    response_model=ModelStatusResponse,
    summary="Model Status & Metadata",
    description="Returns detailed status, provider type, schema version, and metadata of the active model.",
)
async def model_status(
    service: InferenceService = Depends(get_inference_service)
) -> ModelStatusResponse:
    """Returns the metadata and status of the current ML model without exposing any secrets."""
    status_dict = service.get_model_status()
    return ModelStatusResponse(
        loaded=status_dict["loaded"],
        provider=status_dict["provider"],
        is_mock=status_dict["is_mock"],
        model_name=status_dict["model_name"],
        model_version=status_dict["model_version"],
        schema_version=status_dict["schema_version"],
        feature_count=status_dict["feature_count"],
        metadata=status_dict["metadata"],
    )


@router.post(
    "/predict",
    response_model=PredictResponse,
    summary="Single Sample Prediction",
    description="Classifies a single network traffic sample. Accepts exactly 78 numerical features.",
)
async def predict_single(
    request: PredictRequest,
    service: InferenceService = Depends(get_inference_service)
) -> PredictResponse:
    """Executes network threat classification on a single 78-dimensional feature vector."""
    result = service.predict_single(request.features)
    return PredictResponse(**result)


@router.post(
    "/predict/batch",
    response_model=BatchPredictResponse,
    summary="Batch Sample Prediction",
    description="Classifies multiple network traffic samples in a single batch request.",
)
async def predict_batch(
    request: BatchPredictRequest,
    service: InferenceService = Depends(get_inference_service)
) -> BatchPredictResponse:
    """Executes network threat classification on multiple 78-dimensional feature vectors."""
    raw_samples = [item.features for item in request.samples]
    result = service.predict_batch(raw_samples)
    return BatchPredictResponse(**result)
