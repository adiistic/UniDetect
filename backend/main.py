"""FastAPI application entry point for UniDetect Backend."""

from contextlib import asynccontextmanager
import time
import uuid
from typing import AsyncGenerator
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api.routes import router as api_v1_router
from backend.core.config import settings
from backend.core.errors import FeatureValidationError, ModelInferenceError, ModelNotLoadedError, UniDetectError
from backend.core.logging import logger
from backend.ml.loader import ModelLoader


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle management."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} in '{settings.ENVIRONMENT}' environment...")
    logger.info(f"Configured Model Provider: '{settings.MODEL_PROVIDER}' | Schema: '{settings.SCHEMA_VERSION}'")

    # Initialize model adapter safely at startup
    try:
        adapter = ModelLoader.get_adapter(settings, force_reload=True)
        if adapter.is_loaded():
            logger.info(f"Model successfully loaded via provider '{adapter.provider}' (Mock: {adapter.is_mock})")
        else:
            logger.warning(
                f"Model provider '{adapter.provider}' initialized but model artifact is not loaded. "
                "Backend will run in unready mode until the model artifact is available."
            )
    except Exception as e:
        logger.error(f"Error initializing model adapter on startup: {e}")

    yield

    logger.info("Shutting down UniDetect Backend...")


app = FastAPI(
    title="UniDetect - Network Threat Classification API",
    description=(
        "Production-grade defensive network-threat classification REST API. "
        "Enforces strict 78-dimensional network flow feature vectors and provides "
        "inference for 6 canonical threat classes (BENIGN, DDOS, RECON, SLOW_HTTP, "
        "DNS_TUNNEL, C2_BEACON)."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """Logs incoming requests with unique Request ID and tracks latency."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
    start_time = time.perf_counter()

    # Pass request ID in state
    request.state.request_id = request_id

    response = await call_next(request)

    latency_ms = (time.perf_counter() - start_time) * 1000
    response.headers["X-Request-ID"] = request_id

    # Avoid logging spam on health checks unless debug
    if request.url.path not in ["/api/v1/health", "/api/v1/readiness"] or settings.DEBUG:
        logger.info(
            f"[{request_id}] {request.method} {request.url.path} "
            f"-> {response.status_code} ({latency_ms:.2f}ms)"
        )

    return response


# --- Exception Handlers ---

@app.exception_handler(FeatureValidationError)
async def feature_validation_exception_handler(request: Request, exc: FeatureValidationError):
    """Handles 78-dimensional feature contract violations with HTTP 422."""
    logger.warning(f"Feature validation error: {exc.message}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": exc.code,
                "message": exc.message,
                "details": exc.details,
            }
        },
    )


@app.exception_handler(ModelNotLoadedError)
async def model_not_loaded_exception_handler(request: Request, exc: ModelNotLoadedError):
    """Handles requests when model is not loaded with HTTP 503."""
    logger.warning(f"Model not loaded: {exc.message}")
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "error": {
                "code": exc.code,
                "message": exc.message,
                "details": exc.details,
            }
        },
    )


@app.exception_handler(ModelInferenceError)
async def model_inference_exception_handler(request: Request, exc: ModelInferenceError):
    """Handles inference failures with HTTP 500 without leaking internals."""
    logger.error(f"Inference error: {exc.message}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": exc.code,
                "message": exc.message,
                "details": exc.details,
            }
        },
    )


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
    """Standardizes Pydantic input validation errors with HTTP 422."""
    error_messages = [f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}" for err in exc.errors()]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": "INVALID_REQUEST_BODY",
                "message": "Request payload failed schema validation.",
                "details": {"validation_errors": error_messages},
            }
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catches unhandled errors and ensures secrets/tracebacks are not leaked to clients."""
    logger.error(f"Unhandled server error on {request.url.path}: {exc}", exc_info=settings.DEBUG)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected internal server error occurred.",
            }
        },
    )


# Register API router
app.include_router(api_v1_router)


@app.get("/", include_in_schema=False)
async def root():
    """Root redirect / information endpoint."""
    return {
        "service": "UniDetect Network Threat Classification API",
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "openapi": "/openapi.json",
        "health": "/api/v1/health",
        "model_status": "/api/v1/model/status",
    }
