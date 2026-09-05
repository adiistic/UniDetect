"""
UniDetect FastAPI Backend Package (Phase 8)
"""

from src.api.app import app, create_app
from src.api.schemas import (
    AlertResponse,
    AlertsListResponse,
    HealthResponse,
    MetricsResponse,
    ModelInfoResponse,
    StatusResponse,
)
from src.api.state import AlertStore, AppState
from src.api.websocket import WebSocketManager

__all__ = [
    "AlertResponse",
    "AlertStore",
    "AlertsListResponse",
    "AppState",
    "HealthResponse",
    "MetricsResponse",
    "ModelInfoResponse",
    "StatusResponse",
    "WebSocketManager",
    "app",
    "create_app",
]
