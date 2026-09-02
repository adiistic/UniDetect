"""
UniDetect FastAPI Backend Package (Phase 8)
"""

from src.api.app import create_app, app
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
    "create_app",
    "app",
    "AlertStore",
    "AppState",
    "WebSocketManager",
    "HealthResponse",
    "StatusResponse",
    "AlertResponse",
    "AlertsListResponse",
    "MetricsResponse",
    "ModelInfoResponse",
]
