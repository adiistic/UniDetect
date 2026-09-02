"""
FastAPI Dependency Providers for UniDetect State & Services
"""

from typing import Optional
from fastapi import Request

from src.api.state import AlertStore, AppState
from src.api.websocket import WebSocketManager
from src.inference.pipeline import RealtimeInferencePipeline


def get_app_state(request: Request) -> AppState:
    """Retrieves the global AppState instance from the FastAPI application."""
    return request.app.state.app_state


def get_alert_store(request: Request) -> AlertStore:
    """Retrieves the thread-safe AlertStore instance from AppState."""
    return request.app.state.app_state.alert_store


def get_inference_pipeline(request: Request) -> Optional[RealtimeInferencePipeline]:
    """Retrieves the active RealtimeInferencePipeline instance from AppState."""
    return request.app.state.app_state.pipeline


def get_websocket_manager(request: Request) -> WebSocketManager:
    """Retrieves the WebSocketManager instance from the FastAPI application."""
    return request.app.state.websocket_manager
