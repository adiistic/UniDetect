"""
FastAPI Application Factory & WebSocket Stream for UniDetect
"""

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional, Union

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from src.api.routes import router
from src.api.state import AppState, DEFAULT_STORE_CAPACITY
from src.api.websocket import WebSocketManager
from src.inference.alert import AlertEvent

logger = logging.getLogger(__name__)


def create_app(
    model_dir: Optional[Union[str, Path]] = None,
    store_capacity: int = DEFAULT_STORE_CAPACITY,
) -> FastAPI:
    """
    Application factory for the UniDetect FastAPI backend.
    Initializes thread-safe in-memory state, loads the frozen ML pipeline,
    and configures REST and WebSocket endpoints.
    """
    app_state = AppState(model_dir=model_dir, store_capacity=store_capacity)
    ws_manager = WebSocketManager()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup logic
        logger.info("Starting UniDetect Backend Server...")
        logger.info(f"Model status: {'Loaded' if app_state.model_loaded else 'Failed to Load'}")
        yield
        # Shutdown logic
        logger.info("Shutting down UniDetect Backend Server...")

    app = FastAPI(
        title="UniDetect Passive Threat Detection API",
        description=(
            "REST API and WebSocket streaming interface for UniDetect — passive network threat detection "
            "powered by calibrated machine learning and Zeek telemetry."
        ),
        version="1.0.0",
        lifespan=lifespan,
    )

    # Attach State and WebSocket Manager to App Instance
    app.state.app_state = app_state
    app.state.websocket_manager = ws_manager

    # Configure CORS for Dashboard Integration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount REST Routes
    app.include_router(router)

    # Mount WebSocket Stream Endpoint
    @app.websocket("/ws/alerts")
    async def websocket_alerts_stream(websocket: WebSocket) -> None:
        """
        WebSocket endpoint streaming real-time threat alert events to dashboard subscribers.
        Receives external alert payloads and broadcasts them to all active subscribers.
        """
        await ws_manager.connect(websocket)
        try:
            while True:
                data_text = await websocket.receive_text()
                try:
                    data = json.loads(data_text)
                    if isinstance(data, dict) and "alert_id" in data:
                        alert = AlertEvent.from_dict(data)
                        app_state.alert_store.add_alert(alert)
                        await ws_manager.broadcast_json(data)
                except Exception as ex:
                    logger.debug(f"Error parsing incoming WebSocket message: {ex}")
        except WebSocketDisconnect:
            await ws_manager.disconnect(websocket)
        except Exception as e:
            logger.debug(f"WebSocket client error: {e}")
            await ws_manager.disconnect(websocket)

    # Mount Built Frontend Static Assets (if available)
    frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
    if frontend_dist.exists() and (frontend_dist / "index.html").exists():
        app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")

    return app


# Default Application Instance for Uvicorn
app = create_app()
