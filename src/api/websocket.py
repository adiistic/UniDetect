"""
Asynchronous WebSocket Manager for Streaming Alert Events to Dashboard Clients
"""

import asyncio
import logging
from typing import Any, Dict, List, Set

from fastapi import WebSocket
from src.inference.alert import AlertEvent

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Manages active WebSocket subscriber connections and broadcasts standardized
    AlertEvent JSON messages to connected dashboards and analysts without blocking
    inference execution or stalling on slow network clients.
    """

    def __init__(self) -> None:
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accepts a new WebSocket connection and adds it to the active subscribers."""
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Total subscribers: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket) -> None:
        """Removes a disconnected WebSocket from the active subscribers."""
        async with self._lock:
            self.active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Total subscribers: {len(self.active_connections)}")

    async def broadcast_json(self, data: Dict[str, Any]) -> None:
        """Broadcasts a raw JSON dictionary to all connected subscribers concurrently."""
        if not self.active_connections:
            return

        async with self._lock:
            connections = list(self.active_connections)

        dead_connections: List[WebSocket] = []

        async def send_to_client(ws: WebSocket):
            try:
                await ws.send_json(data)
            except Exception as e:
                logger.debug(f"Failed to send to WebSocket client: {e}")
                dead_connections.append(ws)

        # Broadcast concurrently across all active clients
        await asyncio.gather(*(send_to_client(ws) for ws in connections), return_exceptions=True)

        if dead_connections:
            async with self._lock:
                for dead_ws in dead_connections:
                    self.active_connections.discard(dead_ws)

    async def broadcast_alert(self, alert: AlertEvent) -> None:
        """Broadcasts an AlertEvent object to all connected subscribers."""
        await self.broadcast_json(alert.to_dict())
