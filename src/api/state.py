"""
Thread-Safe In-Memory State & Bounded Alert Storage for UniDetect Backend
"""

import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

from src.features.schema import THREAT_CLASSES
from src.inference.alert import AlertEvent
from src.inference.pipeline import RealtimeInferencePipeline

DEFAULT_STORE_CAPACITY = 2000


class AlertStore:
    """
    Thread-safe, bounded in-memory ring buffer storing recent AlertEvents.
    Provides fast indexed lookups by alert ID, filtering by threat class / decision verdict,
    and automatic bounded eviction to prevent memory growth during long-running sessions.
    """

    def __init__(self, max_capacity: int = DEFAULT_STORE_CAPACITY) -> None:
        self.max_capacity = max(1, int(max_capacity))
        self._lock = threading.Lock()
        self._alerts_deque: deque[AlertEvent] = deque(maxlen=self.max_capacity)
        self._alerts_by_id: Dict[str, AlertEvent] = {}
        self._class_counts: Counter[str] = Counter()
        self._total_flows: int = 0
        self._total_threats: int = 0
        self._benign_count: int = 0
        self._analyst_reviews: int = 0
        self._latencies_ms: deque[float] = deque(maxlen=self.max_capacity)

    def add_alert(self, alert: AlertEvent) -> None:
        """Adds a new AlertEvent to the bounded store and updates telemetry counters."""
        with self._lock:
            # Handle eviction from by_id index if at max capacity
            if len(self._alerts_deque) == self.max_capacity:
                oldest = self._alerts_deque[0]
                self._alerts_by_id.pop(oldest.alert_id, None)

            self._alerts_deque.append(alert)
            self._alerts_by_id[alert.alert_id] = alert

            self._total_flows += 1
            self._class_counts[alert.predicted_label] += 1
            self._latencies_ms.append(alert.processing_time_ms)

            if alert.abstained:
                self._analyst_reviews += 1
            elif alert.predicted_label == "BENIGN":
                self._benign_count += 1
            else:
                self._total_threats += 1

    def get_alerts(
        self,
        offset: int = 0,
        limit: int = 50,
        class_filter: Optional[str] = None,
        decision_filter: Optional[str] = None,
    ) -> Tuple[List[AlertEvent], int]:
        """
        Retrieves a paginated list of alerts in reverse chronological order (newest first).

        Returns:
            Tuple of (items, total_filtered_count)
        """
        with self._lock:
            # Create list copy for thread safety (reverse chronological)
            all_alerts = list(self._alerts_deque)[::-1]

            filtered = all_alerts
            if class_filter:
                cf = class_filter.strip().upper()
                filtered = [a for a in filtered if a.predicted_label == cf]

            if decision_filter:
                df = decision_filter.strip().upper()
                filtered = [a for a in filtered if a.decision == df]

            total_filtered = len(filtered)
            paginated = filtered[offset : offset + limit]
            return paginated, total_filtered

    def get_alert_by_id(self, alert_id: str) -> Optional[AlertEvent]:
        """Retrieves a single AlertEvent by its UUID."""
        with self._lock:
            return self._alerts_by_id.get(alert_id)

    def get_metrics(self) -> Dict[str, Any]:
        """Computes current telemetry metrics and latency percentiles."""
        with self._lock:
            lats = np.array(self._latencies_ms) if self._latencies_ms else np.array([0.0])
            mean_lat = round(float(np.mean(lats)), 3)
            p95_lat = round(float(np.percentile(lats, 95)), 3)

            return {
                "total_flows": self._total_flows,
                "total_predictions": self._total_flows,
                "total_threats": self._total_threats,
                "benign_count": self._benign_count,
                "analyst_review_count": self._analyst_reviews,
                "per_class_counts": dict(self._class_counts),
                "average_inference_latency_ms": mean_lat,
                "p95_latency_ms": p95_lat,
            }

    def clear(self) -> None:
        """Clears all stored alerts and resets telemetry counters."""
        with self._lock:
            self._alerts_deque.clear()
            self._alerts_by_id.clear()
            self._class_counts.clear()
            self._total_flows = 0
            self._total_threats = 0
            self._benign_count = 0
            self._analyst_reviews = 0
            self._latencies_ms.clear()


class AppState:
    """Singleton application state holding the alert store, inference pipeline, and runtime metadata."""

    def __init__(
        self,
        model_dir: Optional[Union[str, Path]] = None,
        store_capacity: int = DEFAULT_STORE_CAPACITY,
    ) -> None:
        self.start_time = time.time()
        self.alert_store = AlertStore(max_capacity=store_capacity)
        try:
            self.pipeline = RealtimeInferencePipeline(model_dir=model_dir)
            self.model_loaded = True
            self.model_error: Optional[str] = None
        except Exception as e:
            self.pipeline = None
            self.model_loaded = False
            self.model_error = str(e)

    @property
    def uptime_seconds(self) -> float:
        """Returns application uptime in seconds."""
        return round(time.time() - self.start_time, 2)
