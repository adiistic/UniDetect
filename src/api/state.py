"""
Thread-Safe In-Memory State & Bounded Alert Storage for UniDetect Backend
"""

import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any

import numpy as np

from src.api.storage import SQLiteAlertStorage
from src.inference.alert import AlertEvent
from src.inference.pipeline import RealtimeInferencePipeline

DEFAULT_STORE_CAPACITY = 2000


class AlertStore:
    """
    Thread-safe in-memory ring buffer backed by SQLite storage for persistent AlertEvents.
    Provides fast indexed lookups by alert ID, filtering by threat class / decision verdict,
    automatic bounded eviction in RAM, and permanent audit logging in SQLite.
    """

    def __init__(
        self,
        max_capacity: int = DEFAULT_STORE_CAPACITY,
        storage: SQLiteAlertStorage | None = None,
    ) -> None:
        self.max_capacity = max(1, int(max_capacity))
        self.storage = storage
        self._lock = threading.Lock()
        self._alerts_deque: deque[AlertEvent] = deque(maxlen=self.max_capacity)
        self._alerts_by_id: dict[str, AlertEvent] = {}
        self._class_counts: Counter[str] = Counter()
        self._total_flows: int = 0
        self._total_threats: int = 0
        self._benign_count: int = 0
        self._analyst_reviews: int = 0
        self._latencies_ms: deque[float] = deque(maxlen=self.max_capacity)

        # Preload persisted records on startup if storage is available
        if self.storage:
            persisted = self.storage.load_recent_alerts(limit=self.max_capacity)
            for alert in persisted:
                self._alerts_deque.append(alert)
                self._alerts_by_id[alert.alert_id] = alert
                self._total_flows += 1
                self._class_counts[alert.predicted_label] += 1
                self._latencies_ms.append(alert.processing_time_ms)
                if alert.abstained or alert.decision == "ANALYST_REVIEW":
                    self._analyst_reviews += 1
                elif alert.predicted_label == "BENIGN" or alert.decision == "FALSE_POSITIVE":
                    self._benign_count += 1
                else:
                    self._total_threats += 1

    def add_alert(self, alert: AlertEvent) -> None:
        """Adds a new AlertEvent to the bounded store, updates telemetry counters, and persists to SQLite."""
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

        if self.storage:
            try:
                self.storage.save_alert(alert)
            except Exception as e:
                # Failure in persistence should not crash the real-time inference loop
                pass

    def get_alerts(
        self,
        offset: int = 0,
        limit: int = 50,
        class_filter: str | None = None,
        decision_filter: str | None = None,
    ) -> tuple[list[AlertEvent], int]:
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

    def get_alert_by_id(self, alert_id: str) -> AlertEvent | None:
        """Retrieves a single AlertEvent by its UUID."""
        with self._lock:
            return self._alerts_by_id.get(alert_id)

    def get_metrics(self) -> dict[str, Any]:
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

    def update_alert_decision(self, alert_id: str, new_decision: str) -> AlertEvent | None:
        """
        Updates the triage decision verdict of an alert (e.g. ANALYST_REVIEW, AUTOMATED_DETECTION, FALSE_POSITIVE).
        Thread-safely adjusts telemetry counters and returns the updated AlertEvent.
        """
        with self._lock:
            alert = self._alerts_by_id.get(alert_id)
            if not alert:
                return None

            old_decision = alert.decision
            old_abstained = alert.abstained
            if old_decision == new_decision:
                return alert

            # Adjust prior counter allocations
            if old_abstained or old_decision == "ANALYST_REVIEW":
                self._analyst_reviews = max(0, self._analyst_reviews - 1)
            elif old_decision == "AUTOMATED_DETECTION" and alert.predicted_label != "BENIGN":
                self._total_threats = max(0, self._total_threats - 1)

            # Apply new decision and adjust counters
            alert.decision = new_decision
            if new_decision == "ANALYST_REVIEW":
                alert.abstained = True
                self._analyst_reviews += 1
            elif new_decision == "AUTOMATED_DETECTION":
                alert.abstained = False
                if alert.predicted_label != "BENIGN":
                    self._total_threats += 1
            elif new_decision == "FALSE_POSITIVE":
                alert.abstained = False
                self._benign_count += 1

        if self.storage:
            try:
                self.storage.update_decision(alert_id, old_decision, new_decision)
            except Exception:
                pass

        return alert

    def clear(self) -> None:
        """Clears all stored alerts and resets telemetry counters in memory and SQLite."""
        with self._lock:
            self._alerts_deque.clear()
            self._alerts_by_id.clear()
            self._class_counts.clear()
            self._total_flows = 0
            self._total_threats = 0
            self._benign_count = 0
            self._analyst_reviews = 0
            self._latencies_ms.clear()

        if self.storage:
            try:
                self.storage.clear()
            except Exception:
                pass


class AppState:
    """Singleton application state holding the alert store, inference pipeline, and runtime metadata."""

    def __init__(
        self,
        model_dir: str | Path | None = None,
        store_capacity: int = DEFAULT_STORE_CAPACITY,
        db_path: str | Path | None = None,
    ) -> None:
        self.start_time = time.time()
        self.storage = SQLiteAlertStorage(db_path=db_path)
        self.alert_store = AlertStore(max_capacity=store_capacity, storage=self.storage)
        try:
            self.pipeline = RealtimeInferencePipeline(model_dir=model_dir)
            self.model_loaded = True
            self.model_error: str | None = None
        except Exception as e:  # noqa: BLE001
            self.pipeline = None
            self.model_loaded = False
            self.model_error = str(e)

    @property
    def uptime_seconds(self) -> float:
        """Returns application uptime in seconds."""
        return round(time.time() - self.start_time, 2)
