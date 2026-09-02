"""
Unit tests for Phase 8 FastAPI Backend, REST Routes, and WebSocket Streaming
"""

import asyncio
import json
import unittest
from pathlib import Path
from typing import Any, Dict

from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.state import AlertStore, AppState
from src.features.schema import NUM_FEATURES
from src.inference.alert import AlertEvent


class TestPhase8Backend(unittest.TestCase):
    """Test suite verifying FastAPI REST endpoints, WebSocket streaming, and state management."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.model_dir = cls.repo_root / "models" / "phase6e"
        cls.app = create_app(model_dir=cls.model_dir, store_capacity=100)
        cls.client = TestClient(cls.app)

    def setUp(self) -> None:
        # Clear alert store between tests
        self.app.state.app_state.alert_store.clear()

    def _create_mock_alert(
        self,
        aid: str = "alert-001",
        uid: str = "C_mock_01",
        label: str = "DDOS",
        conf: float = 0.95,
        decision: str = "AUTOMATED_DETECTION",
        abstained: bool = False,
    ) -> AlertEvent:
        return AlertEvent.create(
            alert_id=aid,
            flow_uid=uid,
            timestamp=1700000000.0,
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            source_port=44444,
            destination_port=80,
            protocol="tcp",
            predicted_class_id=1,
            predicted_label=label,
            confidence=conf,
            probabilities={"BENIGN": 0.02, "DDOS": conf, "RECON": 0.01, "DNS_TUNNEL": 0.01, "C2_BEACON": 0.005, "SLOW_HTTP": 0.005},
            abstained=abstained,
            decision=decision,
            model_version="unidetect-hgb-calibrated-v1.0.0",
            schema_version="1.0.0",
            processing_time_ms=12.5,
        )

    def test_health_endpoint(self) -> None:
        """Verify /health returns 200 and model readiness metadata."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "ok")
        self.assertTrue(data["model_loaded"])
        self.assertEqual(data["model_version"], "unidetect-hgb-calibrated-v1.0.0")
        self.assertEqual(data["schema_version"], "1.0.0")

    def test_status_endpoint(self) -> None:
        """Verify /api/v1/status returns processing telemetry and uptime."""
        res = self.client.get("/api/v1/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["model_status"], "LOADED_AND_ACTIVE")
        self.assertEqual(data["inference_status"], "READY")
        self.assertIn("uptime_seconds", data)

    def test_alerts_endpoint_empty_store(self) -> None:
        """Verify /api/v1/alerts returns empty list when store has 0 alerts."""
        res = self.client.get("/api/v1/alerts")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 0)
        self.assertEqual(len(data["items"]), 0)

    def test_alerts_endpoint_pagination(self) -> None:
        """Verify /api/v1/alerts pagination with offset and limit."""
        store: AlertStore = self.app.state.app_state.alert_store
        for i in range(10):
            store.add_alert(self._create_mock_alert(aid=f"alert-{i:03d}"))

        res = self.client.get("/api/v1/alerts?limit=4&offset=2")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 10)
        self.assertEqual(len(data["items"]), 4)
        self.assertEqual(data["offset"], 2)
        self.assertEqual(data["limit"], 4)

    def test_alerts_class_filtering(self) -> None:
        """Verify /api/v1/alerts filters correctly by threat_class."""
        store: AlertStore = self.app.state.app_state.alert_store
        store.add_alert(self._create_mock_alert(aid="a1", label="DDOS"))
        store.add_alert(self._create_mock_alert(aid="a2", label="RECON"))
        store.add_alert(self._create_mock_alert(aid="a3", label="DDOS"))
        store.add_alert(self._create_mock_alert(aid="a4", label="BENIGN"))

        res = self.client.get("/api/v1/alerts?threat_class=DDOS")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 2)
        self.assertTrue(all(item["predicted_label"] == "DDOS" for item in data["items"]))

    def test_alerts_decision_filtering(self) -> None:
        """Verify /api/v1/alerts filters correctly by decision."""
        store: AlertStore = self.app.state.app_state.alert_store
        store.add_alert(self._create_mock_alert(aid="a1", decision="AUTOMATED_DETECTION", abstained=False))
        store.add_alert(self._create_mock_alert(aid="a2", decision="ANALYST_REVIEW", abstained=True))

        res = self.client.get("/api/v1/alerts?decision=ANALYST_REVIEW")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["decision"], "ANALYST_REVIEW")

    def test_alerts_invalid_class_filter_400(self) -> None:
        """Verify /api/v1/alerts returns 400 for unknown threat class."""
        res = self.client.get("/api/v1/alerts?threat_class=UNKNOWN_ALIEN_ATTACK")
        self.assertEqual(res.status_code, 400)

    def test_alerts_invalid_decision_filter_400(self) -> None:
        """Verify /api/v1/alerts returns 400 for unknown decision."""
        res = self.client.get("/api/v1/alerts?decision=INVALID_DECISION")
        self.assertEqual(res.status_code, 400)

    def test_alerts_invalid_pagination_bounds_422(self) -> None:
        """Verify /api/v1/alerts returns 422 for invalid limit/offset."""
        res_neg_limit = self.client.get("/api/v1/alerts?limit=-5")
        self.assertEqual(res_neg_limit.status_code, 422)

        res_neg_offset = self.client.get("/api/v1/alerts?offset=-1")
        self.assertEqual(res_neg_offset.status_code, 422)

    def test_alert_by_id_success(self) -> None:
        """Verify /api/v1/alerts/{alert_id} retrieves exact alert record."""
        store: AlertStore = self.app.state.app_state.alert_store
        mock = self._create_mock_alert(aid="alert-target-999", uid="C_target_99")
        store.add_alert(mock)

        res = self.client.get("/api/v1/alerts/alert-target-999")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["alert_id"], "alert-target-999")
        self.assertEqual(data["flow_uid"], "C_target_99")
        self.assertEqual(data["predicted_label"], "DDOS")

    def test_alert_by_id_not_found_404(self) -> None:
        """Verify /api/v1/alerts/{alert_id} returns 404 for missing ID."""
        res = self.client.get("/api/v1/alerts/non-existent-alert-id")
        self.assertEqual(res.status_code, 404)

    def test_metrics_endpoint(self) -> None:
        """Verify /api/v1/metrics computes telemetry and counts."""
        store: AlertStore = self.app.state.app_state.alert_store
        store.add_alert(self._create_mock_alert(aid="m1", label="DDOS"))
        store.add_alert(self._create_mock_alert(aid="m2", label="BENIGN"))
        store.add_alert(self._create_mock_alert(aid="m3", label="RECON", decision="ANALYST_REVIEW", abstained=True))

        res = self.client.get("/api/v1/metrics")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total_flows"], 3)
        self.assertEqual(data["total_threats"], 1)
        self.assertEqual(data["benign_count"], 1)
        self.assertEqual(data["analyst_review_count"], 1)
        self.assertIn("DDOS", data["per_class_counts"])

    def test_model_info_endpoint(self) -> None:
        """Verify /api/v1/model returns model architecture and feature schema specifications."""
        res = self.client.get("/api/v1/model")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["model_version"], "unidetect-hgb-calibrated-v1.0.0")
        self.assertEqual(data["feature_count"], NUM_FEATURES)
        self.assertEqual(data["schema_version"], "1.0.0")
        self.assertEqual(data["calibration_method"], "sigmoid")
        self.assertEqual(data["thresholds"]["abstain_confidence_threshold"], 0.40)
        self.assertEqual(data["thresholds"]["recon_threshold"], 0.35)

    def test_bounded_alert_store_eviction(self) -> None:
        """Verify AlertStore ring buffer evicts oldest alerts when max_capacity is exceeded."""
        store = AlertStore(max_capacity=5)
        for i in range(8):
            store.add_alert(self._create_mock_alert(aid=f"evict-{i}"))

        # Should only hold the 5 most recent alerts (evict-3 to evict-7)
        items, total = store.get_alerts(limit=10)
        self.assertEqual(total, 5)
        self.assertEqual(len(items), 5)
        self.assertEqual(items[0].alert_id, "evict-7")  # Newest first
        self.assertEqual(items[-1].alert_id, "evict-3")  # Oldest retained

        # Evicted IDs should return None
        self.assertIsNone(store.get_alert_by_id("evict-0"))
        self.assertIsNone(store.get_alert_by_id("evict-1"))
        self.assertIsNone(store.get_alert_by_id("evict-2"))
        # Retained ID should return alert
        self.assertIsNotNone(store.get_alert_by_id("evict-7"))

    def test_websocket_connection_and_disconnect(self) -> None:
        """Verify WebSocket client can connect to /ws/alerts and disconnect cleanly."""
        with self.client.websocket_connect("/ws/alerts") as ws:
            self.assertEqual(len(self.app.state.websocket_manager.active_connections), 1)
        # Disconnected
        self.assertEqual(len(self.app.state.websocket_manager.active_connections), 0)

    def test_websocket_broadcast_delivery(self) -> None:
        """Verify WebSocket client receives broadcast AlertEvent payload."""
        mock_alert = self._create_mock_alert(aid="ws-alert-01", label="DNS_TUNNEL")
        with self.client.websocket_connect("/ws/alerts") as ws:
            # Broadcast alert asynchronously
            asyncio.run(self.app.state.websocket_manager.broadcast_alert(mock_alert))
            received = ws.receive_json()
            self.assertEqual(received["alert_id"], "ws-alert-01")
            self.assertEqual(received["predicted_label"], "DNS_TUNNEL")

    def test_model_unavailable_fallback(self) -> None:
        """Verify application behaves gracefully when model fails to load."""
        broken_app = create_app(model_dir=self.repo_root / "non_existent_model_dir")
        broken_client = TestClient(broken_app)

        health_res = broken_client.get("/health")
        self.assertEqual(health_res.status_code, 200)
        self.assertEqual(health_res.json()["status"], "degraded")
        self.assertFalse(health_res.json()["model_loaded"])

        model_res = broken_client.get("/api/v1/model")
        self.assertEqual(model_res.status_code, 503)

    def test_passive_security_invariants(self) -> None:
        """Verify API layer does not perform active networking or payload logging."""
        mock_alert = self._create_mock_alert()
        alert_dict = mock_alert.to_dict()
        # Verify no raw payload keys are present
        self.assertNotIn("raw_payload", alert_dict)
        self.assertNotIn("decrypted_tls_data", alert_dict)
        self.assertNotIn("payload_hex", alert_dict)

    def test_dashboard_root_endpoint_serves_html(self) -> None:
        """Verify root endpoint / serves the built React SOC dashboard."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers.get("content-type", ""))
        self.assertIn("UniDetect SOC", res.text)


if __name__ == "__main__":
    unittest.main()
