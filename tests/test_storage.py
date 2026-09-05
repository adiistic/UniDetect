"""
Unit tests for SQLiteAlertStorage and Alert Export Endpoint
"""

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.storage import SQLiteAlertStorage
from src.inference.alert import AlertEvent


class TestSQLiteStorage(unittest.TestCase):
    """Test suite for SQLiteAlertStorage operations and persistence."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_alerts.db"
        self.storage = SQLiteAlertStorage(db_path=self.db_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _sample_alert(self, aid: str = "test-001", label: str = "DDOS", decision: str = "AUTOMATED_DETECTION") -> AlertEvent:
        return AlertEvent.create(
            flow_uid=f"uid-{aid}",
            timestamp=1700000000.0,
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            source_port=54321,
            destination_port=80,
            protocol="TCP",
            predicted_class_id=1,
            predicted_label=label,
            confidence=0.95,
            probabilities={"BENIGN": 0.05, "DDOS": 0.95},
            abstained=(decision == "ANALYST_REVIEW"),
            decision=decision,
            model_version="test-v1",
            schema_version="1.0.0",
            processing_time_ms=1.23,
            metadata={"conn_state": "SF"},
        )

    def test_save_and_load_alert(self) -> None:
        alert = self._sample_alert("a1")
        self.storage.save_alert(alert)

        loaded = self.storage.load_recent_alerts(limit=10)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].alert_id, alert.alert_id)
        self.assertEqual(loaded[0].predicted_label, "DDOS")
        self.assertEqual(loaded[0].decision, "AUTOMATED_DETECTION")

    def test_update_decision_and_audit(self) -> None:
        alert = self._sample_alert("a2", decision="AUTOMATED_DETECTION")
        self.storage.save_alert(alert)

        ok = self.storage.update_decision(alert.alert_id, "AUTOMATED_DETECTION", "FALSE_POSITIVE", notes="Analyst confirmed benign")
        self.assertTrue(ok)

        loaded = self.storage.load_recent_alerts(limit=10)
        self.assertEqual(loaded[0].decision, "FALSE_POSITIVE")
        self.assertFalse(loaded[0].abstained)

    def test_clear_storage(self) -> None:
        self.storage.save_alert(self._sample_alert("a3"))
        self.storage.clear()
        self.assertEqual(len(self.storage.load_recent_alerts()), 0)


class TestExportEndpoint(unittest.TestCase):
    """Test suite verifying CSV and JSON alert exports."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.model_dir = cls.repo_root / "models" / "phase6e"
        cls.app = create_app(model_dir=cls.model_dir, store_capacity=50)
        cls.client = TestClient(cls.app)

    def setUp(self) -> None:
        self.app.state.app_state.alert_store.clear()

    def test_export_csv_and_json(self) -> None:
        # Ingest a demo alert
        alert = AlertEvent.create(
            flow_uid="uid-exp-01",
            timestamp=1700000000.0,
            source_ip="192.168.1.50",
            destination_ip="10.0.0.5",
            source_port=12345,
            destination_port=443,
            protocol="TCP",
            predicted_class_id=2,
            predicted_label="RECON",
            confidence=0.88,
            probabilities={"BENIGN": 0.12, "RECON": 0.88},
            abstained=False,
            decision="AUTOMATED_DETECTION",
            model_version="v1",
            schema_version="1.0.0",
            processing_time_ms=2.5,
        )
        self.app.state.app_state.alert_store.add_alert(alert)

        # 1. Test CSV export
        csv_res = self.client.get("/api/v1/alerts/export?format=csv")
        self.assertEqual(csv_res.status_code, 200)
        self.assertIn("text/csv", csv_res.headers["content-type"])
        self.assertIn("RECON", csv_res.text)
        self.assertIn("192.168.1.50", csv_res.text)

        # 2. Test JSON export
        json_res = self.client.get("/api/v1/alerts/export?format=json")
        self.assertEqual(json_res.status_code, 200)
        data = json_res.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["predicted_label"], "RECON")


if __name__ == "__main__":
    unittest.main()
