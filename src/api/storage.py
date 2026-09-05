"""
SQLite-Backed Persistent Storage for UniDetect Alerts and SOC Triage Audit Logs
"""

import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional

from src.inference.alert import AlertEvent

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "unidetect_alerts.db"


class SQLiteAlertStorage:
    """
    Thread-safe SQLite storage manager for persisting AlertEvent records,
    historical SOC threat telemetry, and human analyst mitigation decisions.
    """

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initializes database schema with indexing for fast chronological and filtered queries."""
        with self._lock, self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    flow_uid TEXT,
                    timestamp REAL NOT NULL,
                    timestamp_iso TEXT,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    destination_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    predicted_class_id INTEGER,
                    predicted_label TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    probabilities_json TEXT,
                    abstained INTEGER NOT NULL,
                    decision TEXT NOT NULL,
                    model_version TEXT,
                    schema_version TEXT,
                    processing_time_ms REAL,
                    metadata_json TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS triage_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    old_decision TEXT,
                    new_decision TEXT NOT NULL,
                    notes TEXT,
                    FOREIGN KEY (alert_id) REFERENCES alerts (alert_id)
                )
                """
            )
            # Create indexes for fast query filtering and sorting
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_label ON alerts (predicted_label)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_decision ON alerts (decision)")
            conn.commit()

    def save_alert(self, alert: AlertEvent) -> None:
        """Persists a single AlertEvent to SQLite (insert or replace on conflict)."""
        probs_json = json.dumps(alert.probabilities) if alert.probabilities else "{}"
        meta_json = json.dumps(alert.metadata) if alert.metadata else "{}"

        query = """
            INSERT OR REPLACE INTO alerts (
                alert_id, flow_uid, timestamp, timestamp_iso,
                source_ip, destination_ip, source_port, destination_port, protocol,
                predicted_class_id, predicted_label, confidence, probabilities_json,
                abstained, decision, model_version, schema_version,
                processing_time_ms, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            alert.alert_id,
            alert.flow_uid,
            alert.timestamp,
            alert.timestamp_iso,
            alert.source_ip,
            alert.destination_ip,
            alert.source_port,
            alert.destination_port,
            alert.protocol,
            alert.predicted_class_id,
            alert.predicted_label,
            alert.confidence,
            probs_json,
            1 if alert.abstained else 0,
            alert.decision,
            alert.model_version,
            alert.schema_version,
            alert.processing_time_ms,
            meta_json,
        )

        with self._lock, self._connection() as conn:
            conn.execute(query, params)
            conn.commit()

    def update_decision(
        self, alert_id: str, old_decision: str, new_decision: str, notes: str = ""
    ) -> bool:
        """Updates the triage decision for an alert and logs the audit trail."""
        now = time.time()
        with self._lock, self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE alerts SET decision = ?, abstained = ? WHERE alert_id = ?",
                (new_decision, 1 if new_decision == "ANALYST_REVIEW" else 0, alert_id),
            )
            if cursor.rowcount == 0:
                return False

            cursor.execute(
                """
                INSERT INTO triage_audit (alert_id, timestamp, old_decision, new_decision, notes)
                VALUES (?, ?, ?, ?, ?)
                """,
                (alert_id, now, old_decision, new_decision, notes),
            )
            conn.commit()
            return True

    def load_recent_alerts(self, limit: int = 2000) -> list[AlertEvent]:
        """Loads recent alerts in chronological order (oldest to newest) to populate the in-memory buffer."""
        query = """
            SELECT * FROM (
                SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?
            ) ORDER BY timestamp ASC
        """
        alerts: list[AlertEvent] = []
        with self._lock, self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            for row in rows:
                alerts.append(self._row_to_alert(row))
        return alerts

    def clear(self) -> None:
        """Clears all stored alerts and audit logs."""
        with self._lock, self._connection() as conn:
            conn.execute("DELETE FROM triage_audit")
            conn.execute("DELETE FROM alerts")
            conn.commit()

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> AlertEvent:
        probs = json.loads(row["probabilities_json"]) if row["probabilities_json"] else {}
        meta = json.loads(row["metadata_json"]) if row["metadata_json"] else {}

        return AlertEvent(
            alert_id=row["alert_id"],
            flow_uid=row["flow_uid"] or "",
            timestamp=row["timestamp"],
            timestamp_iso=row["timestamp_iso"] or "",
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            source_port=row["source_port"],
            destination_port=row["destination_port"],
            protocol=row["protocol"],
            predicted_class_id=row["predicted_class_id"] or 0,
            predicted_label=row["predicted_label"],
            confidence=row["confidence"],
            probabilities=probs,
            abstained=bool(row["abstained"]),
            decision=row["decision"],
            model_version=row["model_version"] or "v1.0.0",
            schema_version=row["schema_version"] or "1.0.0",
            processing_time_ms=row["processing_time_ms"] or 0.0,
            metadata=meta,
        )
