"""
Unit tests for Phase 7 Real-Time Inference & Streaming Pipeline
"""

import math
import unittest
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

from src.features.schema import FEATURE_COLUMNS, NUM_FEATURES
from src.inference.alert import AlertEvent
from src.inference.pipeline import RealtimeInferencePipeline
from src.models.flow_record import FlowRecord, normalize_conn_record


class TestPhase7StreamingPipeline(unittest.TestCase):
    """Test suite verifying end-to-end passive streaming inference, alert emission, and replay."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.model_dir = cls.repo_root / "models" / "phase6e"
        cls.pipeline = RealtimeInferencePipeline(model_dir=cls.model_dir)

    def setUp(self) -> None:
        self.pipeline.reset_state()

    def _create_mock_conn(self, uid: str = "Cmock001", ts: float = 1700000000.0, proto: str = "tcp", duration: float = 0.5) -> Dict[str, Any]:
        return {
            "ts": ts,
            "uid": uid,
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 49152,
            "id.resp_h": "192.168.1.100",
            "id.resp_p": 80,
            "proto": proto,
            "service": "http",
            "duration": duration,
            "orig_bytes": 250,
            "resp_bytes": 1200,
            "conn_state": "SF",
            "local_orig": "T",
            "local_resp": "T",
            "missed_bytes": 0,
            "history": "ShADadFf",
            "orig_pkts": 5,
            "orig_ip_bytes": 450,
            "resp_pkts": 7,
            "resp_ip_bytes": 1480,
        }

    def test_flow_record_to_feature_vector(self) -> None:
        """Verify FlowRecord correctly transforms into 78D vector."""
        raw_conn = self._create_mock_conn()
        flow = normalize_conn_record(raw_conn)
        vec = self.pipeline.assembler.assemble_for_flow(flow)

        self.assertEqual(len(vec), NUM_FEATURES)
        self.assertFalse(any(math.isnan(x) for x in vec))
        self.assertFalse(any(math.isinf(x) for x in vec))

    def test_feature_vector_to_frozen_model_inference(self) -> None:
        """Verify assembled feature vector produces valid calibrated probabilities."""
        raw_conn = self._create_mock_conn()
        flow = normalize_conn_record(raw_conn)
        vec = self.pipeline.assembler.assemble_for_flow(flow)
        verdict = self.pipeline.detector.predict_single(vec)

        self.assertIn("predicted_class_id", verdict)
        self.assertIn("predicted_label", verdict)
        self.assertIn("probabilities", verdict)
        self.assertAlmostEqual(sum(verdict["probabilities"].values()), 1.0, places=2)

    def test_standardized_alert_event_structure(self) -> None:
        """Verify process_flow produces a complete, standardized AlertEvent."""
        raw_conn = self._create_mock_conn(uid="C_alert_test_01")
        alert = self.pipeline.process_flow(raw_conn)

        self.assertIsInstance(alert, AlertEvent)
        self.assertEqual(alert.flow_uid, "C_alert_test_01")
        self.assertEqual(alert.source_ip, "192.168.1.10")
        self.assertEqual(alert.destination_ip, "192.168.1.100")
        self.assertEqual(alert.source_port, 49152)
        self.assertEqual(alert.destination_port, 80)
        self.assertEqual(alert.protocol, "tcp")
        self.assertEqual(alert.model_version, "unidetect-hgb-calibrated-v1.0.0")
        self.assertEqual(alert.schema_version, "1.0.0")
        self.assertGreater(alert.processing_time_ms, 0.0)
        self.assertIn("T", alert.timestamp_iso)  # ISO timestamp format check

        # Serialization test
        alert_dict = alert.to_dict()
        self.assertIsInstance(alert_dict, dict)
        self.assertEqual(alert_dict["flow_uid"], "C_alert_test_01")

    def test_missing_optional_event_context(self) -> None:
        """Verify flow with zero DNS/SSL/Weird context still produces valid inference."""
        raw_conn = self._create_mock_conn(uid="C_no_aux_context")
        # Ensure no auxiliary logs are indexed
        alert = self.pipeline.process_flow(raw_conn)

        self.assertNotEqual(alert.decision, "INFERENCE_ERROR")
        self.assertIn(alert.predicted_label, ["BENIGN", "DDOS", "RECON", "DNS_TUNNEL", "C2_BEACON", "SLOW_HTTP"])

    def test_nan_inf_error_handling(self) -> None:
        """Verify pipeline handles corrupted numerical inputs safely without crashing."""
        raw_conn = self._create_mock_conn()
        raw_conn["duration"] = float("nan")

        alert = self.pipeline.process_flow(raw_conn)
        # Safe float conversion in FlowRecord/vector_assembler converts NaN duration to default (0.0)
        self.assertIsInstance(alert, AlertEvent)
        self.assertFalse(math.isnan(alert.confidence))

    def test_duplicate_uid_resilience(self) -> None:
        """Verify processing duplicate UIDs does not cause pipeline corruption."""
        raw_conn = self._create_mock_conn(uid="C_duplicate_001")
        alert1 = self.pipeline.process_flow(raw_conn)
        alert2 = self.pipeline.process_flow(raw_conn)

        self.assertEqual(alert1.predicted_label, alert2.predicted_label)
        self.assertEqual(self.pipeline.total_flows_processed, 2)

    def test_causal_sliding_window_progression(self) -> None:
        """Verify sequential flows update lookback rates and counts in chronological order."""
        t0 = 1700000000.0
        # Flow 1 at t0
        a1 = self.pipeline.process_flow(self._create_mock_conn(uid="C_time_01", ts=t0))
        # Flow 2 at t0 + 2.0s from same source
        a2 = self.pipeline.process_flow(self._create_mock_conn(uid="C_time_02", ts=t0 + 2.0))
        # Flow 3 at t0 + 4.0s from same source
        a3 = self.pipeline.process_flow(self._create_mock_conn(uid="C_time_03", ts=t0 + 4.0))

        # Check window aggregator holds 3 flows
        self.assertEqual(len(self.pipeline.window_aggregator.flows), 3)

    def test_deterministic_repeated_inference(self) -> None:
        """Verify two identical pipelines produce identical predictions."""
        raw_conn = self._create_mock_conn(uid="C_deterministic")
        p1 = RealtimeInferencePipeline(model_dir=self.model_dir)
        p2 = RealtimeInferencePipeline(model_dir=self.model_dir)

        alert1 = p1.process_flow(raw_conn)
        alert2 = p2.process_flow(raw_conn)

        self.assertEqual(alert1.predicted_label, alert2.predicted_label)
        self.assertEqual(alert1.confidence, alert2.confidence)
        self.assertEqual(alert1.probabilities, alert2.probabilities)

    def test_replay_benign_periodic_traffic(self) -> None:
        """Replay exp_benign_periodic_007 and verify 0 false alarms."""
        exp_dir = self.repo_root / "data/experiments/BENIGN/exp_benign_periodic_007/zeek"
        if not exp_dir.exists():
            self.skipTest(f"Experiment dir {exp_dir} not found")

        alerts, perf = self.pipeline.replay_directory(exp_dir)
        self.assertEqual(perf["total_flows_processed"], 63)
        self.assertEqual(perf["threats_detected"], 0)
        self.assertEqual(perf["benign_flows"], 63)
        self.assertEqual(perf["inference_errors"], 0)

    def test_replay_ddos_syn_traffic(self) -> None:
        """Replay exp_ddos_syn_001 and verify threat detection."""
        exp_dir = self.repo_root / "data/experiments/DDOS/exp_ddos_syn_001/zeek"
        if not exp_dir.exists():
            self.skipTest(f"Experiment dir {exp_dir} not found")

        alerts, perf = self.pipeline.replay_directory(exp_dir)
        self.assertEqual(perf["total_flows_processed"], 150)
        self.assertEqual(perf["threats_detected"], 150)
        self.assertEqual(perf["benign_flows"], 0)

    def test_replay_c2_beacon_traffic(self) -> None:
        """Replay exp_c2_beacon_001 and verify C2 threat detection."""
        exp_dir = self.repo_root / "data/experiments/C2_BEACON/exp_c2_beacon_001/zeek"
        if not exp_dir.exists():
            self.skipTest(f"Experiment dir {exp_dir} not found")

        alerts, perf = self.pipeline.replay_directory(exp_dir)
        self.assertEqual(perf["total_flows_processed"], 50)
        self.assertEqual(perf["threats_detected"], 50)

    def test_replay_slow_http_traffic(self) -> None:
        """Replay exp_slow_http_001 and verify Slow HTTP threat detection."""
        exp_dir = self.repo_root / "data/experiments/SLOW_HTTP/exp_slow_http_001/zeek"
        if not exp_dir.exists():
            self.skipTest(f"Experiment dir {exp_dir} not found")

        alerts, perf = self.pipeline.replay_directory(exp_dir)
        self.assertEqual(perf["total_flows_processed"], 50)
        self.assertEqual(perf["threats_detected"], 50)

    def test_replay_dns_tunnel_traffic(self) -> None:
        """Replay exp_dns_tunnel_001 and verify DNS tunnel threat detection."""
        exp_dir = self.repo_root / "data/experiments/DNS_TUNNEL/exp_dns_tunnel_001/zeek"
        if not exp_dir.exists():
            self.skipTest(f"Experiment dir {exp_dir} not found")

        alerts, perf = self.pipeline.replay_directory(exp_dir)
        self.assertEqual(perf["total_flows_processed"], 52)
        self.assertGreater(perf["threats_detected"], 40)

    def test_replay_recon_traffic(self) -> None:
        """Replay exp_recon_001 and verify Recon threat detection."""
        exp_dir = self.repo_root / "data/experiments/RECON/exp_recon_001/zeek"
        if not exp_dir.exists():
            self.skipTest(f"Experiment dir {exp_dir} not found")

        alerts, perf = self.pipeline.replay_directory(exp_dir)
        self.assertEqual(perf["total_flows_processed"], 59)
        self.assertGreater(perf["threats_detected"], 50)

    def test_attach_to_live_pipeline_callback(self) -> None:
        """Verify attaching inference pipeline to live pipeline invokes alert callbacks."""
        received_alerts: List[AlertEvent] = []

        class MockLivePipeline:
            def poll_once(self) -> Dict[str, Any]:
                return {
                    "logs": {
                        "conn": [
                            {
                                "ts": 1700000001.0,
                                "uid": "C_live_cb_01",
                                "id.orig_h": "10.0.0.5",
                                "id.orig_p": 50000,
                                "id.resp_h": "10.0.0.1",
                                "id.resp_p": 80,
                                "proto": "tcp",
                                "duration": 0.05,
                                "orig_bytes": 100,
                                "resp_bytes": 200,
                                "conn_state": "SF",
                                "history": "ShAD",
                            }
                        ]
                    }
                }

        mock_live = MockLivePipeline()
        poll_fn = self.pipeline.attach_to_live_pipeline(mock_live, alert_callback=lambda a: received_alerts.append(a))
        emitted = poll_fn()

        self.assertEqual(len(emitted), 1)
        self.assertEqual(len(received_alerts), 1)
        self.assertEqual(received_alerts[0].flow_uid, "C_live_cb_01")


if __name__ == "__main__":
    unittest.main()
