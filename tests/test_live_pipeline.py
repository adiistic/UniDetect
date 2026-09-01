"""
Unit tests for LiveZeekPipeline (src/ingestion/live_pipeline.py)
"""

import tempfile
import unittest
from pathlib import Path

from src.ingestion.checkpoint import CheckpointManager
from src.ingestion.live_pipeline import LiveZeekPipeline
from src.models.flow_record import FlowRecord


class TestLiveZeekPipeline(unittest.TestCase):
    """Test suite verifying LiveZeekPipeline coordination and flow record generation."""

    def setUp(self) -> None:
        """Create temporary test directories for logs and checkpoints."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_dir_path = Path(self.test_dir.name).resolve()
        self.log_dir = self.test_dir_path / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_file = self.test_dir_path / "checkpoint.json"
        self.checkpoint_manager = CheckpointManager(self.checkpoint_file)

    def tearDown(self) -> None:
        """Clean up temporary test directory."""
        self.test_dir.cleanup()

    def test_pipeline_initialization(self) -> None:
        """Test pipeline initialization with temporary directory and defaults."""
        pipeline = LiveZeekPipeline(
            log_dir=self.log_dir,
            checkpoint_manager=self.checkpoint_manager,
            poll_interval=0.5,
        )

        self.assertEqual(pipeline.log_dir, self.log_dir)
        self.assertIn("conn", pipeline.tracked_logs)
        self.assertIn("dns", pipeline.tracked_logs)
        self.assertIn("weird", pipeline.tracked_logs)

    def test_missing_log_files(self) -> None:
        """Test poll_once with empty directory returns 0 counts and does not crash."""
        pipeline = LiveZeekPipeline(
            log_dir=self.log_dir,
            checkpoint_manager=self.checkpoint_manager,
        )

        results = pipeline.poll_once()

        self.assertEqual(results["flows"], [])
        self.assertEqual(results["summary"]["flows_count"], 0)
        self.assertEqual(results["summary"]["total_records"], 0)
        self.assertEqual(results["summary"]["conn_count"], 0)

    def test_conn_log_processing_to_flow_record(self) -> None:
        """Test conn.log records are converted into normalized FlowRecord objects."""
        conn_file = self.log_dir / "conn.log"
        conn_file.write_bytes(
            b"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\tconn_state\tmissed_bytes\n"
            b"1618317000.1\tC001\t192.168.1.100\t54321\t93.184.216.34\t80\ttcp\thttp\t0.12\t150\t4500\t4\t6\tSF\t0\n"
        )

        pipeline = LiveZeekPipeline(
            log_dir=self.log_dir,
            checkpoint_manager=self.checkpoint_manager,
        )

        results = pipeline.poll_once()

        self.assertEqual(len(results["flows"]), 1)
        flow = results["flows"][0]
        self.assertIsInstance(flow, FlowRecord)
        self.assertEqual(flow.uid, "C001")
        self.assertEqual(flow.source.ip, "192.168.1.100")
        self.assertEqual(flow.source.port, 54321)
        self.assertEqual(flow.destination.ip, "93.184.216.34")
        self.assertEqual(flow.destination.port, 80)
        self.assertEqual(flow.network.protocol, "tcp")
        self.assertEqual(flow.metrics.total_bytes, 4650)
        self.assertEqual(flow.metrics.total_packets, 10)

    def test_incremental_append(self) -> None:
        """Test newly appended records are processed without duplicating earlier ones."""
        conn_file = self.log_dir / "conn.log"
        conn_file.write_bytes(
            b"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\tconn_state\tmissed_bytes\n"
            b"100.1\tC1\t1.1.1.1\t80\t2.2.2.2\t80\ttcp\thttp\t1.0\t10\t20\t1\t1\tSF\t0\n"
        )

        pipeline = LiveZeekPipeline(
            log_dir=self.log_dir,
            checkpoint_manager=self.checkpoint_manager,
        )

        res1 = pipeline.poll_once()
        self.assertEqual(res1["summary"]["flows_count"], 1)
        self.assertEqual(res1["flows"][0].uid, "C1")

        # Append new record
        with open(conn_file, "ab") as f:
            f.write(b"100.2\tC2\t1.1.1.1\t80\t2.2.2.2\t80\ttcp\thttp\t1.0\t10\t20\t1\t1\tSF\t0\n")

        res2 = pipeline.poll_once()
        self.assertEqual(res2["summary"]["flows_count"], 1)
        self.assertEqual(res2["flows"][0].uid, "C2")

        # Third poll with no new data
        res3 = pipeline.poll_once()
        self.assertEqual(res3["summary"]["flows_count"], 0)

    def test_multiple_zeek_logs_coexist(self) -> None:
        """Test conn.log, dns.log, and weird.log can coexist and be tracked together."""
        conn_file = self.log_dir / "conn.log"
        dns_file = self.log_dir / "dns.log"
        weird_file = self.log_dir / "weird.log"

        conn_file.write_bytes(
            b"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\tconn_state\tmissed_bytes\n"
            b"100.1\tC1\t1.1.1.1\t80\t2.2.2.2\t80\ttcp\thttp\t1.0\t10\t20\t1\t1\tSF\t0\n"
        )
        dns_file.write_bytes(b"#fields\tts\tquery\n100.2\texample.org\n")
        weird_file.write_bytes(b"#fields\tts\tname\n100.3\tbad_HTTP_request\n")

        pipeline = LiveZeekPipeline(
            log_dir=self.log_dir,
            checkpoint_manager=self.checkpoint_manager,
        )

        results = pipeline.poll_once()

        self.assertEqual(results["summary"]["flows_count"], 1)
        self.assertEqual(results["summary"]["dns_count"], 1)
        self.assertEqual(results["summary"]["weird_count"], 1)
        self.assertEqual(results["summary"]["total_records"], 3)
        self.assertEqual(results["logs"]["dns"][0]["query"], "example.org")
        self.assertEqual(results["logs"]["weird"][0]["name"], "bad_HTTP_request")

    def test_checkpoint_resume_across_instances(self) -> None:
        """Test a new pipeline instance resumes from saved checkpoint without reprocessing."""
        conn_file = self.log_dir / "conn.log"
        conn_file.write_bytes(
            b"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\tconn_state\tmissed_bytes\n"
            b"100.1\tC1\t1.1.1.1\t80\t2.2.2.2\t80\ttcp\thttp\t1.0\t10\t20\t1\t1\tSF\t0\n"
        )

        pipeline1 = LiveZeekPipeline(
            log_dir=self.log_dir,
            checkpoint_manager=self.checkpoint_manager,
        )
        res1 = pipeline1.poll_once()
        self.assertEqual(res1["summary"]["flows_count"], 1)

        # Create fresh pipeline with reloaded checkpoint
        reloaded_checkpoint = CheckpointManager(self.checkpoint_file)
        pipeline2 = LiveZeekPipeline(
            log_dir=self.log_dir,
            checkpoint_manager=reloaded_checkpoint,
        )

        res2 = pipeline2.poll_once()
        self.assertEqual(res2["summary"]["flows_count"], 0)

    def test_late_log_creation(self) -> None:
        """Test pipeline handles a log file appearing after pipeline is already running."""
        pipeline = LiveZeekPipeline(
            log_dir=self.log_dir,
            checkpoint_manager=self.checkpoint_manager,
        )

        res1 = pipeline.poll_once()
        self.assertEqual(res1["summary"]["dns_count"], 0)

        # Create dns.log after first poll
        dns_file = self.log_dir / "dns.log"
        dns_file.write_bytes(b"#fields\tts\tquery\n100.5\tlate-domain.com\n")

        res2 = pipeline.poll_once()
        self.assertEqual(res2["summary"]["dns_count"], 1)
        self.assertEqual(res2["logs"]["dns"][0]["query"], "late-domain.com")

    def test_custom_path_configuration(self) -> None:
        """Test custom log directory path configuration."""
        custom_dir = self.test_dir_path / "custom_zeek_logs"
        custom_dir.mkdir(parents=True, exist_ok=True)

        conn_file = custom_dir / "conn.log"
        conn_file.write_bytes(
            b"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\tconn_state\tmissed_bytes\n"
            b"200.1\tCUSTOM_UID\t10.0.0.1\t1234\t10.0.0.2\t80\ttcp\thttp\t1.0\t50\t50\t1\t1\tSF\t0\n"
        )

        pipeline = LiveZeekPipeline(
            log_dir=custom_dir,
            checkpoint_manager=self.checkpoint_manager,
        )

        results = pipeline.poll_once()
        self.assertEqual(results["summary"]["flows_count"], 1)
        self.assertEqual(results["flows"][0].uid, "CUSTOM_UID")


if __name__ == "__main__":
    unittest.main()
