"""
Unit tests for ZeekLogWatcher (src/ingestion/watcher.py)
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from src.ingestion.checkpoint import CheckpointManager
from src.ingestion.incremental_reader import IncrementalZeekReader
from src.ingestion.watcher import ZeekLogWatcher
from src.models.flow_record import FlowRecord


class TestZeekLogWatcher(unittest.TestCase):
    """Test suite verifying local log file watcher and polling behavior."""

    def setUp(self) -> None:
        """Create a temporary directory, checkpoint manager, and reader."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_dir_path = Path(self.test_dir.name).resolve()
        self.checkpoint_file = self.test_dir_path / "checkpoint.json"
        self.checkpoint_manager = CheckpointManager(self.checkpoint_file)
        self.reader = IncrementalZeekReader(self.checkpoint_manager)

    def tearDown(self) -> None:
        """Clean up temporary test directory."""
        self.test_dir.cleanup()

    def test_single_file_first_poll(self) -> None:
        """Test poll_once on a single new log file processes content and returns records."""
        log_file = self.test_dir_path / "dns.log"
        log_file.write_bytes(b"#fields\tts\tquery\n100.1\texample.com\n")

        watcher = ZeekLogWatcher(log_paths=[log_file], reader=self.reader)
        results = watcher.poll_once()

        canonical_path = str(log_file)
        self.assertIn(canonical_path, results)
        res = results[canonical_path]

        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["records"][0]["query"], "example.com")

    def test_incremental_append(self) -> None:
        """Test poll_once on appended content returns only newly appended records."""
        log_file = self.test_dir_path / "dns.log"
        log_file.write_bytes(b"#fields\tts\tquery\n100.1\texample.com\n")

        watcher = ZeekLogWatcher(log_paths=[log_file], reader=self.reader)
        res1 = watcher.poll_once()
        self.assertEqual(res1[str(log_file)]["count"], 1)

        # Append new complete line
        with open(log_file, "ab") as f:
            f.write(b"100.2\tsecond.org\n")

        res2 = watcher.poll_once()
        self.assertEqual(res2[str(log_file)]["count"], 1)
        self.assertEqual(res2[str(log_file)]["records"][0]["query"], "second.org")

    def test_no_changes(self) -> None:
        """Test polling an unchanged file returns status 'no_change' with 0 count."""
        log_file = self.test_dir_path / "dns.log"
        log_file.write_bytes(b"#fields\tts\tquery\n100.1\texample.com\n")

        watcher = ZeekLogWatcher(log_paths=[log_file], reader=self.reader)
        watcher.poll_once()
        res_again = watcher.poll_once()

        self.assertEqual(res_again[str(log_file)]["status"], "no_change")
        self.assertEqual(res_again[str(log_file)]["count"], 0)

    def test_multiple_files(self) -> None:
        """Test watching multiple log files processes each file independently."""
        conn_file = self.test_dir_path / "conn.log"
        dns_file = self.test_dir_path / "dns.log"

        conn_file.write_bytes(
            b"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\tconn_state\tmissed_bytes\n"
            b"100.1\tC001\t1.1.1.1\t80\t2.2.2.2\t80\ttcp\thttp\t1.0\t10\t20\t1\t1\tSF\t0\n"
        )
        dns_file.write_bytes(b"#fields\tts\tquery\n100.2\ttest.org\n")

        watcher = ZeekLogWatcher(log_paths=[conn_file, dns_file], reader=self.reader)
        results = watcher.poll_once()

        self.assertIn(str(conn_file), results)
        self.assertIn(str(dns_file), results)

        self.assertEqual(results[str(conn_file)]["count"], 1)
        self.assertEqual(results[str(dns_file)]["count"], 1)

    def test_one_missing_file_and_one_valid_file(self) -> None:
        """Test watching a mix of missing and valid files does not crash."""
        valid_file = self.test_dir_path / "dns.log"
        missing_file = self.test_dir_path / "missing.log"

        valid_file.write_bytes(b"#fields\tts\tquery\n100.1\tvalid.com\n")

        watcher = ZeekLogWatcher(log_paths=[missing_file, valid_file], reader=self.reader)
        results = watcher.poll_once()

        self.assertEqual(results[str(missing_file)]["status"], "file_not_found")
        self.assertEqual(results[str(missing_file)]["count"], 0)

        self.assertEqual(results[str(valid_file)]["status"], "ok")
        self.assertEqual(results[str(valid_file)]["count"], 1)

    def test_file_appears_later(self) -> None:
        """Test configuring a non-existent path handles missing state first, then processes when file appears."""
        late_file = self.test_dir_path / "late.log"

        watcher = ZeekLogWatcher(log_paths=[late_file], reader=self.reader)
        res1 = watcher.poll_once()
        self.assertEqual(res1[str(late_file)]["status"], "file_not_found")

        # Now create the file
        late_file.write_bytes(b"#fields\tts\tquery\n100.1\tappeared.org\n")

        res2 = watcher.poll_once()
        self.assertEqual(res2[str(late_file)]["status"], "ok")
        self.assertEqual(res2[str(late_file)]["count"], 1)

    def test_flow_record_integration(self) -> None:
        """Test returning FlowRecord objects for conn.log connections."""
        conn_file = self.test_dir_path / "conn.log"
        conn_file.write_bytes(
            b"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\tconn_state\tmissed_bytes\n"
            b"100.1\tCH100\t192.168.1.50\t5000\t10.0.0.1\t80\ttcp\thttp\t0.5\t100\t200\t2\t2\tSF\t0\n"
        )

        watcher = ZeekLogWatcher(log_paths=[conn_file], reader=self.reader)
        results = watcher.poll_once(as_flow_records=True)

        records = results[str(conn_file)]["records"]
        self.assertEqual(len(records), 1)
        self.assertIsInstance(records[0], FlowRecord)
        self.assertEqual(records[0].uid, "CH100")
        self.assertEqual(records[0].source.ip, "192.168.1.50")

    def test_error_isolation(self) -> None:
        """Test that an unexpected error processing one log file is caught and isolated without stopping other files."""
        file1 = self.test_dir_path / "file1.log"
        file2 = self.test_dir_path / "file2.log"

        file1.write_bytes(b"#fields\tts\tval\n100\tA\n")
        file2.write_bytes(b"#fields\tts\tval\n200\tB\n")

        mock_reader = MagicMock(spec=IncrementalZeekReader)
        mock_reader.checkpoint_manager = self.checkpoint_manager

        # Make read_new_records raise exception for file1, but succeed for file2
        def mock_read(path):
            if str(path) == str(file1):
                raise ValueError("Simulated I/O read failure")
            return [{"val": "B"}]

        mock_reader.read_new_records.side_effect = mock_read

        watcher = ZeekLogWatcher(log_paths=[file1, file2], reader=mock_reader)

        with self.assertLogs("src.ingestion.watcher", level="ERROR") as cm:
            results = watcher.poll_once()

        self.assertEqual(results[str(file1)]["status"], "error")
        self.assertIn("Simulated I/O read failure", results[str(file1)]["error"])

        # File 2 should be processed successfully
        self.assertEqual(results[str(file2)]["status"], "ok")
        self.assertEqual(results[str(file2)]["count"], 1)


if __name__ == "__main__":
    unittest.main()
