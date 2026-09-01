"""
Unit tests for UniDetect Zeek TSV Log Reader (src/ingestion/zeek_reader.py)
"""

import tempfile
import unittest
from pathlib import Path

from src.ingestion.zeek_reader import load_zeek_logs, read_zeek_log


class TestZeekReader(unittest.TestCase):
    """Test suite verifying passive Zeek log ingestion functionality."""

    def setUp(self) -> None:
        """Create a temporary directory for test log files."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_dir_path = Path(self.test_dir.name)

    def tearDown(self) -> None:
        """Clean up temporary test directory."""
        self.test_dir.cleanup()

    def test_read_valid_zeek_log(self) -> None:
        """Test that metadata lines are ignored, #fields header is parsed, and normal records are returned as dictionaries."""
        log_content = (
            "#separator \\x09\n"
            "#set_separator\t,\n"
            "#empty_field\t(empty)\n"
            "#unset_field\t-\n"
            "#path\tconn\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\n"
            "1618317000.100\tC12345\t192.168.1.10\t53530\t1.1.1.1\t53\tudp\n"
            "1618317001.200\tC12346\t192.168.1.11\t44321\t8.8.8.8\t53\tudp\n"
            "#close\t2026-09-01-12-00-00\n"
        )
        log_file = self.test_dir_path / "conn.log"
        log_file.write_text(log_content, encoding="utf-8")

        records = read_zeek_log(log_file)

        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["uid"], "C12345")
        self.assertEqual(records[0]["id.orig_h"], "192.168.1.10")
        self.assertEqual(records[0]["id.resp_p"], "53")
        self.assertEqual(records[1]["uid"], "C12346")
        self.assertEqual(records[1]["id.resp_h"], "8.8.8.8")

    def test_missing_file_handling(self) -> None:
        """Test that attempting to read a non-existent file returns an empty list without crashing."""
        non_existent_file = self.test_dir_path / "missing_file.log"
        records = read_zeek_log(non_existent_file)
        self.assertEqual(records, [])

    def test_malformed_rows_handling(self) -> None:
        """Test that malformed rows with mismatching column counts are safely skipped."""
        log_content = (
            "#fields\tts\tuid\tproto\n"
            "100.1\tC001\ttcp\n"
            "100.2\tC002\n"  # Malformed: missing proto field
            "100.3\tC003\tudp\textra_field\n"  # Malformed: extra field
            "100.4\tC004\ttcp\n"
        )
        log_file = self.test_dir_path / "weird.log"
        log_file.write_text(log_content, encoding="utf-8")

        records = read_zeek_log(log_file)

        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["uid"], "C001")
        self.assertEqual(records[1]["uid"], "C004")

    def test_load_zeek_logs(self) -> None:
        """Test loading supported log files from a directory, returning empty lists for missing files."""
        conn_content = "#fields\tts\tuid\n100.1\tC001\n"
        dns_content = "#fields\tts\tquery\n100.2\texample.com\n"

        (self.test_dir_path / "conn.log").write_text(conn_content, encoding="utf-8")
        (self.test_dir_path / "dns.log").write_text(dns_content, encoding="utf-8")

        loaded = load_zeek_logs(self.test_dir_path)

        self.assertIn("conn", loaded)
        self.assertIn("dns", loaded)
        self.assertIn("weird", loaded)
        self.assertIn("ntp", loaded)
        self.assertIn("quic", loaded)

        self.assertEqual(len(loaded["conn"]), 1)
        self.assertEqual(len(loaded["dns"]), 1)
        self.assertEqual(len(loaded["weird"]), 0)
        self.assertEqual(len(loaded["ntp"]), 0)
        self.assertEqual(len(loaded["quic"]), 0)


if __name__ == "__main__":
    unittest.main()
