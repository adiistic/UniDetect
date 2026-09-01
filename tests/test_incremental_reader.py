"""
Unit tests for IncrementalZeekReader (src/ingestion/incremental_reader.py)
"""

import tempfile
import unittest
from pathlib import Path

from src.ingestion.checkpoint import CheckpointManager
from src.ingestion.incremental_reader import IncrementalZeekReader


class TestIncrementalZeekReader(unittest.TestCase):
    """Test suite verifying incremental log tailing, offset seeking, and byte safety."""

    def setUp(self) -> None:
        """Create a temporary working directory and checkpoint manager."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_dir_path = Path(self.test_dir.name).resolve()
        self.checkpoint_file = self.test_dir_path / "checkpoint.json"
        self.checkpoint_manager = CheckpointManager(self.checkpoint_file)
        self.reader = IncrementalZeekReader(self.checkpoint_manager)

    def tearDown(self) -> None:
        """Clean up temporary test directory."""
        self.test_dir.cleanup()

    def test_first_read(self) -> None:
        """Test first read starts at offset 0, returns complete lines, and saves checkpoint offset."""
        log_file = self.test_dir_path / "conn.log"
        content_bytes = b"#fields\tts\tuid\n100.1\tC001\n100.2\tC002\n"
        log_file.write_bytes(content_bytes)

        lines, metadata, _ = self.reader.read_new_lines(log_file)

        self.assertEqual(lines, ["100.1\tC001", "100.2\tC002"])
        self.assertEqual(len(metadata), 1)

        offset = self.checkpoint_manager.get_offset(log_file)
        self.assertEqual(offset, len(content_bytes))

    def test_incremental_append(self) -> None:
        """Test appending new complete lines returns only new lines without duplicating previous ones."""
        log_file = self.test_dir_path / "conn.log"
        log_file.write_bytes(b"#fields\tts\tuid\n100.1\tC001\n")

        # First read
        lines1, _, _ = self.reader.read_new_lines(log_file)
        self.assertEqual(lines1, ["100.1\tC001"])

        # Append new complete line in binary mode
        with open(log_file, "ab") as f:
            f.write(b"100.2\tC002\n")

        # Second read
        lines2, _, _ = self.reader.read_new_lines(log_file)
        self.assertEqual(lines2, ["100.2\tC002"])

    def test_no_changes(self) -> None:
        """Test reading an unchanged file returns an empty result and does not duplicate records."""
        log_file = self.test_dir_path / "conn.log"
        log_file.write_bytes(b"#fields\tts\tuid\n100.1\tC001\n")

        self.reader.read_new_lines(log_file)
        lines_again, _, _ = self.reader.read_new_lines(log_file)

        self.assertEqual(lines_again, [])

    def test_incomplete_final_line(self) -> None:
        """Test that an incomplete final line without newline is deferred until line completion."""
        log_file = self.test_dir_path / "conn.log"

        # Write two complete lines and one incomplete line (no trailing newline)
        with open(log_file, "wb") as f:
            f.write(b"line1\nline2\npartial_rec")

        lines1, _, _ = self.reader.read_new_lines(log_file)
        self.assertEqual(lines1, ["line1", "line2"])

        # Verify checkpoint offset did not advance past line2
        offset1 = self.checkpoint_manager.get_offset(log_file)
        expected_offset_after_line2 = len(b"line1\nline2\n")
        self.assertEqual(offset1, expected_offset_after_line2)

        # Complete the partial line
        with open(log_file, "ab") as f:
            f.write(b"ord_completed\n")

        lines2, _, _ = self.reader.read_new_lines(log_file)
        self.assertEqual(lines2, ["partial_record_completed"])

    def test_multiple_incremental_reads(self) -> None:
        """Test multiple sequential appends return only newly completed lines each time."""
        log_file = self.test_dir_path / "conn.log"
        log_file.write_bytes(b"header\n")

        self.reader.read_new_lines(log_file)

        for i in range(3):
            with open(log_file, "ab") as f:
                f.write(f"record_{i}\n".encode("utf-8"))

            lines, _, _ = self.reader.read_new_lines(log_file)
            self.assertEqual(lines, [f"record_{i}"])

    def test_file_truncation(self) -> None:
        """Test that truncating a file smaller than saved offset resets read position to 0."""
        log_file = self.test_dir_path / "conn.log"
        log_file.write_bytes(b"line1\nline2\nline3\n")

        self.reader.read_new_lines(log_file)
        saved_offset = self.checkpoint_manager.get_offset(log_file)
        self.assertGreater(saved_offset, 0)

        # Truncate file to smaller content
        log_file.write_bytes(b"new1\n")

        lines, _, _ = self.reader.read_new_lines(log_file)
        self.assertEqual(lines, ["new1"])

    def test_file_replacement(self) -> None:
        """Test file replacement detection using updated inode/size state."""
        log_file = self.test_dir_path / "conn.log"
        log_file.write_bytes(b"old_data_line\n")

        self.reader.read_new_lines(log_file)

        # Simulate replacement by deleting and recreating the file
        log_file.unlink()
        log_file.write_bytes(b"fresh_replaced_data\n")

        lines, _, _ = self.reader.read_new_lines(log_file)
        self.assertEqual(lines, ["fresh_replaced_data"])

    def test_missing_file(self) -> None:
        """Test that missing log file returns empty result without destroying existing checkpoint."""
        log_file = self.test_dir_path / "conn.log"
        log_file.write_bytes(b"line1\n")

        self.reader.read_new_lines(log_file)
        saved_offset = self.checkpoint_manager.get_offset(log_file)

        missing_file = self.test_dir_path / "non_existent.log"
        lines, _, _ = self.reader.read_new_lines(missing_file)

        self.assertEqual(lines, [])
        # Check existing checkpoint for conn.log was not affected
        self.assertEqual(self.checkpoint_manager.get_offset(log_file), saved_offset)

    def test_byte_offset_correctness_utf8(self) -> None:
        """Test that multi-byte UTF-8 characters are handled based on byte offsets."""
        log_file = self.test_dir_path / "utf8.log"

        # "€" is 3 bytes in UTF-8 (0xE2, 0x82, 0xAC)
        utf8_content = "line1_euro_€\nline2_dollar_$\n".encode("utf-8")

        with open(log_file, "wb") as f:
            f.write(utf8_content)

        lines, _, _ = self.reader.read_new_lines(log_file)
        self.assertEqual(lines, ["line1_euro_€", "line2_dollar_$"])

        saved_offset = self.checkpoint_manager.get_offset(log_file)
        self.assertEqual(saved_offset, len(utf8_content))


if __name__ == "__main__":
    unittest.main()
