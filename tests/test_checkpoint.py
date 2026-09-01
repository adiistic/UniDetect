"""
Unit tests for UniDetect CheckpointManager (src/ingestion/checkpoint.py)
"""

import json
import logging
import tempfile
import unittest
from pathlib import Path

from src.ingestion.checkpoint import CheckpointManager, get_file_identity


class TestCheckpointManager(unittest.TestCase):
    """Test suite verifying local state checkpoint management."""

    def setUp(self) -> None:
        """Create a temporary working directory for tests."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_dir_path = Path(self.test_dir.name).resolve()
        self.checkpoint_file = self.test_dir_path / "checkpoint.json"

    def tearDown(self) -> None:
        """Clean up temporary test directory."""
        self.test_dir.cleanup()

    def test_missing_checkpoint_file(self) -> None:
        """Test that loading a non-existent checkpoint file returns a valid empty state without crashing."""
        manager = CheckpointManager(self.checkpoint_file)
        state = manager.state

        self.assertIsInstance(state, dict)
        self.assertEqual(state.get("version"), 1)
        self.assertEqual(state.get("files"), {})

    def test_save_and_reload(self) -> None:
        """Test saving a checkpoint and reloading it in a new manager instance."""
        target_log = self.test_dir_path / "conn.log"
        target_log.write_text("sample content", encoding="utf-8")

        manager1 = CheckpointManager(self.checkpoint_file)
        manager1.save_checkpoint(target_log, offset=105432)

        # Re-instantiate manager to test reload from disk
        manager2 = CheckpointManager(self.checkpoint_file)
        reloaded_offset = manager2.get_offset(target_log)

        self.assertEqual(reloaded_offset, 105432)

    def test_multiple_files(self) -> None:
        """Test that checkpoints for multiple log files coexist without overwriting each other."""
        log1 = self.test_dir_path / "conn.log"
        log2 = self.test_dir_path / "dns.log"
        log1.write_text("conn data", encoding="utf-8")
        log2.write_text("dns data", encoding="utf-8")

        manager = CheckpointManager(self.checkpoint_file)
        manager.save_checkpoint(log1, offset=100)
        manager.save_checkpoint(log2, offset=200)

        reload_manager = CheckpointManager(self.checkpoint_file)
        self.assertEqual(reload_manager.get_offset(log1), 100)
        self.assertEqual(reload_manager.get_offset(log2), 200)

    def test_offset_update(self) -> None:
        """Test updating an existing file checkpoint replaces the old offset correctly."""
        log_file = self.test_dir_path / "conn.log"
        log_file.write_text("data", encoding="utf-8")

        manager = CheckpointManager(self.checkpoint_file)
        manager.save_checkpoint(log_file, offset=100)
        self.assertEqual(manager.get_offset(log_file), 100)

        manager.save_checkpoint(log_file, offset=500)
        self.assertEqual(manager.get_offset(log_file), 500)

    def test_atomic_write_behavior(self) -> None:
        """Test atomic write creates a valid JSON checkpoint file matching state."""
        log_file = self.test_dir_path / "conn.log"
        log_file.write_text("data", encoding="utf-8")

        manager = CheckpointManager(self.checkpoint_file)
        manager.save_checkpoint(log_file, offset=1234)

        self.assertTrue(self.checkpoint_file.is_file())

        with open(self.checkpoint_file, "r", encoding="utf-8") as f:
            raw_json = json.load(f)

        self.assertEqual(raw_json["version"], 1)
        canonical_path = str(log_file.resolve())
        self.assertIn(canonical_path, raw_json["files"])
        self.assertEqual(raw_json["files"][canonical_path]["offset"], 1234)

    def test_corrupt_json_handling(self) -> None:
        """Test that invalid JSON causes warning, returns empty valid state, and preserves the corrupt file."""
        # Write invalid raw JSON to checkpoint path
        corrupt_content = "{ invalid json content ... "
        self.checkpoint_file.write_text(corrupt_content, encoding="utf-8")

        with self.assertLogs("src.ingestion.checkpoint", level="WARNING") as cm:
            manager = CheckpointManager(self.checkpoint_file)

        # Check warning emitted
        self.assertTrue(any("Corrupt checkpoint file" in log for log in cm.output))

        # Check valid empty in-memory state returned
        self.assertEqual(manager.state, {"version": 1, "files": {}})

        # Check corrupt file is preserved on disk
        self.assertTrue(self.checkpoint_file.is_file())
        self.assertEqual(self.checkpoint_file.read_text(encoding="utf-8"), corrupt_content)

    def test_file_identity(self) -> None:
        """Test file identity helper for resolved path, size, and platform inode/device handling."""
        sample_file = self.test_dir_path / "sample.log"
        sample_file.write_text("hello world", encoding="utf-8")

        identity = get_file_identity(sample_file)

        self.assertEqual(identity["path"], str(sample_file.resolve()))
        self.assertEqual(identity["size"], len("hello world"))
        self.assertIn("inode", identity)
        self.assertIn("device", identity)

    def test_path_normalization(self) -> None:
        """Test that relative, absolute, and path with dot components resolve to the same checkpoint entry."""
        sample_file = self.test_dir_path / "conn.log"
        sample_file.write_text("data", encoding="utf-8")

        manager = CheckpointManager(self.checkpoint_file)
        manager.save_checkpoint(sample_file, offset=999)

        # Build equivalent non-canonical path representation
        relative_path = self.test_dir_path / ".." / self.test_dir_path.name / "conn.log"

        self.assertEqual(manager.get_offset(relative_path), 999)


if __name__ == "__main__":
    unittest.main()
