"""
UniDetect Local Checkpoint Manager

Provides robust, atomic persistence for tracking log file read positions (byte offsets)
and file identity metadata across runs. Prepares UniDetect for incremental ingestion
without opening network sockets or modifying source log files.
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Union

logger = logging.getLogger(__name__)

DEFAULT_CHECKPOINT_PATH = Path("data/.unidetect_checkpoint.json")


def get_file_identity(file_path: Union[str, Path]) -> Dict[str, Any]:
    """Inspect a file and return identity metadata across platforms.

    Args:
        file_path: Path to the target file.

    Returns:
        Dictionary containing resolved path, size, inode, and device ID (where available).
    """
    path = Path(file_path).resolve()
    identity: Dict[str, Any] = {
        "path": str(path),
        "size": 0,
        "inode": None,
        "device": None,
    }

    if path.is_file():
        try:
            stat_result = path.stat()
            identity["size"] = stat_result.st_size

            # st_ino and st_dev may be 0 or unavailable on non-POSIX platforms
            if stat_result.st_ino:
                identity["inode"] = stat_result.st_ino
            if stat_result.st_dev:
                identity["device"] = stat_result.st_dev
        except OSError as e:
            logger.warning(f"Failed to stat file '{path}': {e}")

    return identity


class CheckpointManager:
    """Manages persistent byte offsets and file state for offline and incremental readers."""

    def __init__(self, checkpoint_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize the CheckpointManager with a target storage path.

        Args:
            checkpoint_path: Path to checkpoint JSON file. Defaults to 'data/.unidetect_checkpoint.json'.
        """
        if checkpoint_path is None:
            self.checkpoint_path = DEFAULT_CHECKPOINT_PATH.resolve()
        else:
            self.checkpoint_path = Path(checkpoint_path).resolve()

        self.state: Dict[str, Any] = self.load()

    def load(self) -> Dict[str, Any]:
        """Load checkpoint state from disk.

        If the file is missing, returns a valid empty state.
        If the file is corrupt or invalid JSON, emits a warning, preserves the file,
        and returns a valid empty in-memory state.

        Returns:
            Dictionary representing current checkpoint state.
        """
        empty_state: Dict[str, Any] = {"version": 1, "files": {}}

        if not self.checkpoint_path.is_file():
            logger.info(f"No checkpoint file at '{self.checkpoint_path}'. Starting with empty state.")
            return empty_state

        try:
            with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Validate top-level JSON structure
            if not isinstance(data, dict) or "files" not in data or not isinstance(data["files"], dict):
                logger.warning(
                    f"Corrupt checkpoint file at '{self.checkpoint_path}': invalid structure. "
                    f"Preserving corrupt file and using empty in-memory state."
                )
                return empty_state

            return data

        except Exception as e:
            logger.warning(
                f"Corrupt checkpoint file at '{self.checkpoint_path}': {e}. "
                f"Preserving corrupt file and using empty in-memory state."
            )
            return empty_state

    def get_checkpoint(self, file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """Get stored checkpoint metadata for a specific log file.

        Args:
            file_path: Path to the log file.

        Returns:
            Dictionary of stored metadata or None if no checkpoint exists.
        """
        canonical_path = str(Path(file_path).resolve())
        return self.state.get("files", {}).get(canonical_path)

    def get_offset(self, file_path: Union[str, Path]) -> int:
        """Get stored authoritative byte offset for a log file (defaults to 0).

        Args:
            file_path: Path to the log file.

        Returns:
            Authoritative byte offset integer.
        """
        checkpoint = self.get_checkpoint(file_path)
        if checkpoint and "offset" in checkpoint:
            try:
                return int(checkpoint["offset"])
            except (ValueError, TypeError):
                return 0
        return 0

    def save_checkpoint(
        self, file_path: Union[str, Path], offset: int
    ) -> Dict[str, Any]:
        """Update and atomically persist checkpoint state for a log file.

        Args:
            file_path: Target log file path.
            offset: Authoritative byte offset resume position.

        Returns:
            Updated file checkpoint metadata entry.
        """
        path_obj = Path(file_path).resolve()
        canonical_path = str(path_obj)
        identity = get_file_identity(path_obj)

        entry = {
            "path": canonical_path,
            "offset": int(offset),
            "inode": identity["inode"],
            "device": identity["device"],
            "size": identity["size"],
            "updated_at": time.time(),
        }

        if "files" not in self.state or not isinstance(self.state["files"], dict):
            self.state["files"] = {}

        self.state["files"][canonical_path] = entry
        self._atomic_write()
        return entry

    def _atomic_write(self) -> None:
        """Atomically write in-memory state to disk using a temporary file in the same directory."""
        parent_dir = self.checkpoint_path.parent
        parent_dir.mkdir(parents=True, exist_ok=True)

        temp_path = parent_dir / f"{self.checkpoint_path.name}.tmp.{os.getpid()}"

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            # Atomic file replacement
            os.replace(temp_path, self.checkpoint_path)

        except Exception as e:
            logger.error(f"Failed atomic checkpoint write to '{self.checkpoint_path}': {e}")
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise
