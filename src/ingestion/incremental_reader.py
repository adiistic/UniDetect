"""
UniDetect Incremental Zeek Log Reader

Reads newly appended content from Zeek TSV log files using byte offsets
persisted by CheckpointManager. Handles incomplete line writes, file truncation,
and file replacement safely without opening network sockets or modifying source files.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from src.ingestion.checkpoint import CheckpointManager, get_file_identity
from src.models.flow_record import FlowRecord, normalize_conn_record

logger = logging.getLogger(__name__)


class IncrementalZeekReader:
    """Safely reads appended records from Zeek log files using byte-offset checkpointing."""

    def __init__(self, checkpoint_manager: Optional[CheckpointManager] = None) -> None:
        """Initialize IncrementalZeekReader.

        Args:
            checkpoint_manager: CheckpointManager instance. Uses default manager if None.
        """
        if checkpoint_manager is None:
            self.checkpoint_manager = CheckpointManager()
        else:
            self.checkpoint_manager = checkpoint_manager

    def read_new_lines(
        self, file_path: Union[str, Path]
    ) -> Tuple[List[str], List[str], str]:
        """Read newly appended lines from a log file in binary mode.

        Args:
            file_path: Target log file path.

        Returns:
            A tuple of (data_lines, metadata_lines, separator):
            - data_lines: List of complete data text lines (excluding lines starting with '#').
            - metadata_lines: List of header/metadata lines starting with '#' read in this pass.
            - separator: Detected column delimiter (default '\\t').

            Returns ([], [], '\\t') if the file is missing or has no new complete lines.
        """
        path = Path(file_path).resolve()
        if not path.is_file():
            logger.warning(f"Incremental log file not found: {file_path}")
            return [], [], "\t"

        identity = get_file_identity(path)
        current_size = identity["size"]

        checkpoint = self.checkpoint_manager.get_checkpoint(path)
        start_offset = 0
        should_reset_offset = False

        if checkpoint:
            stored_offset = self.checkpoint_manager.get_offset(path)
            stored_size = checkpoint.get("size", 0)
            stored_inode = checkpoint.get("inode")
            stored_device = checkpoint.get("device")

            # Check for file truncation
            if current_size < stored_offset:
                logger.info(
                    f"File truncation detected on '{path.name}': "
                    f"current size ({current_size}) < saved offset ({stored_offset}). Resetting offset to 0."
                )
                should_reset_offset = True

            # Check for file replacement via identity (inode/device change)
            elif (
                stored_inode is not None
                and identity["inode"] is not None
                and stored_inode != identity["inode"]
            ):
                logger.info(
                    f"File replacement detected on '{path.name}': "
                    f"saved inode ({stored_inode}) != current inode ({identity['inode']}). Resetting offset to 0."
                )
                should_reset_offset = True
            else:
                start_offset = stored_offset

        if should_reset_offset:
            start_offset = 0

        # If file hasn't grown past start_offset, return empty
        if current_size <= start_offset and not should_reset_offset and checkpoint:
            return [], [], "\t"

        data_lines: List[str] = []
        metadata_lines: List[str] = []
        separator = "\t"
        safe_offset = start_offset

        try:
            with open(path, "rb") as f:
                f.seek(start_offset)
                current_pos = start_offset

                while True:
                    line_pos = f.tell()
                    raw_line = f.readline()

                    if not raw_line:
                        # Reached EOF
                        break

                    # Check for incomplete final line (must end with b'\n')
                    if not raw_line.endswith(b"\n"):
                        logger.debug(
                            f"Incomplete line detected at offset {line_pos} in '{path.name}'. "
                            f"Deferring processing until line completion."
                        )
                        # Do not advance safe_offset past incomplete line
                        break

                    # Complete line read successfully
                    current_pos = f.tell()
                    safe_offset = current_pos

                    text_line = raw_line.decode("utf-8", errors="replace").strip("\r\n")
                    if not text_line:
                        continue

                    if text_line.startswith("#"):
                        metadata_lines.append(text_line)
                        if text_line.startswith("#separator"):
                            parts = text_line.split()
                            if len(parts) >= 2:
                                raw_sep = parts[1]
                                if raw_sep.startswith("\\x"):
                                    try:
                                        separator = chr(int(raw_sep[2:], 16))
                                    except ValueError:
                                        separator = "\t"
                                else:
                                    separator = raw_sep
                    else:
                        data_lines.append(text_line)

        except Exception as e:
            logger.error(f"Error reading incremental log '{path}': {e}")
            return [], [], "\t"

        # Update checkpoint only after successful read up to safe_offset
        self.checkpoint_manager.save_checkpoint(path, safe_offset)
        return data_lines, metadata_lines, separator

    def read_new_records(
        self, file_path: Union[str, Path]
    ) -> List[Dict[str, Any]]:
        """Read newly appended Zeek log entries and return as parsed dictionaries.

        Args:
            file_path: Target Zeek log file path.

        Returns:
            List of parsed record dictionaries for newly appended entries.
        """
        path = Path(file_path).resolve()
        checkpoint = self.checkpoint_manager.get_checkpoint(path)
        cached_fields: List[str] = checkpoint.get("fields", []) if checkpoint else []

        data_lines, metadata_lines, separator = self.read_new_lines(path)
        fields = list(cached_fields)

        # Parse fields from new metadata lines if available
        for meta in metadata_lines:
            if meta.startswith("#fields"):
                parts = meta.split(separator)
                if len(parts) > 1:
                    fields = [p.strip() for p in parts[1:]]

        # Update cached fields in checkpoint state if new fields discovered
        if fields and fields != cached_fields:
            cp = self.checkpoint_manager.get_checkpoint(path)
            if cp:
                offset = cp.get("offset", 0)
                cp_entry = self.checkpoint_manager.save_checkpoint(path, offset)
                cp_entry["fields"] = fields
                self.checkpoint_manager._atomic_write()

        if not fields or not data_lines:
            return []

        records: List[Dict[str, Any]] = []
        for line in data_lines:
            values = line.split(separator)
            if len(values) == len(fields):
                records.append(dict(zip(fields, values)))
            else:
                logger.warning(
                    f"Skipping malformed incremental record in '{path.name}': "
                    f"expected {len(fields)} fields, got {len(values)}."
                )

        return records

    def read_new_flow_records(
        self, file_path: Union[str, Path]
    ) -> List[FlowRecord]:
        """Read newly appended conn.log entries and normalize into FlowRecord DTOs.

        Args:
            file_path: Target conn.log file path.

        Returns:
            List of normalized FlowRecord objects for newly appended connection entries.
        """
        raw_records = self.read_new_records(file_path)
        return [normalize_conn_record(rec) for rec in raw_records]
