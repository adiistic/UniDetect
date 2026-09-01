"""
UniDetect Local Zeek Log Watcher

Provides a lightweight, cross-platform polling watcher for observing local Zeek log files.
Delegates incremental file tailing and byte-offset checkpointing to IncrementalZeekReader.
"""

import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from src.ingestion.checkpoint import get_file_identity
from src.ingestion.incremental_reader import IncrementalZeekReader
from src.models.flow_record import FlowRecord

logger = logging.getLogger(__name__)


class ZeekLogWatcher:
    """Polls local Zeek log files for changes and triggers incremental reading."""

    def __init__(
        self,
        log_paths: List[Union[str, Path]],
        reader: Optional[IncrementalZeekReader] = None,
        poll_interval: float = 1.0,
    ) -> None:
        """Initialize ZeekLogWatcher.

        Args:
            log_paths: List of log file paths to observe.
            reader: IncrementalZeekReader instance. Uses default if None.
            poll_interval: Delay in seconds between polling cycles in continuous mode.
        """
        self.log_paths = [Path(p).resolve() for p in log_paths]
        self.reader = reader if reader is not None else IncrementalZeekReader()
        self.poll_interval = poll_interval
        self._last_stats: Dict[str, Dict[str, Any]] = {}

    def poll_once(
        self, as_flow_records: bool = False
    ) -> Dict[str, Dict[str, Any]]:
        """Perform a single deterministic polling pass across all configured log files.

        Args:
            as_flow_records: If True, normalizes conn.log records into FlowRecord DTOs.

        Returns:
            Dictionary mapping canonical file path strings to status and record results:
            {
                "/path/to/conn.log": {
                    "status": "ok" | "no_change" | "file_not_found" | "error",
                    "records": [...],
                    "count": int,
                    "error": str (optional)
                }
            }
        """
        results: Dict[str, Dict[str, Any]] = {}

        for path in self.log_paths:
            canonical_path = str(path)

            try:
                if not path.is_file():
                    logger.debug(f"Watched file not found: {canonical_path}")
                    results[canonical_path] = {
                        "status": "file_not_found",
                        "records": [],
                        "count": 0,
                    }
                    continue

                identity = get_file_identity(path)
                last_stat = self._last_stats.get(canonical_path)

                # Quick metadata check: if size & inode haven't changed and checkpoint exists
                if last_stat:
                    checkpoint = self.reader.checkpoint_manager.get_checkpoint(path)
                    if checkpoint:
                        stored_offset = self.reader.checkpoint_manager.get_offset(path)
                        if (
                            identity["size"] == stored_offset
                            and identity["size"] == last_stat.get("size")
                            and identity["inode"] == last_stat.get("inode")
                        ):
                            results[canonical_path] = {
                                "status": "no_change",
                                "records": [],
                                "count": 0,
                            }
                            continue

                # Read new data using IncrementalZeekReader
                if as_flow_records or path.name.lower() == "conn.log":
                    records = self.reader.read_new_flow_records(path)
                else:
                    records = self.reader.read_new_records(path)

                self._last_stats[canonical_path] = identity

                status_str = "ok" if records else "no_change"
                results[canonical_path] = {
                    "status": status_str,
                    "records": records,
                    "count": len(records),
                }

            except Exception as e:
                logger.error(
                    f"Error polling log file '{canonical_path}' in watcher: {e}",
                    exc_info=True,
                )
                results[canonical_path] = {
                    "status": "error",
                    "records": [],
                    "count": 0,
                    "error": str(e),
                }

        return results

    def watch(
        self,
        max_polls: Optional[int] = None,
        stop_event: Optional[threading.Event] = None,
        callback: Optional[Callable[[Dict[str, Dict[str, Any]]], None]] = None,
        as_flow_records: bool = False,
    ) -> None:
        """Run continuous polling loop until stopped or max_polls is reached.

        Args:
            max_polls: Maximum number of polling passes to execute (useful for testing).
            stop_event: threading.Event signal to cleanly terminate polling loop.
            callback: Optional callable invoked with poll results after each cycle.
            as_flow_records: If True, returns records as FlowRecord objects.
        """
        poll_count = 0

        while True:
            if stop_event and stop_event.is_set():
                break

            if max_polls is not None and poll_count >= max_polls:
                break

            poll_results = self.poll_once(as_flow_records=as_flow_records)
            poll_count += 1

            if callback:
                try:
                    callback(poll_results)
                except Exception as e:
                    logger.error(f"Error executing watcher callback: {e}")

            if stop_event and stop_event.is_set():
                break

            if max_polls is not None and poll_count >= max_polls:
                break

            time.sleep(self.poll_interval)
