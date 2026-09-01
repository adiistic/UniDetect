"""
UniDetect Live Zeek Log Directory Integration Pipeline

Coordinates ZeekLogWatcher, IncrementalZeekReader, and CheckpointManager to passively
monitor a directory of continuously generated Zeek log files without duplicating logic.
"""

import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from src.ingestion.checkpoint import CheckpointManager
from src.ingestion.incremental_reader import IncrementalZeekReader
from src.ingestion.watcher import ZeekLogWatcher
from src.models.flow_record import FlowRecord

logger = logging.getLogger(__name__)

DEFAULT_TRACKED_LOGS = ["conn", "dns", "weird", "ntp", "quic"]


class LiveZeekPipeline:
    """Integration pipeline that connects ZeekLogWatcher and IncrementalZeekReader to a log directory."""

    def __init__(
        self,
        log_dir: Union[str, Path],
        checkpoint_manager: Optional[CheckpointManager] = None,
        poll_interval: float = 1.0,
        tracked_logs: Optional[List[str]] = None,
    ) -> None:
        """Initialize LiveZeekPipeline for a target Zeek log directory.

        Args:
            log_dir: Path to directory containing active Zeek log files.
            checkpoint_manager: CheckpointManager instance. Uses default if None.
            poll_interval: Polling interval in seconds for continuous mode.
            tracked_logs: List of log type names to monitor (e.g. ['conn', 'dns', 'weird']).
        """
        self.log_dir = Path(log_dir).resolve()
        self.tracked_logs = tracked_logs if tracked_logs is not None else list(DEFAULT_TRACKED_LOGS)
        self.log_paths = [self.log_dir / f"{name}.log" for name in self.tracked_logs]

        self.checkpoint_manager = (
            checkpoint_manager if checkpoint_manager is not None else CheckpointManager()
        )
        self.reader = IncrementalZeekReader(self.checkpoint_manager)
        self.watcher = ZeekLogWatcher(
            log_paths=self.log_paths,
            reader=self.reader,
            poll_interval=poll_interval,
        )

    def poll_once(self) -> Dict[str, Any]:
        """Execute a single polling pass across all tracked log files in the directory.

        Returns:
            Dictionary with normalized flows, per-log records, summary counts, and raw watcher results:
            {
                "flows": List[FlowRecord],
                "logs": {
                    "conn": List[FlowRecord],
                    "dns": List[Dict[str, Any]],
                    "weird": List[Dict[str, Any]],
                    ...
                },
                "summary": {
                    "flows_count": int,
                    "total_records": int,
                    "conn_count": int,
                    "dns_count": int,
                    ...
                },
                "raw_results": Dict[str, Dict[str, Any]]
            }
        """
        raw_results = self.watcher.poll_once()

        log_data: Dict[str, List[Any]] = {}
        flows: List[FlowRecord] = []

        for name in self.tracked_logs:
            file_path_str = str(self.log_dir / f"{name}.log")
            file_res = raw_results.get(file_path_str, {})
            records = file_res.get("records", [])
            log_data[name] = records
            if name == "conn":
                flows = records

        summary = {
            "flows_count": len(flows),
            "total_records": sum(len(r) for r in log_data.values()),
        }
        for name, records in log_data.items():
            summary[f"{name}_count"] = len(records)

        return {
            "flows": flows,
            "logs": log_data,
            "summary": summary,
            "raw_results": raw_results,
        }

    def watch(
        self,
        max_polls: Optional[int] = None,
        stop_event: Optional[threading.Event] = None,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        """Run continuous polling loop over the Zeek log directory.

        Args:
            max_polls: Maximum polling passes to execute (useful for testing and bounded runs).
            stop_event: threading.Event signal to terminate watch loop cleanly.
            callback: Optional callable invoked with pipeline results after each poll pass.
        """
        poll_count = 0

        while True:
            if stop_event and stop_event.is_set():
                break

            if max_polls is not None and poll_count >= max_polls:
                break

            results = self.poll_once()
            poll_count += 1

            if callback:
                try:
                    callback(results)
                except Exception as e:
                    logger.error(f"Error executing live pipeline callback: {e}")

            if stop_event and stop_event.is_set():
                break

            if max_polls is not None and poll_count >= max_polls:
                break

            time.sleep(self.watcher.poll_interval)
