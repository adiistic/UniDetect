"""
UniDetect Ingestion Module

Provides passive log readers for Zeek TSV logs, offline capture files,
incremental log tailing, local file watching, live pipeline integration,
and state checkpoint management.
"""

from src.ingestion.checkpoint import CheckpointManager, get_file_identity
from src.ingestion.incremental_reader import IncrementalZeekReader
from src.ingestion.live_pipeline import LiveZeekPipeline
from src.ingestion.watcher import ZeekLogWatcher
from src.ingestion.zeek_reader import load_zeek_logs, read_zeek_log

__all__ = [
    "read_zeek_log",
    "load_zeek_logs",
    "CheckpointManager",
    "get_file_identity",
    "IncrementalZeekReader",
    "ZeekLogWatcher",
    "LiveZeekPipeline",
]
