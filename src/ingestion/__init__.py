"""
UniDetect Ingestion Module

Provides passive log readers for Zeek TSV logs, offline capture files,
incremental log tailing, and state checkpoint management.
"""

from src.ingestion.checkpoint import CheckpointManager, get_file_identity
from src.ingestion.incremental_reader import IncrementalZeekReader
from src.ingestion.zeek_reader import load_zeek_logs, read_zeek_log

__all__ = [
    "read_zeek_log",
    "load_zeek_logs",
    "CheckpointManager",
    "get_file_identity",
    "IncrementalZeekReader",
]
