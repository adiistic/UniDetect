"""
UniDetect Ingestion Module

Provides passive log readers for Zeek TSV logs and offline capture files.
"""

from src.ingestion.zeek_reader import load_zeek_logs, read_zeek_log

__all__ = ["read_zeek_log", "load_zeek_logs"]
