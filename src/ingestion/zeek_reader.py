"""
Zeek TSV Log Reader for UniDetect

This module safely and passively reads Zeek TSV (Tab-Separated Value) log files
from disk without opening network sockets or modifying source log files.
"""

import os
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

logger = logging.getLogger(__name__)

SUPPORTED_LOG_TYPES = ["conn", "dns", "weird", "ntp", "quic"]


def read_zeek_log(file_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Read a single Zeek TSV log file and return records as a list of dictionaries.

    Args:
        file_path: Path to the Zeek log file (e.g., conn.log).

    Returns:
        A list of dictionaries where keys correspond to field headers in the Zeek log.
        Returns an empty list if the file is missing, empty, or invalid.
    """
    path = Path(file_path)
    if not path.is_file():
        logger.warning(f"Zeek log file not found: {file_path}")
        return []

    records: List[Dict[str, Any]] = []
    fields: List[str] = []
    separator = "\t"

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                stripped_line = line.strip("\r\n")

                # Skip completely blank lines
                if not stripped_line:
                    continue

                # Handle header / metadata lines starting with '#'
                if stripped_line.startswith("#"):
                    if stripped_line.startswith("#separator"):
                        # Parse custom separator if present e.g. '#separator \x09'
                        parts = stripped_line.split()
                        if len(parts) >= 2:
                            raw_sep = parts[1]
                            if raw_sep.startswith("\\x"):
                                try:
                                    separator = chr(int(raw_sep[2:], 16))
                                except ValueError:
                                    separator = "\t"
                            else:
                                separator = raw_sep
                    elif stripped_line.startswith("#fields"):
                        # Header defining column names
                        header_parts = stripped_line.split(separator)
                        if len(header_parts) > 1:
                            fields = [p.strip() for p in header_parts[1:]]
                    continue

                # Record row - requires field headers to be set
                if not fields:
                    logger.warning(
                        f"Skipping record at line {line_num} in {path.name}: #fields header missing."
                    )
                    continue

                values = stripped_line.split(separator)

                # Handle malformed rows safely
                if len(values) != len(fields):
                    logger.warning(
                        f"Malformed row at line {line_num} in {path.name}: "
                        f"expected {len(fields)} fields, got {len(values)}. Row skipped."
                    )
                    continue

                record = dict(zip(fields, values))
                records.append(record)

    except Exception as e:
        logger.error(f"Error reading Zeek log {file_path}: {e}")
        return []

    return records


def load_zeek_logs(directory: Union[str, Path]) -> Dict[str, List[Dict[str, Any]]]:
    """Load all supported Zeek log files from a target directory.

    Supported log files include: conn.log, dns.log, weird.log, ntp.log, quic.log.

    Args:
        directory: Path to directory containing Zeek log files.

    Returns:
        A dictionary mapping log types (e.g. 'conn', 'dns') to lists of parsed records.
    """
    dir_path = Path(directory)
    results: Dict[str, List[Dict[str, Any]]] = {}

    for log_name in SUPPORTED_LOG_TYPES:
        file_name = f"{log_name}.log"
        file_path = dir_path / file_name

        if file_path.is_file():
            results[log_name] = read_zeek_log(file_path)
        else:
            logger.info(f"Log file '{file_name}' not found in {dir_path}. Returning empty list.")
            results[log_name] = []

    return results
