# UniDetect Source Directory (`src`)

This directory contains the Python modules and main entry points for the UniDetect passive analysis system.

## Submodules
- `models/`: Standardized Data Transfer Objects (DTOs) for handoff between system components.
  - `flow_record.py`: Defines `FlowRecord`, `Endpoint`, `NetworkContext`, `FlowMetrics`, and `normalize_conn_record()` to structure raw `conn.log` entries into typed flow objects.
- `features/`: Converts raw ingested Zeek log entries into structured, normalized feature sets and summary statistics.
  - `extractor.py`: Functions `extract_connection_features`, `extract_dns_features`, and `extract_all_features`.
- `ingestion/`: Ingests offline network logs (Zeek TSV files) safely without opening network sockets or transmitting packets.
  - `zeek_reader.py`: Parses Zeek headers (`#fields`, `#separator`), ignores metadata, and converts TSV records into Python dictionaries.
- `main.py`: CLI entry point for running passive analysis workflows.

## Security Constraints
All source code residing in `src/` must adhere strictly to passive monitoring principles:
- **Read-Only Inspection**: Inspect packets or log stream data in-memory or from disk.
- **No Active Network I/O**: Do not construct, send, transmit, block, or modify any network packets.
