"""
UniDetect Models Package

Defines standardized Data Transfer Objects (DTOs) for network flow records.
"""

from src.models.flow_record import (
    Endpoint,
    FlowMetrics,
    FlowRecord,
    NetworkContext,
    normalize_conn_record,
)

__all__ = [
    "Endpoint",
    "NetworkContext",
    "FlowMetrics",
    "FlowRecord",
    "normalize_conn_record",
]
