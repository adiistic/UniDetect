"""
Unit tests for FlowRecord DTO schema and normalization (src/models/flow_record.py)
"""

import unittest

from src.models.flow_record import (
    Endpoint,
    FlowMetrics,
    FlowRecord,
    NetworkContext,
    normalize_conn_record,
)


class TestFlowRecord(unittest.TestCase):
    """Test suite verifying FlowRecord normalization and structure."""

    def test_normal_conn_record_normalization(self) -> None:
        """Test normalization of a complete, valid conn.log record."""
        raw_record = {
            "ts": "1618317000.123",
            "uid": "CH432111",
            "id.orig_h": "192.168.1.50",
            "id.orig_p": "51234",
            "id.resp_h": "192.168.1.1",
            "id.resp_p": "53",
            "proto": "udp",
            "service": "dns",
            "duration": "0.002341",
            "orig_bytes": "45",
            "resp_bytes": "110",
            "conn_state": "SF",
            "local_orig": "-",
            "local_resp": "-",
            "missed_bytes": "0",
            "history": "Dd",
            "orig_pkts": "1",
            "resp_pkts": "1",
        }

        flow = normalize_conn_record(raw_record)

        self.assertIsInstance(flow, FlowRecord)
        self.assertEqual(flow.timestamp, 1618317000.123)
        self.assertEqual(flow.uid, "CH432111")
        self.assertEqual(flow.source.ip, "192.168.1.50")
        self.assertEqual(flow.source.port, 51234)
        self.assertEqual(flow.destination.ip, "192.168.1.1")
        self.assertEqual(flow.destination.port, 53)
        self.assertEqual(flow.network.protocol, "udp")
        self.assertEqual(flow.network.service, "dns")
        self.assertEqual(flow.metrics.duration, 0.002341)
        self.assertEqual(flow.metrics.orig_bytes, 45)
        self.assertEqual(flow.metrics.resp_bytes, 110)
        self.assertEqual(flow.metrics.total_bytes, 155)
        self.assertEqual(flow.metrics.orig_packets, 1)
        self.assertEqual(flow.metrics.resp_packets, 1)
        self.assertEqual(flow.metrics.total_packets, 2)
        self.assertEqual(flow.metrics.bytes_per_packet, 77.5)
        self.assertEqual(flow.connection_state, "SF")

    def test_missing_dash_and_invalid_numeric_values(self) -> None:
        """Test normalization when fields contain '-', '(empty)', missing keys, or invalid string numbers."""
        raw_record = {
            "ts": "-",
            "uid": "CH999999",
            "id.orig_h": "10.0.0.5",
            "id.orig_p": "invalid_port",
            "id.resp_h": "-",
            "id.resp_p": "(empty)",
            "proto": "-",
            "service": "-",
            "duration": "invalid_duration",
            "orig_bytes": "-",
            "resp_bytes": "(empty)",
            "orig_pkts": "invalid_pkts",
            "resp_pkts": "-",
            "conn_state": "S0",
        }

        flow = normalize_conn_record(raw_record)

        self.assertEqual(flow.timestamp, 0.0)
        self.assertEqual(flow.uid, "CH999999")
        self.assertEqual(flow.source.ip, "10.0.0.5")
        self.assertEqual(flow.source.port, 0)
        self.assertEqual(flow.destination.ip, "")
        self.assertEqual(flow.destination.port, 0)
        self.assertEqual(flow.network.protocol, "")
        self.assertEqual(flow.network.service, "")
        self.assertEqual(flow.metrics.duration, 0.0)
        self.assertEqual(flow.metrics.orig_bytes, 0)
        self.assertEqual(flow.metrics.resp_bytes, 0)
        self.assertEqual(flow.metrics.total_bytes, 0)
        self.assertEqual(flow.metrics.orig_packets, 0)
        self.assertEqual(flow.metrics.resp_packets, 0)
        self.assertEqual(flow.metrics.total_packets, 0)
        self.assertEqual(flow.metrics.bytes_per_packet, 0.0)
        self.assertEqual(flow.connection_state, "S0")

    def test_zero_packets_safety(self) -> None:
        """Test that zero total packets result in 0.0 bytes_per_packet without division error."""
        raw_record = {
            "orig_bytes": "100",
            "resp_bytes": "100",
            "orig_pkts": "0",
            "resp_pkts": "0",
        }

        flow = normalize_conn_record(raw_record)

        self.assertEqual(flow.metrics.total_bytes, 200)
        self.assertEqual(flow.metrics.total_packets, 0)
        self.assertEqual(flow.metrics.bytes_per_packet, 0.0)

    def test_metadata_preservation(self) -> None:
        """Test that additional non-explicit Zeek fields are preserved in the metadata dictionary."""
        raw_record = {
            "uid": "C100",
            "id.orig_h": "192.168.1.1",
            "history": "ShADda",
            "local_orig": "T",
            "tunnel_parents": "-",
        }

        flow = normalize_conn_record(raw_record)

        self.assertIn("history", flow.metadata)
        self.assertEqual(flow.metadata["history"], "ShADda")
        self.assertIn("local_orig", flow.metadata)
        self.assertEqual(flow.metadata["local_orig"], "T")
        self.assertIn("tunnel_parents", flow.metadata)
        self.assertEqual(flow.metadata["tunnel_parents"], "-")

    def test_to_dict_conversion(self) -> None:
        """Test converting FlowRecord into a plain Python dictionary."""
        raw_record = {
            "ts": "100.0",
            "uid": "C200",
            "id.orig_h": "1.1.1.1",
            "id.orig_p": "80",
            "id.resp_h": "2.2.2.2",
            "id.resp_p": "443",
            "proto": "tcp",
            "service": "ssl",
            "conn_state": "SF",
        }

        flow = normalize_conn_record(raw_record)
        as_dict = flow.to_dict()

        self.assertIsInstance(as_dict, dict)
        self.assertEqual(as_dict["uid"], "C200")
        self.assertEqual(as_dict["source"], {"ip": "1.1.1.1", "port": 80})
        self.assertEqual(as_dict["destination"], {"ip": "2.2.2.2", "port": 443})
        self.assertEqual(as_dict["network"], {"protocol": "tcp", "service": "ssl"})
        self.assertEqual(as_dict["connection_state"], "SF")
        self.assertIsInstance(as_dict["metrics"], dict)
        self.assertIsInstance(as_dict["metadata"], dict)


if __name__ == "__main__":
    unittest.main()
