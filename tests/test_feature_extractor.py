"""
Unit tests for UniDetect Feature Extractor (src/features/extractor.py)
"""

import unittest

from src.features.extractor import (
    extract_all_features,
    extract_connection_features,
    extract_dns_features,
    safe_float,
    safe_int,
)


class TestFeatureExtractor(unittest.TestCase):
    """Test suite for network feature extraction and summary statistics."""

    def test_safe_helpers(self) -> None:
        """Test safe numeric conversions for missing, dash, and empty values."""
        self.assertEqual(safe_int("-"), 0)
        self.assertEqual(safe_int("(empty)"), 0)
        self.assertEqual(safe_int(None), 0)
        self.assertEqual(safe_int("100"), 100)

        self.assertEqual(safe_float("-"), 0.0)
        self.assertEqual(safe_float("(empty)"), 0.0)
        self.assertEqual(safe_float(None), 0.0)
        self.assertEqual(safe_float("12.34"), 12.34)

    def test_extract_connection_features_normal(self) -> None:
        """Test normal connection feature extraction and total byte/packet calculation."""
        raw_conn = [
            {
                "uid": "C12345",
                "ts": "1618317000.100",
                "id.orig_h": "192.168.1.10",
                "id.orig_p": "50000",
                "id.resp_h": "10.0.0.1",
                "id.resp_p": "80",
                "proto": "tcp",
                "service": "http",
                "duration": "1.5",
                "orig_bytes": "100",
                "resp_bytes": "400",
                "orig_pkts": "2",
                "resp_pkts": "3",
                "conn_state": "SF",
                "missed_bytes": "0",
            }
        ]

        features = extract_connection_features(raw_conn)
        self.assertEqual(len(features), 1)

        f = features[0]
        self.assertEqual(f["uid"], "C12345")
        self.assertEqual(f["timestamp"], 1618317000.100)
        self.assertEqual(f["source_ip"], "192.168.1.10")
        self.assertEqual(f["source_port"], 50000)
        self.assertEqual(f["destination_ip"], "10.0.0.1")
        self.assertEqual(f["destination_port"], 80)
        self.assertEqual(f["protocol"], "tcp")
        self.assertEqual(f["service"], "http")
        self.assertEqual(f["duration"], 1.5)
        self.assertEqual(f["orig_bytes"], 100)
        self.assertEqual(f["resp_bytes"], 400)
        self.assertEqual(f["total_bytes"], 500)
        self.assertEqual(f["orig_pkts"], 2)
        self.assertEqual(f["resp_pkts"], 3)
        self.assertEqual(f["total_packets"], 5)
        self.assertEqual(f["bytes_per_packet"], 100.0)
        self.assertEqual(f["connection_state"], "SF")

    def test_extract_connection_missing_numeric_and_dash_values(self) -> None:
        """Test connection records containing '-' and missing numeric fields."""
        raw_conn = [
            {
                "uid": "C99999",
                "ts": "-",
                "id.orig_h": "192.168.1.50",
                "id.orig_p": "-",
                "id.resp_h": "8.8.8.8",
                "id.resp_p": "53",
                "proto": "udp",
                "service": "-",
                "duration": "-",
                "orig_bytes": "-",
                "resp_bytes": "(empty)",
                "orig_pkts": "-",
                "resp_pkts": "-",
                "conn_state": "S0",
            }
        ]

        features = extract_connection_features(raw_conn)
        self.assertEqual(len(features), 1)

        f = features[0]
        self.assertEqual(f["service"], "")
        self.assertEqual(f["orig_bytes"], 0)
        self.assertEqual(f["resp_bytes"], 0)
        self.assertEqual(f["total_bytes"], 0)
        self.assertEqual(f["total_packets"], 0)
        self.assertEqual(f["bytes_per_packet"], 0.0)

    def test_zero_packets_division_safety(self) -> None:
        """Test zero packets safety when calculating bytes_per_packet."""
        raw_conn = [
            {
                "orig_bytes": "50",
                "resp_bytes": "50",
                "orig_pkts": "0",
                "resp_pkts": "0",
            }
        ]
        features = extract_connection_features(raw_conn)
        self.assertEqual(features[0]["total_packets"], 0)
        self.assertEqual(features[0]["bytes_per_packet"], 0.0)

    def test_extract_dns_features_and_answers_count(self) -> None:
        """Test DNS feature extraction and answer list parsing."""
        raw_dns = [
            {
                "uid": "D10101",
                "ts": "1618317005.0",
                "id.orig_h": "192.168.1.10",
                "id.resp_h": "1.1.1.1",
                "query": "example.com",
                "qtype_name": "A",
                "rcode_name": "NOERROR",
                "answers": "93.184.216.34, 93.184.216.35",
            },
            {
                "uid": "D10102",
                "ts": "1618317006.0",
                "id.orig_h": "192.168.1.10",
                "id.resp_h": "1.1.1.1",
                "query": "nonexistent.test",
                "qtype_name": "A",
                "rcode_name": "NXDOMAIN",
                "answers": "-",
            },
        ]

        dns_features = extract_dns_features(raw_dns)
        self.assertEqual(len(dns_features), 2)

        self.assertEqual(dns_features[0]["answer_count"], 2)
        self.assertEqual(
            dns_features[0]["answers"], ["93.184.216.34", "93.184.216.35"]
        )

        self.assertEqual(dns_features[1]["answer_count"], 0)
        self.assertEqual(dns_features[1]["answers"], [])

    def test_extract_all_features_summary_statistics(self) -> None:
        """Test high-level extract_all_features function and computed summary statistics."""
        log_data = {
            "conn": [
                {
                    "uid": "C1",
                    "id.orig_h": "192.168.1.10",
                    "id.resp_h": "10.0.0.1",
                    "proto": "tcp",
                    "service": "http",
                    "conn_state": "SF",
                    "orig_bytes": "100",
                    "resp_bytes": "200",
                    "orig_pkts": "2",
                    "resp_pkts": "2",
                },
                {
                    "uid": "C2",
                    "id.orig_h": "192.168.1.20",
                    "id.resp_h": "10.0.0.1",
                    "proto": "udp",
                    "service": "dns",
                    "conn_state": "SF",
                    "orig_bytes": "50",
                    "resp_bytes": "50",
                    "orig_pkts": "1",
                    "resp_pkts": "1",
                },
            ],
            "dns": [
                {
                    "uid": "D1",
                    "id.orig_h": "192.168.1.10",
                    "id.resp_h": "1.1.1.1",
                    "query": "test.org",
                }
            ],
        }

        extracted = extract_all_features(log_data)
        summary = extracted["summary"]

        self.assertEqual(summary["total_connections"], 2)
        self.assertEqual(summary["total_dns_queries"], 1)
        self.assertEqual(summary["unique_source_ips"], 2)  # 192.168.1.10, 192.168.1.20
        self.assertEqual(summary["unique_destination_ips"], 2)  # 10.0.0.1, 1.1.1.1
        self.assertEqual(summary["total_bytes_observed"], 400)  # (100+200) + (50+50)
        self.assertEqual(summary["total_packets_observed"], 6)  # (2+2) + (1+1)
        self.assertEqual(summary["protocols"], {"tcp": 1, "udp": 1})
        self.assertEqual(summary["services"], {"http": 1, "dns": 1})
        self.assertEqual(summary["connection_states"], {"SF": 2})


if __name__ == "__main__":
    unittest.main()
