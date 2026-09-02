"""
Unit Tests for UniDetect Feature Engineering (Person 2 - Phase 4)

Tests:
- Shannon entropy calculation
- Linguistic / DNS domain metric calculation
- Flow-level feature extraction
- Event log extraction (DNS, QUIC, Weird, SSL)
- Multi-log correlation
- Sliding-window aggregations (10s, 60s, 300s)
- Missing log resilience & deterministic neutral defaults
- 78-feature vector column ordering & determinism
- Batch feature matrix generation on sample Zeek logs
"""

import math
import unittest
from pathlib import Path

from src.features.correlator import LogCorrelator
from src.features.math_utils import (
    dns_max_label_len,
    dns_numeric_ratio,
    dns_subdomain_depth,
    dns_vowel_ratio,
    is_private_ip,
    shannon_entropy,
)
from src.features.schema import (
    FEATURE_COLUMNS,
    FEATURE_DEFAULTS,
    FEATURE_INDICES,
    NUM_FEATURES,
)
from src.features.vector_assembler import (
    FeatureVectorAssembler,
    extract_feature_matrix,
)
from src.features.window_aggregator import WindowAggregator
from src.ingestion.zeek_reader import load_zeek_logs
from src.models.flow_record import (
    Endpoint,
    FlowMetrics,
    FlowRecord,
    NetworkContext,
    normalize_conn_record,
)


class TestMathAndLinguisticUtils(unittest.TestCase):
    """Test suite for math_utils module."""

    def test_shannon_entropy(self) -> None:
        # Edge cases
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy(None), 0.0)
        self.assertEqual(shannon_entropy("a"), 0.0)
        self.assertEqual(shannon_entropy("aaaaaaa"), 0.0)

        # 2 equally likely characters -> log2(2) = 1.0 bit
        self.assertAlmostEqual(shannon_entropy("ab"), 1.0, places=4)
        self.assertAlmostEqual(shannon_entropy("aabb"), 1.0, places=4)

        # 4 equally likely characters -> log2(4) = 2.0 bits
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0, places=4)

        # High entropy pseudo-random domain vs standard natural domain
        normal_entropy = shannon_entropy("google.com")
        dga_entropy = shannon_entropy("x8q9z3p4m1k2v7w5.com")
        self.assertGreater(dga_entropy, normal_entropy)

    def test_is_private_ip(self) -> None:
        # RFC1918 Private IPs
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("10.0.0.50"))
        self.assertTrue(is_private_ip("172.16.0.1"))
        self.assertTrue(is_private_ip("172.31.255.255"))
        self.assertTrue(is_private_ip("127.0.0.1"))

        # Public IPs
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("93.184.216.34"))
        self.assertFalse(is_private_ip("142.250.190.46"))

        # Invalid / missing
        self.assertFalse(is_private_ip("-"))
        self.assertFalse(is_private_ip("(empty)"))
        self.assertFalse(is_private_ip(""))
        self.assertFalse(is_private_ip(None))
        self.assertFalse(is_private_ip("not_an_ip"))

    def test_dns_lexical_helpers(self) -> None:
        # Vowel ratio
        self.assertEqual(dns_vowel_ratio(""), 0.0)
        self.assertEqual(dns_vowel_ratio(None), 0.0)
        self.assertEqual(dns_vowel_ratio("bcdfg.com"), 0.125)  # 'o' in com out of 8 alphas
        self.assertEqual(dns_vowel_ratio("aeiou.com"), 0.75)  # 6 vowels out of 8 alphas

        # Numeric ratio
        self.assertEqual(dns_numeric_ratio(""), 0.0)
        self.assertEqual(dns_numeric_ratio("example.com"), 0.0)
        self.assertAlmostEqual(dns_numeric_ratio("1234.com"), 4.0 / 7.0, places=4)

        # Subdomain depth
        self.assertEqual(dns_subdomain_depth("com"), 0)
        self.assertEqual(dns_subdomain_depth("example.com"), 1)
        self.assertEqual(dns_subdomain_depth("sub.example.com"), 2)
        self.assertEqual(dns_subdomain_depth("a.b.c.d.tunnel.com"), 5)

        # Max label length
        self.assertEqual(dns_max_label_len(""), 0)
        self.assertEqual(dns_max_label_len("a.verylongsubdomainlabelhere.com"), 26)


class TestFeatureVectorAssembler(unittest.TestCase):
    """Test suite for feature extraction and vector assembly."""

    def setUp(self) -> None:
        self.assembler = FeatureVectorAssembler()
        self.sample_flow = FlowRecord(
            timestamp=1618317000.100,
            uid="C_TEST_01",
            source=Endpoint(ip="192.168.1.50", port=51234),
            destination=Endpoint(ip="93.184.216.34", port=80),
            network=NetworkContext(protocol="tcp", service="http"),
            metrics=FlowMetrics(
                duration=0.5,
                orig_bytes=1000,
                resp_bytes=4000,
                total_bytes=5000,
                orig_packets=10,
                resp_packets=20,
                total_packets=30,
                bytes_per_packet=166.6667,
                missed_bytes=0,
            ),
            connection_state="SF",
            metadata={"history": "ShADda", "orig_ip_bytes": 1400, "resp_ip_bytes": 4800},
        )

    def test_schema_exactness(self) -> None:
        self.assertEqual(NUM_FEATURES, 78)
        self.assertEqual(len(FEATURE_COLUMNS), 78)
        self.assertEqual(len(FEATURE_INDICES), 78)
        self.assertEqual(FEATURE_COLUMNS[0], "flow_duration")
        self.assertEqual(FEATURE_COLUMNS[77], "win_pair_total_orig_bytes_300s")

    def test_flow_features_extraction(self) -> None:
        flow_feats = self.assembler.extract_flow_features(self.sample_flow)
        self.assertEqual(flow_feats["flow_duration"], 0.5)
        self.assertEqual(flow_feats["orig_bytes"], 1000.0)
        self.assertEqual(flow_feats["resp_bytes"], 4000.0)
        self.assertEqual(flow_feats["total_bytes"], 5000.0)
        self.assertEqual(flow_feats["orig_packets"], 10.0)
        self.assertEqual(flow_feats["resp_packets"], 20.0)
        self.assertEqual(flow_feats["total_packets"], 30.0)
        self.assertAlmostEqual(flow_feats["orig_bytes_ratio"], 1000.0 / 5001.0, places=3)
        self.assertEqual(flow_feats["is_well_known_dst_port"], 1.0)  # Port 80 < 1024
        self.assertEqual(flow_feats["is_registered_dst_port"], 0.0)
        self.assertEqual(flow_feats["is_dynamic_dst_port"], 0.0)
        self.assertEqual(flow_feats["is_src_private_ip"], 1.0)
        self.assertEqual(flow_feats["is_dst_private_ip"], 0.0)
        self.assertEqual(flow_feats["proto_is_tcp"], 1.0)
        self.assertEqual(flow_feats["proto_is_udp"], 0.0)
        self.assertEqual(flow_feats["conn_state_is_SF"], 1.0)
        self.assertEqual(flow_feats["conn_state_is_S0"], 0.0)
        self.assertEqual(flow_feats["history_has_syn"], 1.0)
        self.assertEqual(flow_feats["history_len"], 6.0)

    def test_dns_features_extraction(self) -> None:
        dns_rec = {
            "query": "c2-tunnel.data.example.com",
            "qtype_name": "TXT",
            "rcode_name": "NOERROR",
            "answers": ["encodedpayload1", "encodedpayload2"],
            "rtt": "0.015",
        }
        dns_feats = self.assembler.extract_dns_features(dns_rec)
        self.assertEqual(dns_feats["has_dns_context"], 1.0)
        self.assertEqual(dns_feats["dns_query_len"], len("c2-tunnel.data.example.com"))
        self.assertGreater(dns_feats["dns_query_entropy"], 2.0)
        self.assertEqual(dns_feats["dns_subdomain_depth"], 3.0)
        self.assertEqual(dns_feats["dns_qtype_is_TXT"], 1.0)
        self.assertEqual(dns_feats["dns_qtype_is_A"], 0.0)
        self.assertEqual(dns_feats["dns_is_nxdomain"], 0.0)
        self.assertEqual(dns_feats["dns_answer_count"], 2.0)
        self.assertAlmostEqual(dns_feats["dns_rtt"], 0.015, places=3)

    def test_missing_dns_record_defaults(self) -> None:
        dns_feats = self.assembler.extract_dns_features(None)
        self.assertEqual(dns_feats["has_dns_context"], 0.0)
        self.assertEqual(dns_feats["dns_query_len"], 0.0)
        self.assertEqual(dns_feats["dns_query_entropy"], 0.0)
        self.assertEqual(dns_feats["dns_is_nxdomain"], 0.0)
        self.assertEqual(dns_feats["dns_answer_count"], 0.0)

    def test_quic_features_extraction(self) -> None:
        quic_rec = {
            "server_name": "encrypted.c2.io",
            "client_initial_dcid": "abcdef123456",
        }
        quic_feats = self.assembler.extract_quic_features(quic_rec)
        self.assertEqual(quic_feats["has_quic_context"], 1.0)
        self.assertEqual(quic_feats["quic_sni_len"], len("encrypted.c2.io"))
        self.assertGreater(quic_feats["quic_sni_entropy"], 2.0)
        self.assertEqual(quic_feats["quic_dcid_len"], 12.0)

    def test_weird_features_extraction(self) -> None:
        weird_recs = [
            {"name": "bad_SYN_ack", "notice": "F"},
            {"name": "bad_HTTP_request", "notice": "T"},
        ]
        weird_feats = self.assembler.extract_weird_features(weird_recs)
        self.assertEqual(weird_feats["has_weird_anomaly"], 1.0)
        self.assertEqual(weird_feats["weird_anomaly_count_flow"], 2.0)
        self.assertEqual(weird_feats["weird_is_bad_syn_ack"], 1.0)
        self.assertEqual(weird_feats["weird_is_bad_http"], 1.0)
        self.assertEqual(weird_feats["weird_notice_flag"], 1.0)

    def test_ssl_features_extraction(self) -> None:
        ssl_rec = {
            "server_name": "malware-c2.net",
            "version": "TLSv10",
            "validation_status": "self signed certificate",
            "subject": "CN=Malware",
            "issuer": "CN=Malware",
            "ja3": "ada70206e40642a3e4461f35503241d5",
            "resumed": "T",
        }
        ssl_feats = self.assembler.extract_ssl_features(ssl_rec)
        self.assertEqual(ssl_feats["has_ssl_context"], 1.0)
        self.assertEqual(ssl_feats["ssl_is_outdated_version"], 1.0)
        self.assertEqual(ssl_feats["ssl_is_self_signed"], 1.0)
        self.assertEqual(ssl_feats["ssl_has_ja3_fingerprint"], 1.0)
        self.assertEqual(ssl_feats["ssl_resumed_flag"], 1.0)


class TestWindowAggregatorAndCorrelation(unittest.TestCase):
    """Test suite for sliding window calculations and multi-log correlation."""

    def test_sliding_window_calculations(self) -> None:
        # Create a series of 4 flows from 192.168.1.100
        # Flow 1 at t=100 to 10.0.0.1:80 (SF)
        # Flow 2 at t=110 to 10.0.0.1:80 (SF)
        # Flow 3 at t=120 to 10.0.0.2:443 (S0)
        # Flow 4 at t=130 to 10.0.0.3:8080 (REJ)
        flows = [
            FlowRecord(
                timestamp=100.0,
                uid="UID_1",
                source=Endpoint("192.168.1.100", 50001),
                destination=Endpoint("10.0.0.1", 80),
                network=NetworkContext("tcp", "http"),
                metrics=FlowMetrics(0.1, 100, 200, 300, 2, 2, 4, 75.0, 0),
                connection_state="SF",
            ),
            FlowRecord(
                timestamp=110.0,
                uid="UID_2",
                source=Endpoint("192.168.1.100", 50002),
                destination=Endpoint("10.0.0.1", 80),
                network=NetworkContext("tcp", "http"),
                metrics=FlowMetrics(0.1, 100, 200, 300, 2, 2, 4, 75.0, 0),
                connection_state="SF",
            ),
            FlowRecord(
                timestamp=120.0,
                uid="UID_3",
                source=Endpoint("192.168.1.100", 50003),
                destination=Endpoint("10.0.0.2", 443),
                network=NetworkContext("tcp", "ssl"),
                metrics=FlowMetrics(0.01, 0, 0, 0, 1, 0, 1, 0.0, 0),
                connection_state="S0",
            ),
            FlowRecord(
                timestamp=130.0,
                uid="UID_4",
                source=Endpoint("192.168.1.100", 50004),
                destination=Endpoint("10.0.0.3", 8080),
                network=NetworkContext("tcp", ""),
                metrics=FlowMetrics(0.01, 0, 0, 0, 1, 0, 1, 0.0, 0),
                connection_state="REJ",
            ),
        ]

        aggregator = WindowAggregator(flows=flows)
        target_flow = flows[3]  # at t=130

        win_feats = aggregator.compute_window_features(target_flow)

        # In [130-60, 130] = [70, 130], all 4 flows are present
        self.assertEqual(win_feats["win_src_flow_count_60s"], 4.0)
        self.assertEqual(win_feats["win_src_unique_dst_ips_60s"], 3.0)  # 10.0.0.1, 10.0.0.2, 10.0.0.3
        self.assertEqual(win_feats["win_src_unique_dst_ports_60s"], 3.0)  # 80, 443, 8080

        # Failed flows: UID_3 (S0), UID_4 (REJ) -> 2 out of 4 = 0.5
        self.assertEqual(win_feats["win_src_failed_conn_ratio_60s"], 0.5)

        # S0 flows: UID_3 -> 1 out of 4 = 0.25
        self.assertEqual(win_feats["win_src_s0_syn_ratio_60s"], 0.25)

        # In [130-10, 130] = [120, 130], flows at t=120 and t=130 -> 2 flows / 10s = 0.2 flows/s
        self.assertEqual(win_feats["win_src_flow_rate_10s"], 0.2)

        # Total orig bytes in 300s: 100 + 100 + 0 + 0 = 200
        self.assertEqual(win_feats["win_src_total_orig_bytes_300s"], 200.0)

    def test_beaconing_pair_metrics(self) -> None:
        # Periodic C2 beaconing between host pair at strict 30s intervals
        flows = [
            FlowRecord(
                timestamp=100.0,
                uid="B1",
                source=Endpoint("192.168.1.50", 40001),
                destination=Endpoint("45.33.32.156", 443),
                network=NetworkContext("tcp", "ssl"),
                metrics=FlowMetrics(0.2, 128, 64, 192, 3, 2, 5, 38.4, 0),
                connection_state="SF",
            ),
            FlowRecord(
                timestamp=130.0,
                uid="B2",
                source=Endpoint("192.168.1.50", 40002),
                destination=Endpoint("45.33.32.156", 443),
                network=NetworkContext("tcp", "ssl"),
                metrics=FlowMetrics(0.2, 128, 64, 192, 3, 2, 5, 38.4, 0),
                connection_state="SF",
            ),
            FlowRecord(
                timestamp=160.0,
                uid="B3",
                source=Endpoint("192.168.1.50", 40003),
                destination=Endpoint("45.33.32.156", 443),
                network=NetworkContext("tcp", "ssl"),
                metrics=FlowMetrics(0.2, 128, 64, 192, 3, 2, 5, 38.4, 0),
                connection_state="SF",
            ),
        ]

        aggregator = WindowAggregator(flows=flows)
        win_feats = aggregator.compute_window_features(flows[2])

        self.assertEqual(win_feats["win_pair_flow_count_300s"], 3.0)
        self.assertAlmostEqual(win_feats["win_pair_delta_t_mean"], 30.0, places=2)
        # Standard deviation of delta_t (30, 30) is 0.0
        self.assertAlmostEqual(win_feats["win_pair_delta_t_std"], 0.0, places=2)
        self.assertAlmostEqual(win_feats["win_pair_delta_t_cv"], 0.0, places=2)
        # Uniform payload of 128 bytes -> std is 0.0
        self.assertAlmostEqual(win_feats["win_pair_orig_bytes_std"], 0.0, places=2)


class TestFullVectorAssemblyAndDeterminism(unittest.TestCase):
    """Test suite for complete 78-feature vector assembly and reproducibility."""

    def test_vector_length_and_order(self) -> None:
        assembler = FeatureVectorAssembler()
        flow = FlowRecord(
            timestamp=1618317000.0,
            uid="C_ORDER_TEST",
            source=Endpoint("192.168.1.50", 55555),
            destination=Endpoint("8.8.8.8", 53),
            network=NetworkContext("udp", "dns"),
            metrics=FlowMetrics(0.01, 50, 100, 150, 1, 1, 2, 75.0, 0),
            connection_state="SF",
        )
        vec = assembler.assemble_feature_vector(flow)

        self.assertEqual(len(vec), 78)
        for val in vec:
            self.assertIsInstance(val, float)
            self.assertFalse(math.isnan(val))
            self.assertFalse(math.isinf(val))

    def test_determinism(self) -> None:
        assembler = FeatureVectorAssembler()
        flow = FlowRecord(
            timestamp=1618317000.0,
            uid="C_DETERMINISTIC",
            source=Endpoint("192.168.1.50", 55555),
            destination=Endpoint("8.8.8.8", 53),
            network=NetworkContext("udp", "dns"),
            metrics=FlowMetrics(0.01, 50, 100, 150, 1, 1, 2, 75.0, 0),
            connection_state="SF",
        )

        vec1 = assembler.assemble_feature_vector(flow)
        vec2 = assembler.assemble_feature_vector(flow)
        self.assertEqual(vec1, vec2)

    def test_extract_feature_matrix_on_sample_zeek_logs(self) -> None:
        log_dir = Path("data/zeek_logs")
        logs = load_zeek_logs(log_dir)

        feature_cols, matrix, flows = extract_feature_matrix(logs)

        self.assertEqual(len(feature_cols), 78)
        self.assertEqual(len(matrix), 2)  # conn.log in data/zeek_logs has 2 sample records
        self.assertEqual(len(flows), 2)

        for row in matrix:
            self.assertEqual(len(row), 78)
            for val in row:
                self.assertFalse(math.isnan(val))
                self.assertFalse(math.isinf(val))

        # Check that DNS log record correlated with UID CH432111
        flow1 = flows[0]
        self.assertEqual(flow1.uid, "CH432111")
        row1 = matrix[0]
        # has_dns_context is index 27
        self.assertEqual(row1[FEATURE_INDICES["has_dns_context"]], 1.0)
        self.assertEqual(row1[FEATURE_INDICES["dns_query_len"]], len("example.com"))
        self.assertEqual(row1[FEATURE_INDICES["dns_qtype_is_A"]], 1.0)


if __name__ == "__main__":
    unittest.main()
