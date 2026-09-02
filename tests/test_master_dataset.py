"""
Unit tests for UniDetect Master Dataset Builder (scripts/build_master_dataset.py)
"""

import csv
import json
import math
import unittest
from pathlib import Path

from scripts.build_master_dataset import RETAINED_EXPERIMENTS, build_master_dataset
from src.features.schema import FEATURE_COLUMNS, NUM_FEATURES, THREAT_CLASSES


class TestMasterDataset(unittest.TestCase):
    """Test suite verifying Master Dataset construction, integrity, and reproducibility."""

    @classmethod
    def setUpClass(cls) -> None:
        """Build master dataset before running tests."""
        cls.build_result = build_master_dataset()
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.master_dir = cls.repo_root / "data" / "master"
        cls.csv_path = cls.master_dir / "master_dataset.csv"
        cls.jsonl_path = cls.master_dir / "master_dataset.jsonl"
        cls.meta_path = cls.master_dir / "dataset_metadata.json"
        cls.profile_path = cls.master_dir / "DATASET_PROFILE.md"

    def test_files_exist(self) -> None:
        """Test that all master dataset files are generated and non-empty."""
        self.assertTrue(self.csv_path.exists(), "master_dataset.csv missing")
        self.assertTrue(self.jsonl_path.exists(), "master_dataset.jsonl missing")
        self.assertTrue(self.meta_path.exists(), "dataset_metadata.json missing")
        self.assertTrue(self.profile_path.exists(), "DATASET_PROFILE.md missing")

        self.assertGreater(self.csv_path.stat().st_size, 100000)
        self.assertGreater(self.jsonl_path.stat().st_size, 100000)

    def test_row_count_and_dimensionality(self) -> None:
        """Test that exactly 655 rows and 78 features are present across CSV and JSONL."""
        with open(self.jsonl_path, "r", encoding="utf-8") as f:
            jsonl_rows = [json.loads(line) for line in f]

        self.assertEqual(len(jsonl_rows), 655, "Expected 655 rows in JSONL")

        for i, row in enumerate(jsonl_rows):
            features = row["features"]
            self.assertEqual(
                len(features),
                NUM_FEATURES,
                f"Row {i} has {len(features)} features, expected {NUM_FEATURES}",
            )
            for j, val in enumerate(features):
                self.assertIsInstance(val, (int, float), f"Row {i} feature {j} non-numeric")
                self.assertFalse(math.isnan(val), f"Row {i} feature {j} is NaN")
                self.assertFalse(math.isinf(val), f"Row {i} feature {j} is Inf")

    def test_csv_header_and_column_alignment(self) -> None:
        """Test that CSV header contains 12 metadata columns and 78 exact schema feature columns."""
        with open(self.csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            csv_rows = list(reader)

        self.assertEqual(len(csv_rows), 655, "Expected 655 rows in CSV")
        self.assertEqual(len(header), 12 + NUM_FEATURES, "Expected 90 columns in CSV")

        feature_headers = header[12:]
        self.assertEqual(feature_headers, FEATURE_COLUMNS, "CSV feature columns misaligned with schema")

    def test_label_and_provenance_integrity(self) -> None:
        """Test that every row's label matches its label_id and corresponds to a retained experiment."""
        retained_exp_ids = {Path(p).name for _, p in RETAINED_EXPERIMENTS}

        with open(self.jsonl_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                rec = json.loads(line)
                label = rec["label"]
                label_id = rec["label_id"]
                exp_id = rec["experiment_id"]

                self.assertIn(exp_id, retained_exp_ids, f"Row {i} experiment {exp_id} not retained")
                self.assertEqual(
                    THREAT_CLASSES[label_id],
                    label,
                    f"Row {i} label {label} mismatch with label_id {label_id}",
                )

    def test_metadata_summary(self) -> None:
        """Test dataset_metadata.json structure and class totals."""
        with open(self.meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        self.assertEqual(meta["total_rows"], 655)
        self.assertEqual(meta["total_features"], 78)
        self.assertEqual(meta["class_distribution"]["BENIGN"], 143)
        self.assertEqual(meta["class_distribution"]["DDOS"], 301)
        self.assertEqual(meta["class_distribution"]["RECON"], 59)
        self.assertEqual(meta["class_distribution"]["DNS_TUNNEL"], 52)
        self.assertEqual(meta["class_distribution"]["C2_BEACON"], 50)
        self.assertEqual(meta["class_distribution"]["SLOW_HTTP"], 50)


if __name__ == "__main__":
    unittest.main()
