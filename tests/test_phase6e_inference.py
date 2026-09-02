"""
Unit tests for Phase 6E Inference Layer, Feature Contract, and Serialized Artifacts
"""

import math
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from src.features.schema import FEATURE_COLUMNS, NUM_FEATURES, THREAT_CLASSES
from src.inference.contract import FeatureContract, FeatureContractValidationError
from src.inference.detector import ThreatDetector
from src.inference.loader import ModelArtifactLoadingError, ModelLoader
from src.inference.policy import DecisionPolicy


class TestPhase6EInference(unittest.TestCase):
    """Test suite verifying frozen feature contract, serialized model loading, and deterministic inference."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.model_dir = cls.repo_root / "models" / "phase6e"
        cls.csv_path = cls.repo_root / "data" / "master" / "master_dataset.csv"

        if not cls.model_dir.exists():
            from scripts.serialize_phase6e_model import serialize_phase6e_artifacts
            serialize_phase6e_artifacts()

        cls.detector = ThreatDetector.from_artifact_dir(cls.model_dir)
        cls.df = pd.read_csv(cls.csv_path)

    def test_artifact_files_exist(self) -> None:
        """Verify all 4 required artifact files exist on disk."""
        model_file = self.model_dir / "model" / "model.joblib"
        meta_file = self.model_dir / "metadata" / "model_metadata.json"
        contract_file = self.model_dir / "feature_contract" / "feature_contract.json"
        policy_file = self.model_dir / "thresholds" / "decision_policy.json"

        self.assertTrue(model_file.exists(), "model.joblib missing")
        self.assertTrue(meta_file.exists(), "model_metadata.json missing")
        self.assertTrue(contract_file.exists(), "feature_contract.json missing")
        self.assertTrue(policy_file.exists(), "decision_policy.json missing")

        self.assertGreater(model_file.stat().st_size, 50000)

    def test_model_loader_success(self) -> None:
        """Verify ModelLoader properly instantiates all components."""
        model, metadata, contract, policy = ModelLoader.load_artifacts(self.model_dir)
        self.assertIsNotNone(model)
        self.assertEqual(metadata["model_version"], "unidetect-hgb-calibrated-v1.0.0")
        self.assertEqual(contract.num_features, 78)
        self.assertEqual(policy.abstain_threshold, 0.40)

    def test_invalid_model_dir_raises(self) -> None:
        """Verify ModelLoader raises ModelArtifactLoadingError for non-existent directory."""
        with self.assertRaises(ModelArtifactLoadingError):
            ModelLoader.load_artifacts(self.repo_root / "non_existent_model_dir")

    def test_valid_dict_prediction(self) -> None:
        """Verify ThreatDetector correctly processes a 78-feature dictionary input."""
        sample_row = self.df.iloc[0][FEATURE_COLUMNS].to_dict()
        verdict = self.detector.predict_single(sample_row)

        self.assertIn("predicted_class_id", verdict)
        self.assertIn("predicted_label", verdict)
        self.assertIn("confidence", verdict)
        self.assertIn("probabilities", verdict)
        self.assertIn("abstained", verdict)
        self.assertIn("decision", verdict)
        self.assertEqual(verdict["model_version"], "unidetect-hgb-calibrated-v1.0.0")
        self.assertEqual(verdict["schema_version"], "1.0.0")
        self.assertEqual(len(verdict["probabilities"]), 6)

    def test_valid_list_and_array_prediction(self) -> None:
        """Verify ThreatDetector accepts 1D lists and numpy arrays."""
        sample_list = self.df.iloc[0][FEATURE_COLUMNS].tolist()
        sample_arr = np.array(sample_list, dtype=np.float64)

        verdict_list = self.detector.predict_single(sample_list)
        verdict_arr = self.detector.predict_single(sample_arr)

        self.assertEqual(verdict_list["predicted_label"], verdict_arr["predicted_label"])
        self.assertAlmostEqual(verdict_list["confidence"], verdict_arr["confidence"], places=4)

    def test_rejection_of_wrong_dimensionality(self) -> None:
        """Verify FeatureContract rejects inputs with != 78 features."""
        contract = FeatureContract()
        with self.assertRaises(FeatureContractValidationError):
            contract.validate_and_align([0.0] * 77)

        with self.assertRaises(FeatureContractValidationError):
            contract.validate_and_align([0.0] * 79)

    def test_rejection_of_missing_dict_keys(self) -> None:
        """Verify FeatureContract rejects dictionary with missing columns."""
        sample_dict = self.df.iloc[0][FEATURE_COLUMNS].to_dict()
        del sample_dict["flow_duration"]

        with self.assertRaises(FeatureContractValidationError):
            self.detector.predict_single(sample_dict)

    def test_rejection_of_extraneous_dict_keys(self) -> None:
        """Verify FeatureContract rejects dictionary with unexpected extra keys."""
        sample_dict = self.df.iloc[0][FEATURE_COLUMNS].to_dict()
        sample_dict["unexpected_rogue_feature"] = 999.0

        with self.assertRaises(FeatureContractValidationError):
            self.detector.predict_single(sample_dict)

    def test_rejection_of_nan_and_inf(self) -> None:
        """Verify FeatureContract rejects inputs containing NaN or Inf."""
        sample_list = self.df.iloc[0][FEATURE_COLUMNS].tolist()
        sample_list[0] = float("nan")

        with self.assertRaises(FeatureContractValidationError):
            self.detector.predict_single(sample_list)

        sample_list[0] = float("inf")
        with self.assertRaises(FeatureContractValidationError):
            self.detector.predict_single(sample_list)

    def test_abstention_decision_policy(self) -> None:
        """Verify DecisionPolicy correctly flags low-confidence distributions for review."""
        policy = DecisionPolicy(abstain_threshold=0.50)
        # Uniform ambiguous distribution across 6 classes (1/6 = 0.1667 each)
        ambiguous_probs = np.array([0.17, 0.17, 0.17, 0.17, 0.16, 0.16])
        classes = np.array([0, 1, 2, 4, 5, 7])

        res = policy.evaluate(ambiguous_probs, classes)
        self.assertTrue(res["abstained"])
        self.assertEqual(res["decision"], "ANALYST_REVIEW")

        # High confidence distribution
        high_conf_probs = np.array([0.95, 0.01, 0.01, 0.01, 0.01, 0.01])
        res_high = policy.evaluate(high_conf_probs, classes)
        self.assertFalse(res_high["abstained"])
        self.assertEqual(res_high["decision"], "AUTOMATED_DETECTION")

    def test_batch_prediction_consistency(self) -> None:
        """Verify predict_batch produces identical results to sequential predict_single calls."""
        sample_batch = self.df.iloc[:5][FEATURE_COLUMNS].to_dict(orient="records")
        batch_verdicts = self.detector.predict_batch(sample_batch)

        self.assertEqual(len(batch_verdicts), 5)
        for i, row_dict in enumerate(sample_batch):
            single_verdict = self.detector.predict_single(row_dict)
            self.assertEqual(batch_verdicts[i]["predicted_label"], single_verdict["predicted_label"])
            self.assertEqual(batch_verdicts[i]["confidence"], single_verdict["confidence"])


if __name__ == "__main__":
    unittest.main()
