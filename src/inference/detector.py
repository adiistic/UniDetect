"""
Deterministic Standalone Threat Detector for UniDetect Inference
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import numpy as np

from src.features.schema import NUM_FEATURES, THREAT_CLASSES
from src.inference.contract import FeatureContract, FeatureContractValidationError
from src.inference.loader import ModelLoader
from src.inference.policy import DecisionPolicy


class ThreatDetector:
    """
    Offline threat detection inference engine for UniDetect.
    Accepts raw feature vectors or structured feature dictionaries, validates
    against the frozen 78-dimensional feature contract, predicts calibrated
    class probabilities, and applies operational decision policies.
    """

    def __init__(
        self,
        model_dir: Optional[Union[str, Path]] = None,
        model: Optional[Any] = None,
        contract: Optional[FeatureContract] = None,
        policy: Optional[DecisionPolicy] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if model_dir is not None:
            self.model, self.metadata, self.contract, self.policy = ModelLoader.load_artifacts(model_dir)
        else:
            if model is None:
                raise ValueError("Must provide either model_dir or pre-initialized model.")
            self.model = model
            self.contract = contract or FeatureContract()
            self.policy = policy or DecisionPolicy()
            self.metadata = metadata or {
                "model_version": "unidetect-hgb-calibrated-v1.0.0",
                "schema_version": "1.0.0",
            }

        self.model_version = self.metadata.get("model_version", "unidetect-hgb-calibrated-v1.0.0")
        self.schema_version = self.contract.schema_version

    @classmethod
    def from_artifact_dir(cls, model_dir: Union[str, Path]) -> "ThreatDetector":
        """Factory constructor loading artifacts from a model directory."""
        return cls(model_dir=model_dir)

    def predict_single(
        self,
        features: Union[Dict[str, Any], List[float], np.ndarray],
    ) -> Dict[str, Any]:
        """
        Executes deterministic threat classification on a single network flow record.

        Accepts:
        - 78-feature dictionary with exact column names, OR
        - 78-element list / 1D numpy array in schema index order.

        Returns structured inference output:
        {
            "predicted_class_id": int,
            "predicted_label": str,
            "confidence": float,
            "probabilities": {class_name: float, ...},
            "abstained": bool,
            "decision": "AUTOMATED_DETECTION" | "ANALYST_REVIEW",
            "model_version": str,
            "schema_version": str,
        }
        """
        # 1. Strict Contract Validation & Alignment
        feat_vector = self.contract.validate_and_align(features)

        # 2. Reshape for Scikit-Learn (1, 78)
        X = feat_vector.reshape(1, -1)

        # 3. Model Inference (Probabilities)
        if hasattr(self.model, "predict_proba"):
            probs_2d = self.model.predict_proba(X)
            probs = probs_2d[0]
            classes = self.model.classes_
        else:
            # Fallback for models without predict_proba
            pred_class = self.model.predict(X)[0]
            classes = np.array([pred_class])
            probs = np.array([1.0])

        # 4. Policy Evaluation
        verdict = self.policy.evaluate(probabilities=probs, model_classes=classes)
        verdict["model_version"] = self.model_version
        verdict["schema_version"] = self.schema_version

        return verdict

    def predict_batch(
        self,
        feature_batch: List[Union[Dict[str, Any], List[float], np.ndarray]],
    ) -> List[Dict[str, Any]]:
        """Executes deterministic threat classification across a batch of flow records."""
        return [self.predict_single(feat) for feat in feature_batch]
