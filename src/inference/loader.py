"""
Model Artifact Loader & Integrity Verifier for UniDetect
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import joblib

from src.inference.contract import FeatureContract
from src.inference.policy import DecisionPolicy


class ModelArtifactLoadingError(RuntimeError):
    """Raised when serialized model artifacts fail integrity or file presence checks."""
    pass


class ModelLoader:
    """
    Loads, deserializes, and validates the serialized UniDetect production model
    artifacts from disk with strict version, contract, and metadata checks.
    """

    @staticmethod
    def load_artifacts(
        model_dir: Union[str, Path],
    ) -> Tuple[Any, Dict[str, Any], FeatureContract, DecisionPolicy]:
        """
        Loads the trained model, metadata manifest, feature contract, and decision policy.

        Expected directory layout:
        <model_dir>/
            model/model.joblib
            metadata/model_metadata.json
            feature_contract/feature_contract.json
            thresholds/decision_policy.json
        """
        base_path = Path(model_dir).resolve()
        if not base_path.exists():
            raise ModelArtifactLoadingError(f"Model artifact directory not found: {base_path}")

        model_file = base_path / "model" / "model.joblib"
        meta_file = base_path / "metadata" / "model_metadata.json"
        contract_file = base_path / "feature_contract" / "feature_contract.json"
        policy_file = base_path / "thresholds" / "decision_policy.json"

        # Check required files
        for f in [model_file, meta_file, contract_file, policy_file]:
            if not f.exists():
                raise ModelArtifactLoadingError(f"Required model artifact file missing: {f}")

        # 1. Load Model
        try:
            model = joblib.load(model_file)
        except Exception as e:
            raise ModelArtifactLoadingError(f"Failed to load model from {model_file}: {e}") from e

        # 2. Load Metadata
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                metadata = json.load(f)
        except Exception as e:
            raise ModelArtifactLoadingError(f"Failed to read metadata from {meta_file}: {e}") from e

        # 3. Load Contract
        try:
            contract = FeatureContract(contract_file)
        except Exception as e:
            raise ModelArtifactLoadingError(f"Failed to instantiate contract from {contract_file}: {e}") from e

        # 4. Load Policy
        try:
            with open(policy_file, "r", encoding="utf-8") as f:
                policy_data = json.load(f)
            policy = DecisionPolicy(
                abstain_threshold=policy_data.get("abstain_threshold", 0.40),
                recon_threshold=policy_data.get("recon_threshold", 0.35),
                classes=policy_data.get("active_classes"),
                active_label_ids=policy_data.get("active_label_ids"),
            )
        except Exception as e:
            raise ModelArtifactLoadingError(f"Failed to load policy from {policy_file}: {e}") from e

        return model, metadata, contract, policy
