"""
Feature Contract Specification & Strict Input Validation for UniDetect Inference
"""

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import numpy as np

from src.features.schema import FEATURE_COLUMNS, FEATURE_DEFAULTS, FEATURE_INDICES, NUM_FEATURES

SCHEMA_VERSION = "1.0.0"


class FeatureContractValidationError(ValueError):
    """Raised when an inference input violates the frozen 78-dimensional feature contract."""
    pass


class FeatureContract:
    """
    Frozen 78-dimensional feature contract defining deterministic ordering,
    type validation, default values, and mathematical integrity checks for ML inference.
    """

    def __init__(self, contract_path: Optional[Union[str, Path]] = None) -> None:
        self.schema_version = SCHEMA_VERSION
        self.num_features = NUM_FEATURES
        self.feature_columns = list(FEATURE_COLUMNS)
        self.feature_indices = dict(FEATURE_INDICES)
        self.feature_defaults = dict(FEATURE_DEFAULTS)

        if contract_path is not None:
            path = Path(contract_path)
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.schema_version = data.get("schema_version", SCHEMA_VERSION)
                    self.num_features = data.get("num_features", NUM_FEATURES)
                    self.feature_columns = data.get("feature_columns", list(FEATURE_COLUMNS))
                    self.feature_indices = data.get("feature_indices", dict(FEATURE_INDICES))
                    self.feature_defaults = data.get("feature_defaults", dict(FEATURE_DEFAULTS))

    def validate_and_align(
        self,
        features: Union[Dict[str, Any], List[float], np.ndarray],
    ) -> np.ndarray:
        """
        Validates and converts structured feature inputs (dict, list, or ndarray)
        into a deterministic 1D numpy float64 array of length 78.

        Raises FeatureContractValidationError on:
        - Wrong dimension count
        - Missing required features (in dict mode)
        - Unexpected extraneous features (in dict mode)
        - Non-numeric values
        - NaN or Infinite values
        """
        # Case 1: Structured Feature Dictionary
        if isinstance(features, dict):
            input_keys = set(features.keys())
            expected_keys = set(self.feature_columns)

            missing_keys = expected_keys - input_keys
            if missing_keys:
                raise FeatureContractValidationError(
                    f"Feature contract violation: Missing {len(missing_keys)} required feature(s): {sorted(list(missing_keys))[:5]}"
                )

            extra_keys = input_keys - expected_keys
            if extra_keys:
                raise FeatureContractValidationError(
                    f"Feature contract violation: Extraneous unexpected feature(s) provided: {sorted(list(extra_keys))[:5]}"
                )

            # Assemble into strict deterministic order
            ordered_vals: List[float] = []
            for col_name in self.feature_columns:
                val = features[col_name]
                if not isinstance(val, (int, float, np.integer, np.floating)):
                    raise FeatureContractValidationError(
                        f"Feature contract violation: Non-numeric value for feature '{col_name}': {val} (type {type(val)})"
                    )
                float_val = float(val)
                if math.isnan(float_val) or math.isinf(float_val):
                    raise FeatureContractValidationError(
                        f"Feature contract violation: Invalid numerical value (NaN/Inf) for feature '{col_name}': {float_val}"
                    )
                ordered_vals.append(float_val)

            return np.array(ordered_vals, dtype=np.float64)

        # Case 2: Sequence or Numpy Array
        elif isinstance(features, (list, tuple, np.ndarray)):
            arr = np.asarray(features, dtype=np.float64)
            if arr.ndim != 1 or arr.shape[0] != self.num_features:
                raise FeatureContractValidationError(
                    f"Feature contract violation: Expected 1D array of shape ({self.num_features},), got shape {arr.shape}"
                )

            if np.isnan(arr).any():
                raise FeatureContractValidationError("Feature contract violation: Input array contains NaN values.")
            if np.isinf(arr).any():
                raise FeatureContractValidationError("Feature contract violation: Input array contains Infinite values.")

            return arr

        else:
            raise FeatureContractValidationError(
                f"Feature contract violation: Unsupported input type {type(features)}. Expected dict, list, or np.ndarray."
            )

    def export_contract_dict(self) -> Dict[str, Any]:
        """Exports contract specification as a serializable dictionary."""
        return {
            "schema_version": self.schema_version,
            "num_features": self.num_features,
            "feature_columns": self.feature_columns,
            "feature_indices": self.feature_indices,
            "feature_defaults": self.feature_defaults,
            "data_type": "float64",
            "validation_rules": {
                "strict_dimension": NUM_FEATURES,
                "nan_allowed": False,
                "inf_allowed": False,
                "reordering_allowed": False,
            },
        }
