"""Local Model Adapter for joblib/pickle scikit-learn models."""

import os
from typing import Any, Dict, List, Optional
import joblib
import numpy as np

from backend.core.constants import (
    CLASS_NAME_TO_ID,
    CLASS_NAMES,
    FEATURE_COUNT,
    SCHEMA_VERSION,
)
from backend.core.errors import (
    FeatureValidationError,
    ModelInferenceError,
    ModelNotLoadedError,
    UniDetectError,
)
from backend.core.logging import logger
from backend.ml.base import ModelAdapter


class LocalModelAdapter(ModelAdapter):
    """
    Adapter for loading and running local scikit-learn / joblib / pickle model artifacts.
    Supports seamless drop-in when Person 2 delivers the trained model file.
    """

    def __init__(
        self,
        model_path: str = "models/unidetect_model.joblib",
        model_name: str = "unidetect_threat_classifier",
        model_version: str = "1.0.0",
    ):
        self._model_path = model_path
        self._model_name = model_name
        self._model_version = model_version
        self._model: Any = None
        self._is_loaded = False
        self._model_metadata: Dict[str, Any] = {}

    @property
    def provider(self) -> str:
        return "local"

    @property
    def is_mock(self) -> bool:
        return False

    def load(self) -> bool:
        """Attempts to load the model artifact from disk."""
        if not os.path.exists(self._model_path):
            logger.warning(
                f"Local model artifact not found at '{self._model_path}'. "
                "Backend is running in uninitialized/unready state for local inference."
            )
            self._is_loaded = False
            return False

        try:
            logger.info(f"Loading local model artifact from '{self._model_path}'...")
            loaded_obj = joblib.load(self._model_path)

            # Check if artifact is a dictionary containing model + metadata or raw estimator
            if isinstance(loaded_obj, dict) and "model" in loaded_obj:
                self._model = loaded_obj["model"]
                self._model_metadata = loaded_obj.get("metadata", {})
                self._model_version = loaded_obj.get("version", self._model_version)
            else:
                self._model = loaded_obj

            self._is_loaded = True
            logger.info(f"Local model successfully loaded from '{self._model_path}'.")
            return True
        except Exception as e:
            logger.error(f"Failed to load local model artifact from '{self._model_path}': {e}")
            self._is_loaded = False
            self._model = None
            return False

    def is_loaded(self) -> bool:
        return self._is_loaded and self._model is not None

    def _ensure_loaded(self) -> None:
        if not self.is_loaded():
            raise ModelNotLoadedError(
                f"Local model at '{self._model_path}' is not loaded. Ensure Person 2 has provided the model file."
            )

    def predict(self, features: List[float]) -> int:
        self._ensure_loaded()
        if len(features) != FEATURE_COUNT:
            raise FeatureValidationError(f"Expected {FEATURE_COUNT} features, got {len(features)}.")

        try:
            arr = np.array(features, dtype=np.float64).reshape(1, -1)
            raw_pred = self._model.predict(arr)[0]

            # Handle either string class names or numeric class IDs from the estimator
            if isinstance(raw_pred, (int, np.integer)):
                class_id = int(raw_pred)
                if class_id not in CLASS_NAMES:
                    raise ModelInferenceError(f"Model returned unrecognized class ID: {class_id}")
                return class_id
            elif isinstance(raw_pred, str):
                cleaned_name = raw_pred.strip().upper()
                if cleaned_name not in CLASS_NAME_TO_ID:
                    raise ModelInferenceError(f"Model returned unrecognized class name: '{raw_pred}'")
                return CLASS_NAME_TO_ID[cleaned_name]
            else:
                raise ModelInferenceError(f"Unexpected prediction return type: {type(raw_pred).__name__}")
        except UniDetectError:
            raise
        except Exception as e:
            logger.error(f"Error during local model inference: {e}")
            raise ModelInferenceError(f"Local model inference failed: {str(e)}")

    def predict_proba(self, features: List[float]) -> Optional[Dict[str, float]]:
        self._ensure_loaded()
        if len(features) != FEATURE_COUNT:
            raise FeatureValidationError(f"Expected {FEATURE_COUNT} features, got {len(features)}.")

        if not hasattr(self._model, "predict_proba"):
            # Model does not provide probability calibration; do not fabricate
            return None

        try:
            arr = np.array(features, dtype=np.float64).reshape(1, -1)
            raw_probs = self._model.predict_proba(arr)[0]

            # Extract classes from estimator if available
            classes = getattr(self._model, "classes_", None)
            probs_dict: Dict[str, float] = {}

            if classes is not None and len(classes) == len(raw_probs):
                for cls_label, prob_val in zip(classes, raw_probs):
                    if isinstance(cls_label, (int, np.integer)):
                        cname = CLASS_NAMES.get(int(cls_label), f"CLASS_{cls_label}")
                    else:
                        cname = str(cls_label).strip().upper()
                    probs_dict[cname] = float(prob_val)
            else:
                # Default mapping to canonical classes in index order
                for i, prob_val in enumerate(raw_probs):
                    if i in CLASS_NAMES:
                        probs_dict[CLASS_NAMES[i]] = float(prob_val)

            # Ensure all canonical classes exist in output dictionary (fill 0.0 if not emitted)
            for cname in CLASS_NAMES.values():
                if cname not in probs_dict:
                    probs_dict[cname] = 0.0

            return probs_dict
        except Exception as e:
            logger.warning(f"Failed to calculate predict_proba on local model: {e}")
            return None

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "is_mock": False,
            "model_path": self._model_path,
            "model_name": self._model_name,
            "model_version": self._model_version,
            "schema_version": SCHEMA_VERSION,
            "feature_count": FEATURE_COUNT,
            "classes": [CLASS_NAMES[i] for i in sorted(CLASS_NAMES.keys())],
            "loaded": self.is_loaded(),
            "extra_metadata": self._model_metadata,
        }
