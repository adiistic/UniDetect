"""Development-only Mock Model Adapter.

Used exclusively during development and testing before Person 2 delivers the final model.
Clearly marked as mock mode; does not fabricate real ML training metrics.
"""

from typing import Any, Dict, List, Optional
from backend.core.constants import (
    CLASS_ID_BENIGN,
    CLASS_ID_C2_BEACON,
    CLASS_ID_DDOS,
    CLASS_ID_DNS_TUNNEL,
    CLASS_ID_RECON,
    CLASS_ID_SLOW_HTTP,
    CLASS_NAMES,
    FEATURE_COUNT,
    SCHEMA_VERSION,
)
from backend.core.errors import FeatureValidationError
from backend.ml.base import ModelAdapter


class MockModelAdapter(ModelAdapter):
    """
    Deterministic development mock model.
    Accepts exactly 78 features and produces consistent dummy predictions for testing API wiring.
    """

    def __init__(self, model_version: str = "mock-dev-1.0"):
        self._is_loaded = False
        self._model_version = model_version
        self._model_name = "development_mock"

    @property
    def provider(self) -> str:
        return "mock"

    @property
    def is_mock(self) -> bool:
        return True

    def load(self) -> bool:
        self._is_loaded = True
        return True

    def is_loaded(self) -> bool:
        return self._is_loaded

    def predict(self, features: List[float]) -> int:
        """
        Deterministic mock prediction.
        Derives class ID from feature values deterministically without pseudo-randomness.
        """
        if len(features) != FEATURE_COUNT:
            raise FeatureValidationError(f"Expected {FEATURE_COUNT} features, got {len(features)}.")

        # Simple deterministic formula based on sum of first 5 features
        # to ensure predictable test cases:
        # e.g., if feature 0 is specifically set to a class id or sum modulo 6
        val_sum = sum(features[:10])
        class_id = int(abs(val_sum)) % len(CLASS_NAMES)
        return class_id

    def predict_proba(self, features: List[float]) -> Optional[Dict[str, float]]:
        """
        Returns deterministic mock probabilities across the 6 canonical classes.
        Highest probability assigned to predicted class.
        """
        pred_id = self.predict(features)
        pred_name = CLASS_NAMES[pred_id]

        # Distribute mock probabilities deterministically
        base_prob = 0.02
        remaining = 1.0 - (base_prob * (len(CLASS_NAMES) - 1))
        
        probs: Dict[str, float] = {}
        for cid, cname in CLASS_NAMES.items():
            if cname == pred_name:
                probs[cname] = round(remaining, 4)
            else:
                probs[cname] = round(base_prob, 4)

        return probs

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "is_mock": True,
            "model_name": self._model_name,
            "model_version": self._model_version,
            "schema_version": SCHEMA_VERSION,
            "feature_count": FEATURE_COUNT,
            "classes": [CLASS_NAMES[i] for i in sorted(CLASS_NAMES.keys())],
            "description": "Development mock model for API integration. NOT a trained ML model."
        }
