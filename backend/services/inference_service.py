"""Inference service orchestrating validation, prediction, and response generation."""

import time
from typing import Any, Dict, List, Optional
from backend.core.constants import (
    CLASS_NAMES,
    CLASS_SUBTYPES,
    FEATURE_COUNT,
    SCHEMA_VERSION,
)
from backend.core.errors import ModelNotLoadedError
from backend.core.logging import logger
from backend.core.schema import validate_feature_values
from backend.ml.base import ModelAdapter
from backend.ml.loader import ModelLoader


class InferenceService:
    """High-level service for threat classification inference."""

    def __init__(self, adapter: Optional[ModelAdapter] = None):
        self._adapter = adapter or ModelLoader.get_adapter()

    @property
    def adapter(self) -> ModelAdapter:
        return self._adapter

    def is_ready(self) -> bool:
        """Returns True if model adapter is ready for inference."""
        return self._adapter.is_loaded()

    def get_model_status(self) -> Dict[str, Any]:
        """Returns detailed status information about current ML model."""
        meta = self._adapter.get_metadata()
        return {
            "loaded": self._adapter.is_loaded(),
            "provider": self._adapter.provider,
            "is_mock": self._adapter.is_mock,
            "model_name": meta.get("model_name", "unknown"),
            "model_version": meta.get("model_version", "unknown"),
            "schema_version": SCHEMA_VERSION,
            "feature_count": FEATURE_COUNT,
            "metadata": meta,
        }

    def predict_single(self, raw_features: Any) -> Dict[str, Any]:
        """
        Validates 78-dimensional vector, runs inference, and returns formatted prediction.
        """
        start_time = time.perf_counter()
        validated_vector = validate_feature_values(raw_features)

        if not self._adapter.is_loaded():
            raise ModelNotLoadedError("Model is not loaded. Cannot perform inference.")

        class_id = self._adapter.predict(validated_vector)
        class_name = CLASS_NAMES.get(class_id, f"UNKNOWN_CLASS_{class_id}")
        probabilities = self._adapter.predict_proba(validated_vector)

        # Calculate confidence
        confidence: Optional[float] = None
        if probabilities and class_name in probabilities:
            confidence = float(probabilities[class_name])
        elif probabilities:
            confidence = float(max(probabilities.values()))
        else:
            # Fallback if no probabilities are available
            confidence = 1.0 if not self._adapter.is_mock else 0.90

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        result: Dict[str, Any] = {
            "prediction": {
                "class_id": class_id,
                "class_name": class_name,
                "subtypes": CLASS_SUBTYPES.get(class_id, []),
            },
            "confidence": round(confidence, 4) if confidence is not None else None,
            "probabilities": probabilities,
            "model": {
                "provider": self._adapter.provider,
                "model_version": self._adapter.get_metadata().get("model_version", "unknown"),
                "schema_version": SCHEMA_VERSION,
                "feature_count": FEATURE_COUNT,
                "is_mock": self._adapter.is_mock,
            },
            "latency_ms": round(elapsed_ms, 2),
        }

        if self._adapter.is_mock:
            result["mode"] = "mock"

        return result

    def predict_batch(self, samples: List[Any]) -> Dict[str, Any]:
        """
        Validates and runs batch prediction for multiple samples.
        """
        start_time = time.perf_counter()
        if not samples:
            return {"results": [], "total_samples": 0, "latency_ms": 0.0}

        # Step 1: Validate all samples upfront
        validated_samples = [
            validate_feature_values(sample, sample_index=i)
            for i, sample in enumerate(samples)
        ]

        # Step 2: Run inference on each sample
        results: List[Dict[str, Any]] = []
        for i, vector in enumerate(validated_samples):
            single_result = self.predict_single(vector)
            single_result["sample_index"] = i
            results.append(single_result)

        total_elapsed_ms = (time.perf_counter() - start_time) * 1000

        batch_response: Dict[str, Any] = {
            "results": results,
            "total_samples": len(results),
            "model": {
                "provider": self._adapter.provider,
                "model_version": self._adapter.get_metadata().get("model_version", "unknown"),
                "schema_version": SCHEMA_VERSION,
                "is_mock": self._adapter.is_mock,
            },
            "latency_ms": round(total_elapsed_ms, 2),
        }

        if self._adapter.is_mock:
            batch_response["mode"] = "mock"

        return batch_response
