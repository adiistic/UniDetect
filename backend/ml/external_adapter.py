"""External HTTP REST Model Adapter for remote inference endpoints."""

from typing import Any, Dict, List, Optional
import httpx

from backend.core.constants import (
    CLASS_NAME_TO_ID,
    CLASS_NAMES,
    FEATURE_COUNT,
    SCHEMA_VERSION,
)
from backend.core.errors import (
    ConfigurationError,
    FeatureValidationError,
    ModelInferenceError,
    ModelNotLoadedError,
)
from backend.core.logging import logger
from backend.ml.base import ModelAdapter


class ExternalModelAdapter(ModelAdapter):
    """
    Adapter for connecting to a remote ML inference service or microservice over HTTP.
    API keys are loaded securely from environment variables and never logged or exposed.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 15.0,
        model_name: str = "external_unidetect_service",
        model_version: str = "remote-1.0",
    ):
        self._api_url = api_url
        self._api_key = api_key
        self._timeout = timeout
        self._model_name = model_name
        self._model_version = model_version
        self._is_loaded = False

    @property
    def provider(self) -> str:
        return "external"

    @property
    def is_mock(self) -> bool:
        return False

    def load(self) -> bool:
        if not self._api_url:
            logger.warning("External model API URL is not configured (MODEL_API_URL is unset).")
            self._is_loaded = False
            return False

        # Ready for external queries
        self._is_loaded = True
        logger.info(f"External model adapter configured for endpoint '{self._api_url}'.")
        return True

    def is_loaded(self) -> bool:
        return self._is_loaded and bool(self._api_url)

    def _ensure_loaded(self) -> None:
        if not self.is_loaded():
            raise ModelNotLoadedError(
                "External model endpoint is not configured. Set MODEL_API_URL in environment."
            )

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def predict(self, features: List[float]) -> int:
        self._ensure_loaded()
        if len(features) != FEATURE_COUNT:
            raise FeatureValidationError(f"Expected {FEATURE_COUNT} features, got {len(features)}.")

        payload = {"features": features}
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(self._api_url, json=payload, headers=self._get_headers())
                if response.status_code != 200:
                    raise ModelInferenceError(
                        f"External model service returned HTTP {response.status_code}"
                    )
                data = response.json()

                raw_pred = data.get("prediction", {}).get("class_id") or data.get("class_id")
                if raw_pred is None:
                    class_name = data.get("prediction", {}).get("class_name") or data.get("class_name")
                    if class_name and class_name.upper() in CLASS_NAME_TO_ID:
                        return CLASS_NAME_TO_ID[class_name.upper()]
                    raise ModelInferenceError("External model response missing valid prediction class.")

                class_id = int(raw_pred)
                if class_id not in CLASS_NAMES:
                    raise ModelInferenceError(f"External model returned unrecognized class ID: {class_id}")
                return class_id
        except Exception as e:
            logger.error(f"External model API request failed: {e}")
            raise ModelInferenceError(f"External model inference error: {str(e)}")

    def predict_proba(self, features: List[float]) -> Optional[Dict[str, float]]:
        self._ensure_loaded()
        if len(features) != FEATURE_COUNT:
            raise FeatureValidationError(f"Expected {FEATURE_COUNT} features, got {len(features)}.")

        payload = {"features": features}
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(self._api_url, json=payload, headers=self._get_headers())
                if response.status_code == 200:
                    data = response.json()
                    probs = data.get("probabilities")
                    if isinstance(probs, dict):
                        return {k: float(v) for k, v in probs.items()}
            return None
        except Exception as e:
            logger.warning(f"Failed to retrieve probabilities from external model: {e}")
            return None

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "is_mock": False,
            "api_url_configured": bool(self._api_url),
            "model_name": self._model_name,
            "model_version": self._model_version,
            "schema_version": SCHEMA_VERSION,
            "feature_count": FEATURE_COUNT,
            "classes": [CLASS_NAMES[i] for i in sorted(CLASS_NAMES.keys())],
        }
