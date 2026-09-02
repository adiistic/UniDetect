"""Custom exceptions and error structures for UniDetect backend."""

from typing import Any, Dict, Optional


class UniDetectError(Exception):
    """Base exception for all UniDetect errors."""
    def __init__(self, message: str, code: str = "INTERNAL_ERROR", details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class FeatureValidationError(UniDetectError):
    """Raised when the 78-dimensional feature contract is violated."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="INVALID_FEATURE_VECTOR", details=details)


class ModelNotLoadedError(UniDetectError):
    """Raised when inference is requested but model is not loaded."""
    def __init__(self, message: str = "Model is not loaded or ready for inference.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="MODEL_NOT_LOADED", details=details)


class ModelInferenceError(UniDetectError):
    """Raised when an internal error occurs during model inference."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="INFERENCE_FAILED", details=details)


class ConfigurationError(UniDetectError):
    """Raised when application configuration is invalid."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="CONFIG_ERROR", details=details)
