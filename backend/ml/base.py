"""Abstract base class for UniDetect Model Adapters."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class ModelAdapter(ABC):
    """
    Abstract interface for model inference in UniDetect.
    Decouples the REST API from underlying ML frameworks (scikit-learn, ONNX, PyTorch, External API).
    """

    @property
    @abstractmethod
    def provider(self) -> str:
        """Name of the provider (e.g., 'mock', 'local', 'external')."""
        pass

    @property
    @abstractmethod
    def is_mock(self) -> bool:
        """True if this is a development mock model, False for real models."""
        pass

    @abstractmethod
    def load(self) -> bool:
        """
        Loads the model into memory.
        Returns True if successful, False or raises an error otherwise.
        """
        pass

    @abstractmethod
    def is_loaded(self) -> bool:
        """Returns True if the model is ready to serve inference requests."""
        pass

    @abstractmethod
    def predict(self, features: List[float]) -> int:
        """
        Runs model inference on a single 78-dimensional feature vector.
        Returns canonical class ID (int).
        """
        pass

    @abstractmethod
    def predict_proba(self, features: List[float]) -> Optional[Dict[str, float]]:
        """
        Computes class probability distribution for all canonical classes.
        Returns a dictionary mapping class names to probabilities, or None if not supported.
        """
        pass

    @abstractmethod
    def get_metadata(self) -> Dict[str, Any]:
        """Returns model metadata (version, feature count, schema, algorithm)."""
        pass
