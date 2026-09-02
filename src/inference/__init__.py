"""
UniDetect Inference Package (Phase 6E & Phase 7)
"""

from src.inference.alert import AlertEvent
from src.inference.contract import FeatureContract, FeatureContractValidationError, SCHEMA_VERSION
from src.inference.detector import ThreatDetector
from src.inference.loader import ModelArtifactLoadingError, ModelLoader
from src.inference.pipeline import RealtimeInferencePipeline
from src.inference.policy import DecisionPolicy, DEFAULT_ABSTAIN_THRESHOLD, DEFAULT_RECON_THRESHOLD

__all__ = [
    "AlertEvent",
    "FeatureContract",
    "FeatureContractValidationError",
    "SCHEMA_VERSION",
    "DecisionPolicy",
    "DEFAULT_ABSTAIN_THRESHOLD",
    "DEFAULT_RECON_THRESHOLD",
    "ModelLoader",
    "ModelArtifactLoadingError",
    "ThreatDetector",
    "RealtimeInferencePipeline",
]
