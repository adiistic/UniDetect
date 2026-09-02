"""Feature extraction service interface for raw network data processing (future support)."""

from typing import Any, Dict, List, Optional
from backend.core.constants import FEATURE_COUNT, SCHEMA_VERSION
from backend.core.errors import FeatureValidationError
from backend.core.logging import logger
from backend.core.schema import FeatureVector


class FeatureExtractionService:
    """
    Boundary service for transforming raw network inputs (PCAP, Zeek logs, flow stats)
    into the canonical 78-dimensional feature vector.
    """

    def __init__(self) -> None:
        self._schema_version = SCHEMA_VERSION
        self._feature_count = FEATURE_COUNT

    def extract_from_flow_dict(self, flow_data: Dict[str, Any]) -> FeatureVector:
        """
        Extracts 78-dimensional feature vector from a structured network flow record.
        """
        logger.debug("Extracting 78-dimensional features from flow record")
        # In this phase, if flow_data already provides 78 features, it is validated.
        if "features" in flow_data:
            from backend.core.schema import validate_feature_values
            validated = validate_feature_values(flow_data["features"])
            return FeatureVector(values=validated)
        raise FeatureValidationError("Raw flow parsing pipeline is scheduled for future integration.")

    def extract_from_pcap(self, pcap_bytes: bytes) -> List[FeatureVector]:
        """
        Future extraction interface for raw PCAP file byte payloads.
        """
        raise NotImplementedError(
            "Direct PCAP parsing requires the dataset extraction pipeline extension. "
            "Please provide 78-dimensional feature vectors directly."
        )
