"""
UniDetect Features Module (Person 2 - Phase 4)

Provides feature extraction logic for processing Zeek log records into
structured network behavioral features and 78-dimensional numerical feature vectors.
"""

from src.features.correlator import LogCorrelator
from src.features.extractor import (
    clean_str,
    extract_all_features,
    extract_connection_features,
    extract_dns_features,
    safe_float,
    safe_int,
)
from src.features.math_utils import (
    dns_max_label_len,
    dns_numeric_ratio,
    dns_subdomain_depth,
    dns_vowel_ratio,
    is_private_ip,
    shannon_entropy,
)
from src.features.schema import (
    FEATURE_COLUMNS,
    FEATURE_DEFAULTS,
    FEATURE_INDICES,
    NUM_FEATURES,
    THREAT_CLASSES,
)
from src.features.vector_assembler import (
    FeatureVectorAssembler,
    extract_feature_matrix,
)
from src.features.window_aggregator import WindowAggregator

__all__ = [
    # Baseline extraction API
    "safe_int",
    "safe_float",
    "clean_str",
    "extract_connection_features",
    "extract_dns_features",
    "extract_all_features",
    # Schema & constants
    "FEATURE_COLUMNS",
    "FEATURE_INDICES",
    "FEATURE_DEFAULTS",
    "NUM_FEATURES",
    "THREAT_CLASSES",
    # Mathematical & linguistic utils
    "shannon_entropy",
    "is_private_ip",
    "dns_vowel_ratio",
    "dns_numeric_ratio",
    "dns_subdomain_depth",
    "dns_max_label_len",
    # Multi-log correlation & aggregation
    "LogCorrelator",
    "WindowAggregator",
    # Vector assembler & matrix extraction
    "FeatureVectorAssembler",
    "extract_feature_matrix",
]
