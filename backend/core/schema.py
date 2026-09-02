"""Canonical 78-dimensional feature schema and validation."""

import math
from typing import Any, Dict, List, Sequence, Union
from pydantic import BaseModel, Field

from backend.core.constants import FEATURE_COUNT, SCHEMA_VERSION
from backend.core.errors import FeatureValidationError

# Authoritative canonical 78 feature names (ordered index 0 to 77)
# Based on network flow traffic feature specifications
CANONICAL_FEATURE_NAMES: List[str] = [
    f"f_{i:02d}_{name}"
    for i, name in enumerate([
        "dst_port", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
        "totlen_fwd_pkts", "totlen_bwd_pkts", "fwd_pkt_len_max", "fwd_pkt_len_min",
        "fwd_pkt_len_mean", "fwd_pkt_len_std", "bwd_pkt_len_max", "bwd_pkt_len_min",
        "bwd_pkt_len_mean", "bwd_pkt_len_std", "flow_byts_s", "flow_pkts_s",
        "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
        "fwd_iat_tot", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max",
        "fwd_iat_min", "bwd_iat_tot", "bwd_iat_mean", "bwd_iat_std",
        "bwd_iat_max", "bwd_iat_min", "fwd_psh_flags", "bwd_psh_flags",
        "fwd_urg_flags", "bwd_urg_flags", "fwd_header_len", "bwd_header_len",
        "fwd_pkts_s", "bwd_pkts_s", "pkt_len_min", "pkt_len_max",
        "pkt_len_mean", "pkt_len_std", "pkt_len_var", "fin_flag_cnt",
        "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt",
        "urg_flag_cnt", "cwe_flag_count", "ece_flag_cnt", "down_up_ratio",
        "pkt_size_avg", "fwd_seg_size_avg", "bwd_seg_size_avg", "fwd_byts_b_avg",
        "fwd_pkts_b_avg", "fwd_blk_rate_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg",
        "bwd_blk_rate_avg", "subflow_fwd_pkts", "subflow_fwd_byts", "subflow_bwd_pkts",
        "subflow_bwd_byts", "init_fwd_win_byts", "init_bwd_win_byts", "fwd_act_data_pkts",
        "fwd_seg_size_min", "active_mean", "active_std", "active_max",
        "active_min", "idle_mean", "idle_std", "idle_max",
        "idle_min", "flow_anomaly_score"
    ])
]

# Alias map to support index string ("0", "1", ...), feature_0..77, f_00_..., or raw canonical names
FEATURE_NAME_TO_INDEX: Dict[str, int] = {}
for idx, name in enumerate(CANONICAL_FEATURE_NAMES):
    FEATURE_NAME_TO_INDEX[name] = idx
    FEATURE_NAME_TO_INDEX[f"feature_{idx}"] = idx
    FEATURE_NAME_TO_INDEX[str(idx)] = idx
    # Short name without index prefix
    short_name = name.split("_", 2)[-1]
    if short_name not in FEATURE_NAME_TO_INDEX:
        FEATURE_NAME_TO_INDEX[short_name] = idx


class FeatureVector(BaseModel):
    """Internal canonical representation of a validated 78D feature vector."""
    values: List[float] = Field(..., description="78 numerical feature values")
    feature_count: int = Field(default=FEATURE_COUNT, description="Count of features (must be 78)")
    schema_version: str = Field(default=SCHEMA_VERSION, description="Schema version")


def validate_feature_values(
    features: Union[Sequence[Any], Dict[str, Any]],
    sample_index: Union[int, None] = None
) -> List[float]:
    """
    Validates and normalizes feature input to a list of exactly 78 floats.
    Rejects wrong lengths, NaN, Infinity, and non-numeric values.
    """
    prefix = f"Sample {sample_index}: " if sample_index is not None else ""

    if isinstance(features, dict):
        # Dictionary input: check keys and map to 78 indices
        if len(features) != FEATURE_COUNT:
            raise FeatureValidationError(
                f"{prefix}Expected exactly {FEATURE_COUNT} features in dictionary, got {len(features)}."
            )
        ordered_values: List[float] = [0.0] * FEATURE_COUNT
        visited_indices = set()

        for key, val in features.items():
            if key not in FEATURE_NAME_TO_INDEX:
                raise FeatureValidationError(
                    f"{prefix}Unknown feature name '{key}'. Must be in canonical schema or indices 0..{FEATURE_COUNT - 1}."
                )
            idx = FEATURE_NAME_TO_INDEX[key]
            if idx in visited_indices:
                raise FeatureValidationError(f"{prefix}Duplicate feature index mapped for key '{key}'.")
            visited_indices.add(idx)

            try:
                float_val = float(val)
            except (ValueError, TypeError):
                raise FeatureValidationError(f"{prefix}Feature '{key}' value must be numeric, got {type(val).__name__}.")

            if math.isnan(float_val):
                raise FeatureValidationError(f"{prefix}Feature '{key}' contains NaN which is not permitted.")
            if math.isinf(float_val):
                raise FeatureValidationError(f"{prefix}Feature '{key}' contains Infinity which is not permitted.")

            ordered_values[idx] = float_val

        if len(visited_indices) != FEATURE_COUNT:
            missing = set(range(FEATURE_COUNT)) - visited_indices
            raise FeatureValidationError(f"{prefix}Missing feature indices in dictionary: {sorted(list(missing))[:5]}...")

        return ordered_values

    # Sequential list/tuple input
    if not isinstance(features, (list, tuple)):
        raise FeatureValidationError(f"{prefix}Features must be a list of {FEATURE_COUNT} numeric values or a dictionary.")

    if len(features) != FEATURE_COUNT:
        raise FeatureValidationError(
            f"{prefix}Expected exactly {FEATURE_COUNT} features, got {len(features)}."
        )

    validated: List[float] = []
    for i, val in enumerate(features):
        if val is None:
            raise FeatureValidationError(f"{prefix}Feature at index {i} cannot be None.")
        try:
            float_val = float(val)
        except (ValueError, TypeError):
            raise FeatureValidationError(
                f"{prefix}Feature at index {i} must be numeric, got {type(val).__name__} ({val!r})."
            )

        if math.isnan(float_val):
            raise FeatureValidationError(f"{prefix}Feature at index {i} contains NaN which is not permitted.")
        if math.isinf(float_val):
            raise FeatureValidationError(f"{prefix}Feature at index {i} contains Infinity which is not permitted.")

        validated.append(float_val)

    return validated
