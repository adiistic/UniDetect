"""Tests for 78-dimensional feature validation contract."""

import math
import pytest
from backend.core.constants import (
    CLASS_ID_BENIGN,
    CLASS_ID_C2_BEACON,
    CLASS_ID_DDOS,
    CLASS_ID_DNS_TUNNEL,
    CLASS_ID_RECON,
    CLASS_ID_SLOW_HTTP,
    CLASS_NAMES,
    FEATURE_COUNT,
)
from backend.core.errors import FeatureValidationError
from backend.core.schema import (
    CANONICAL_FEATURE_NAMES,
    validate_feature_values,
)


def test_valid_78d_vector_passes():
    """Test that a vector of exactly 78 floats passes validation."""
    valid_vector = [1.5] * FEATURE_COUNT
    result = validate_feature_values(valid_vector)
    assert len(result) == FEATURE_COUNT
    assert result == valid_vector


def test_vector_with_77_features_rejected():
    """Test that 77 features is strictly rejected."""
    invalid_vector = [1.0] * 77
    with pytest.raises(FeatureValidationError) as exc_info:
        validate_feature_values(invalid_vector)
    assert "Expected exactly 78 features, got 77" in str(exc_info.value)
    assert exc_info.value.code == "INVALID_FEATURE_VECTOR"


def test_vector_with_79_features_rejected():
    """Test that 79 features is strictly rejected."""
    invalid_vector = [1.0] * 79
    with pytest.raises(FeatureValidationError) as exc_info:
        validate_feature_values(invalid_vector)
    assert "Expected exactly 78 features, got 79" in str(exc_info.value)


def test_vector_with_nan_rejected():
    """Test that NaN values are rejected."""
    vector_with_nan = [0.0] * FEATURE_COUNT
    vector_with_nan[10] = float("nan")
    with pytest.raises(FeatureValidationError) as exc_info:
        validate_feature_values(vector_with_nan)
    assert "contains NaN" in str(exc_info.value)


def test_vector_with_positive_infinity_rejected():
    """Test that +Infinity values are rejected."""
    vector_with_inf = [0.0] * FEATURE_COUNT
    vector_with_inf[5] = float("inf")
    with pytest.raises(FeatureValidationError) as exc_info:
        validate_feature_values(vector_with_inf)
    assert "contains Infinity" in str(exc_info.value)


def test_vector_with_negative_infinity_rejected():
    """Test that -Infinity values are rejected."""
    vector_with_neginf = [0.0] * FEATURE_COUNT
    vector_with_neginf[25] = float("-inf")
    with pytest.raises(FeatureValidationError) as exc_info:
        validate_feature_values(vector_with_neginf)
    assert "contains Infinity" in str(exc_info.value)


def test_vector_with_string_rejected():
    """Test that non-numeric values are rejected."""
    vector_with_str = [0.0] * FEATURE_COUNT
    vector_with_str[15] = "not-a-number"  # type: ignore
    with pytest.raises(FeatureValidationError) as exc_info:
        validate_feature_values(vector_with_str)
    assert "must be numeric" in str(exc_info.value)


def test_vector_with_none_rejected():
    """Test that None values are rejected."""
    vector_with_none = [0.0] * FEATURE_COUNT
    vector_with_none[0] = None  # type: ignore
    with pytest.raises(FeatureValidationError) as exc_info:
        validate_feature_values(vector_with_none)
    assert "cannot be None" in str(exc_info.value)


def test_dictionary_features_with_valid_canonical_names():
    """Test that dictionary input matching canonical 78 feature names is converted correctly."""
    dict_features = {name: float(i) for i, name in enumerate(CANONICAL_FEATURE_NAMES)}
    result = validate_feature_values(dict_features)
    assert len(result) == FEATURE_COUNT
    assert result[0] == 0.0
    assert result[77] == 77.0


def test_dictionary_features_with_indices():
    """Test that dictionary input using feature_0..77 indices works."""
    dict_features = {f"feature_{i}": 2.5 for i in range(FEATURE_COUNT)}
    result = validate_feature_values(dict_features)
    assert len(result) == FEATURE_COUNT
    assert all(val == 2.5 for val in result)


def test_dictionary_features_wrong_length_rejected():
    """Test that dictionary with 77 entries is rejected."""
    dict_features = {f"feature_{i}": 1.0 for i in range(77)}
    with pytest.raises(FeatureValidationError) as exc_info:
        validate_feature_values(dict_features)
    assert "Expected exactly 78 features in dictionary, got 77" in str(exc_info.value)


def test_dictionary_features_unknown_key_rejected():
    """Test that dictionary with unknown feature keys is rejected."""
    dict_features = {f"feature_{i}": 1.0 for i in range(FEATURE_COUNT - 1)}
    dict_features["unknown_malicious_key"] = 1.0
    with pytest.raises(FeatureValidationError) as exc_info:
        validate_feature_values(dict_features)
    assert "Unknown feature name" in str(exc_info.value)


def check_canonical_class_mappings():
    """Verify that canonical class labels match the specified project contract."""
    assert CLASS_NAMES[CLASS_ID_BENIGN] == "BENIGN"
    assert CLASS_NAMES[CLASS_ID_DDOS] == "DDOS"
    assert CLASS_NAMES[CLASS_ID_RECON] == "RECON"
    assert CLASS_NAMES[CLASS_ID_SLOW_HTTP] == "SLOW_HTTP"
    assert CLASS_NAMES[CLASS_ID_DNS_TUNNEL] == "DNS_TUNNEL"
    assert CLASS_NAMES[CLASS_ID_C2_BEACON] == "C2_BEACON"
    assert len(CLASS_NAMES) == 6


import unittest

class TestFeatureValidation(unittest.TestCase):
    """Unittest test case class for feature validation."""

    def test_valid_78d_vector_passes(self):
        test_valid_78d_vector_passes()

    def test_vector_with_77_features_rejected(self):
        test_vector_with_77_features_rejected()

    def test_vector_with_79_features_rejected(self):
        test_vector_with_79_features_rejected()

    def test_vector_with_nan_rejected(self):
        test_vector_with_nan_rejected()

    def test_vector_with_positive_infinity_rejected(self):
        test_vector_with_positive_infinity_rejected()

    def test_vector_with_negative_infinity_rejected(self):
        test_vector_with_negative_infinity_rejected()

    def test_vector_with_string_rejected(self):
        test_vector_with_string_rejected()

    def test_vector_with_none_rejected(self):
        test_vector_with_none_rejected()

    def test_dictionary_features_with_valid_canonical_names(self):
        test_dictionary_features_with_valid_canonical_names()

    def test_dictionary_features_with_indices(self):
        test_dictionary_features_with_indices()

    def test_dictionary_features_wrong_length_rejected(self):
        test_dictionary_features_wrong_length_rejected()

    def test_dictionary_features_unknown_key_rejected(self):
        test_dictionary_features_unknown_key_rejected()

    def test_canonical_class_mappings(self):
        check_canonical_class_mappings()
