"""Tests for Model Adapter interfaces, MockModelAdapter, LocalModelAdapter, and ModelLoader."""

import os
import tempfile
import joblib
import numpy as np
import pytest
from sklearn.dummy import DummyClassifier

from backend.core.config import Settings
from backend.core.constants import CLASS_NAMES, FEATURE_COUNT
from backend.core.errors import ConfigurationError, FeatureValidationError, ModelNotLoadedError
from backend.ml.loader import ModelLoader
from backend.ml.local_adapter import LocalModelAdapter
from backend.ml.mock_adapter import MockModelAdapter


def test_mock_adapter_lifecycle():
    """Test the complete mock adapter contract and lifecycle."""
    adapter = MockModelAdapter(model_version="mock-test-1.0")
    assert not adapter.is_loaded()
    assert adapter.provider == "mock"
    assert adapter.is_mock is True

    # Load
    assert adapter.load() is True
    assert adapter.is_loaded() is True

    # Predict
    features = [0.5] * FEATURE_COUNT
    pred_id = adapter.predict(features)
    assert isinstance(pred_id, int)
    assert pred_id in CLASS_NAMES

    # Probabilities
    probs = adapter.predict_proba(features)
    assert probs is not None
    assert len(probs) == len(CLASS_NAMES)
    assert sum(probs.values()) == pytest.approx(1.0, rel=1e-3)
    assert probs[CLASS_NAMES[pred_id]] == max(probs.values())

    # Metadata
    meta = adapter.get_metadata()
    assert meta["provider"] == "mock"
    assert meta["is_mock"] is True
    assert meta["feature_count"] == FEATURE_COUNT
    assert meta["model_version"] == "mock-test-1.0"


def test_mock_adapter_rejects_wrong_feature_count():
    """Test that mock adapter enforces 78 features."""
    adapter = MockModelAdapter()
    adapter.load()
    with pytest.raises(FeatureValidationError):
        adapter.predict([1.0] * 50)


def test_local_adapter_missing_file_handling():
    """Test that LocalModelAdapter gracefully handles missing model files."""
    adapter = LocalModelAdapter(model_path="non_existent_file.joblib")
    assert adapter.load() is False
    assert adapter.is_loaded() is False

    with pytest.raises(ModelNotLoadedError):
        adapter.predict([1.0] * FEATURE_COUNT)


def test_local_adapter_with_real_joblib_artifact():
    """Test LocalModelAdapter with a real scikit-learn estimator serialized to joblib."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_file = os.path.join(tmpdir, "test_threat_model.joblib")

        # Train a small dummy scikit-learn classifier with 6 classes
        X = np.zeros((6, FEATURE_COUNT))
        y = np.array([0, 1, 2, 3, 4, 5])
        clf = DummyClassifier(strategy="most_frequent")
        clf.fit(X, y)

        joblib.dump({"model": clf, "version": "1.2.3", "metadata": {"author": "Person 2"}}, model_file)

        # Load in LocalModelAdapter
        adapter = LocalModelAdapter(model_path=model_file)
        assert adapter.load() is True
        assert adapter.is_loaded() is True
        assert adapter.provider == "local"
        assert adapter.is_mock is False

        features = [0.0] * FEATURE_COUNT
        pred_id = adapter.predict(features)
        assert isinstance(pred_id, int)
        assert pred_id in CLASS_NAMES

        probs = adapter.predict_proba(features)
        assert probs is not None
        assert len(probs) == 6

        meta = adapter.get_metadata()
        assert meta["loaded"] is True
        assert meta["model_version"] == "1.2.3"
        assert meta["extra_metadata"]["author"] == "Person 2"


def test_model_loader_factory():
    """Test ModelLoader factory for creating and dispatching adapters."""
    # Mock settings
    mock_settings = Settings(MODEL_PROVIDER="mock")
    adapter_mock = ModelLoader.create_adapter(mock_settings)
    assert isinstance(adapter_mock, MockModelAdapter)
    assert adapter_mock.is_loaded()

    # Local settings
    local_settings = Settings(MODEL_PROVIDER="local", MODEL_PATH="nonexistent.joblib")
    adapter_local = ModelLoader.create_adapter(local_settings)
    assert isinstance(adapter_local, LocalModelAdapter)

import unittest


class TestModelAdapters(unittest.TestCase):
    """Unittest test case class for Model Adapters."""

    def test_mock_adapter_lifecycle(self):
        test_mock_adapter_lifecycle()

    def test_mock_adapter_rejects_wrong_feature_count(self):
        test_mock_adapter_rejects_wrong_feature_count()

    def test_local_adapter_missing_file_handling(self):
        test_local_adapter_missing_file_handling()

    def test_local_adapter_with_real_joblib_artifact(self):
        test_local_adapter_with_real_joblib_artifact()

    def test_model_loader_factory(self):
        test_model_loader_factory()
