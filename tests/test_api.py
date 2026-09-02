"""FastAPI route integration tests."""

import pytest
from fastapi.testclient import TestClient
from backend.core.constants import FEATURE_COUNT
from backend.main import app
from backend.ml.loader import ModelLoader
from backend.ml.local_adapter import LocalModelAdapter


def test_health_endpoint(client: TestClient):
    """Test GET /api/v1/health returns ok status."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "unidetect-backend"
    assert "model_loaded" in data


def test_readiness_endpoint_ready(client: TestClient):
    """Test GET /api/v1/readiness returns ready when mock model is active."""
    response = client.get("/api/v1/readiness")
    assert response.status_code == 200
    data = response.json()
    assert data["ready"] is True
    assert data["status"] == "READY"
    assert data["provider"] == "mock"


def test_model_status_endpoint(client: TestClient):
    """Test GET /api/v1/model/status exposes safe model metadata."""
    response = client.get("/api/v1/model/status")
    assert response.status_code == 200
    data = response.json()
    assert data["loaded"] is True
    assert data["provider"] == "mock"
    assert data["is_mock"] is True
    assert data["feature_count"] == 78
    assert data["schema_version"] == "78d-v1"
    assert "classes" in data["metadata"]
    # Verify no secret keywords leaked
    assert "api_key" not in str(data).lower()
    assert "secret" not in str(data).lower()


def test_predict_endpoint_valid_78d(client: TestClient, valid_78d_vector):
    """Test POST /api/v1/predict with exactly 78 numeric values."""
    payload = {"features": valid_78d_vector}
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Verify structured frontend-friendly response
    assert "prediction" in data
    assert "class_id" in data["prediction"]
    assert "class_name" in data["prediction"]
    assert isinstance(data["prediction"]["class_id"], int)
    assert isinstance(data["prediction"]["class_name"], str)

    assert "confidence" in data
    assert isinstance(data["confidence"], float)
    assert 0.0 <= data["confidence"] <= 1.0

    assert "probabilities" in data
    assert len(data["probabilities"]) == 6
    assert sum(data["probabilities"].values()) == pytest.approx(1.0, rel=1e-3)

    assert data["model"]["provider"] == "mock"
    assert data["model"]["feature_count"] == 78
    assert data["mode"] == "mock"
    assert "latency_ms" in data


def test_predict_endpoint_rejects_77_features(client: TestClient):
    """Test POST /api/v1/predict returns 422 on 77 features."""
    payload = {"features": [0.0] * 77}
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert data["error"]["code"] == "INVALID_FEATURE_VECTOR"
    assert "Expected exactly 78 features, got 77" in data["error"]["message"]


def test_predict_endpoint_rejects_79_features(client: TestClient):
    """Test POST /api/v1/predict returns 422 on 79 features."""
    payload = {"features": [0.0] * 79}
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert data["error"]["code"] == "INVALID_FEATURE_VECTOR"
    assert "Expected exactly 78 features, got 79" in data["error"]["message"]


def test_predict_endpoint_rejects_nan(client: TestClient):
    """Test POST /api/v1/predict rejects NaN values with 422."""
    raw_features = [0.0] * FEATURE_COUNT
    raw_features[5] = None  # None or invalid representation
    response = client.post("/api/v1/predict", json={"features": raw_features})
    assert response.status_code == 422
    data = response.json()
    assert "error" in data


def test_predict_endpoint_rejects_strings(client: TestClient):
    """Test POST /api/v1/predict rejects non-numeric string values."""
    raw_features = [0.0] * FEATURE_COUNT
    raw_features[2] = "malicious_string"  # type: ignore
    response = client.post("/api/v1/predict", json={"features": raw_features})
    assert response.status_code == 422


def test_predict_endpoint_rejects_malformed_json(client: TestClient):
    """Test POST /api/v1/predict returns 422 on malformed body."""
    response = client.post(
        "/api/v1/predict",
        content="not-json-content",
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422


def test_batch_predict_endpoint(client: TestClient):
    """Test POST /api/v1/predict/batch processes multiple samples."""
    sample1 = [0.0] * FEATURE_COUNT
    sample2 = [1.0] * FEATURE_COUNT
    sample3 = [2.5] * FEATURE_COUNT

    payload = {
        "samples": [
            {"features": sample1},
            {"features": sample2},
            {"features": sample3},
        ]
    }

    response = client.post("/api/v1/predict/batch", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["total_samples"] == 3
    assert len(data["results"]) == 3
    assert data["results"][0]["sample_index"] == 0
    assert data["results"][1]["sample_index"] == 1
    assert data["results"][2]["sample_index"] == 2
    assert data["mode"] == "mock"


def test_batch_predict_rejects_invalid_sample_in_batch(client: TestClient):
    """Test POST /api/v1/predict/batch rejects the entire request if any sample is invalid."""
    valid_sample = [0.0] * FEATURE_COUNT
    invalid_sample = [0.0] * 50

    payload = {
        "samples": [
            {"features": valid_sample},
            {"features": invalid_sample},
        ]
    }

    response = client.post("/api/v1/predict/batch", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert "Expected exactly 78 features" in data["error"]["message"]


def test_predict_when_model_not_loaded(client: TestClient):
    """Test POST /api/v1/predict returns 503 when local model artifact is missing."""
    # Set an uninitialized local adapter in ModelLoader
    unready_adapter = LocalModelAdapter(model_path="missing_file.joblib")
    ModelLoader._instance = unready_adapter

    payload = {"features": [0.0] * FEATURE_COUNT}
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 503
    data = response.json()
    assert data["error"]["code"] == "MODEL_NOT_LOADED"


def test_openapi_docs_endpoints(client: TestClient):
    """Test FastAPI exposes /docs and /openapi.json."""
    docs_resp = client.get("/docs")
    assert docs_resp.status_code == 200

    openapi_resp = client.get("/openapi.json")
    assert openapi_resp.status_code == 200
    schema = openapi_resp.json()
    assert "/api/v1/predict" in schema["paths"]
    assert "/api/v1/predict/batch" in schema["paths"]
    assert "/api/v1/health" in schema["paths"]
    assert "/api/v1/readiness" in schema["paths"]
    assert "/api/v1/model/status" in schema["paths"]


import unittest


class TestAPIEndpoints(unittest.TestCase):
    """Unittest test case class for API endpoints."""

    def setUp(self):
        ModelLoader.reset()
        self.client = TestClient(app)

    def tearDown(self):
        ModelLoader.reset()

    def test_health_endpoint(self):
        test_health_endpoint(self.client)

    def test_readiness_endpoint_ready(self):
        test_readiness_endpoint_ready(self.client)

    def test_model_status_endpoint(self):
        test_model_status_endpoint(self.client)

    def test_predict_endpoint_valid_78d(self):
        test_predict_endpoint_valid_78d(self.client, [0.0] * FEATURE_COUNT)

    def test_predict_endpoint_rejects_77_features(self):
        test_predict_endpoint_rejects_77_features(self.client)

    def test_predict_endpoint_rejects_79_features(self):
        test_predict_endpoint_rejects_79_features(self.client)

    def test_predict_endpoint_rejects_nan(self):
        test_predict_endpoint_rejects_nan(self.client)

    def test_predict_endpoint_rejects_strings(self):
        test_predict_endpoint_rejects_strings(self.client)

    def test_predict_endpoint_rejects_malformed_json(self):
        test_predict_endpoint_rejects_malformed_json(self.client)

    def test_batch_predict_endpoint(self):
        test_batch_predict_endpoint(self.client)

    def test_batch_predict_rejects_invalid_sample_in_batch(self):
        test_batch_predict_rejects_invalid_sample_in_batch(self.client)

    def test_predict_when_model_not_loaded(self):
        test_predict_when_model_not_loaded(self.client)

    def test_openapi_docs_endpoints(self):
        test_openapi_docs_endpoints(self.client)
