"""Pytest configuration and test fixtures."""

from typing import Generator, List
import pytest
from fastapi.testclient import TestClient

from backend.core.config import Settings
from backend.core.constants import FEATURE_COUNT
from backend.main import app
from backend.ml.loader import ModelLoader
from backend.ml.mock_adapter import MockModelAdapter


@pytest.fixture(autouse=True)
def reset_model_loader() -> Generator[None, None, None]:
    """Ensures a clean mock model loader state for every test."""
    ModelLoader.reset()
    yield
    ModelLoader.reset()


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    """FastAPI TestClient fixture."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def valid_78d_vector() -> List[float]:
    """Fixture returning a canonical valid 78-dimensional float vector."""
    return [float(i * 0.1) for i in range(FEATURE_COUNT)]


@pytest.fixture
def zero_78d_vector() -> List[float]:
    """Fixture returning 78 zeros."""
    return [0.0] * FEATURE_COUNT
