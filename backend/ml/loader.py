"""Factory and loader for model adapters."""

from typing import Optional
from backend.core.config import Settings, settings as default_settings
from backend.core.errors import ConfigurationError
from backend.core.logging import logger
from backend.ml.base import ModelAdapter
from backend.ml.external_adapter import ExternalModelAdapter
from backend.ml.local_adapter import LocalModelAdapter
from backend.ml.mock_adapter import MockModelAdapter


class ModelLoader:
    """Manages the creation, loading, and lifecycle of model adapters."""

    _instance: Optional[ModelAdapter] = None

    @classmethod
    def create_adapter(cls, app_settings: Optional[Settings] = None) -> ModelAdapter:
        """Instantiates the appropriate model adapter based on configuration."""
        cfg = app_settings or default_settings
        provider = cfg.MODEL_PROVIDER.lower().strip()

        logger.info(f"Initializing Model Adapter with provider: '{provider}'")

        if provider == "mock":
            adapter = MockModelAdapter(model_version=cfg.MODEL_VERSION)
        elif provider == "local":
            adapter = LocalModelAdapter(
                model_path=cfg.MODEL_PATH,
                model_name=cfg.MODEL_NAME,
                model_version=cfg.MODEL_VERSION,
            )
        elif provider == "external":
            api_key = cfg.MODEL_API_KEY.get_secret_value() if cfg.MODEL_API_KEY else None
            adapter = ExternalModelAdapter(
                api_url=cfg.MODEL_API_URL,
                api_key=api_key,
                timeout=cfg.REQUEST_TIMEOUT_SECONDS,
                model_name=cfg.MODEL_NAME,
                model_version=cfg.MODEL_VERSION,
            )
        else:
            raise ConfigurationError(
                f"Unsupported MODEL_PROVIDER '{provider}'. Supported options are: 'mock', 'local', 'external'."
            )

        # Attempt to load model into memory
        adapter.load()
        return adapter

    @classmethod
    def get_adapter(cls, app_settings: Optional[Settings] = None, force_reload: bool = False) -> ModelAdapter:
        """Returns singleton adapter instance, creating or reloading if needed."""
        if cls._instance is None or force_reload:
            cls._instance = cls.create_adapter(app_settings)
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Resets the singleton adapter (useful for testing)."""
        cls._instance = None
