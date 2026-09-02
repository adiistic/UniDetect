"""Application configuration settings using Pydantic."""

from typing import List, Optional
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Application settings
    APP_NAME: str = "UniDetect Backend"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # CORS settings (comma-separated list of allowed origins)
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173"

    # ML Model Configuration
    # Supported providers: "mock", "local", "external"
    MODEL_PROVIDER: str = Field(default="mock", description="Model provider: mock, local, or external")
    MODEL_PATH: str = Field(default="models/unidetect_model.joblib", description="Path to trained local model artifact")
    MODEL_NAME: str = Field(default="unidetect_threat_classifier", description="Model identifier name")
    MODEL_VERSION: str = Field(default="0.1.0-dev", description="Model version tag")
    SCHEMA_VERSION: str = Field(default="78d-v1", description="Expected feature schema version")

    # External Model Provider Settings (Never hard-code keys)
    MODEL_API_URL: Optional[str] = Field(default=None, description="Remote ML model inference endpoint URL")
    MODEL_API_KEY: Optional[SecretStr] = Field(default=None, description="Secret API key for external ML provider")
    REQUEST_TIMEOUT_SECONDS: float = Field(default=15.0, description="HTTP timeout for external model API")

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse comma-separated CORS origins into a list of clean URLs."""
        if not self.CORS_ORIGINS:
            return []
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


# Global cached settings instance
settings = Settings()
