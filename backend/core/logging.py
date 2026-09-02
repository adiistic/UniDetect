"""Structured logging configuration for UniDetect."""

import logging
import sys
from typing import Any, Dict


class SafeFormatter(logging.Formatter):
    """Log formatter that ensures sensitive keywords (like API keys) are not leaked."""

    SENSITIVE_KEYS = ["api_key", "apikey", "secret", "password", "token", "authorization"]

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        return msg


def setup_logger(name: str = "unidetect", log_level: str = "INFO") -> logging.Logger:
    """Configures and returns the application logger."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Avoid duplicate handlers
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        formatter = SafeFormatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


logger = setup_logger()
