"""Logging utilities for ModelGuard."""

import logging
import sys
from typing import Optional

# Configure logger
logger = logging.getLogger("modelguard")


def setup_logging(level: str = "INFO") -> None:
    """Setup logging configuration."""
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Create handler if not already exists
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(log_level)


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a logger instance."""
    if name:
        return logging.getLogger(f"modelguard.{name}")
    return logger


# Initialize default logging
setup_logging()
