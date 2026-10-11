"""TraceHoundAI logger — stdlib only. Never log secrets or credentials."""

from __future__ import annotations

import logging

_configured = False


def get_logger(name: str = "tracehound") -> logging.Logger:
    global _configured
    logger = logging.getLogger(name)
    if not _configured:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        _configured = True
    return logger


def stage_log(logger: logging.Logger, scan_id: str, stage: str,
              status: str, duration_ms: float = 0.0) -> None:
    """One structured line per stage: ids, stage, status, duration only."""
    logger.info("scan_id=%s stage=%s status=%s duration_ms=%.1f",
                scan_id, stage, status, duration_ms)
