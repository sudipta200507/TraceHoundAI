"""Per-stage checkpoints (Phase 11) — restartable, deterministically valid.

A checkpoint is valid only when status is completed AND every listed
output file exists. Resume never repeats a valid stage and never resumes
a stage whose outputs are missing or invalid.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


class Checkpoint(BaseModel):
    scan_id: str
    stage: str
    status: str = "pending"
    started_at: str = ""
    completed_at: str = ""
    output_files: list[str] = Field(default_factory=list)
    error: str = ""


def checkpoints_dir(scan_id: str, base: Optional[Path] = None) -> Path:
    root = base or Path(__file__).resolve().parents[3]
    d = root / "data" / "processed" / scan_id / "checkpoints"
    d.mkdir(parents=True, exist_ok=True)
    return d


def checkpoint_path(scan_id: str, stage: str, base: Optional[Path] = None) -> Path:
    return checkpoints_dir(scan_id, base) / f"{stage}.json"


def write_checkpoint(checkpoint: Checkpoint, base: Optional[Path] = None) -> Path:
    path = checkpoint_path(checkpoint.scan_id, checkpoint.stage, base)
    path.write_text(checkpoint.model_dump_json(indent=2), encoding="utf-8")
    return path


def read_checkpoint(scan_id: str, stage: str,
                    base: Optional[Path] = None) -> Optional[Checkpoint]:
    path = checkpoint_path(scan_id, stage, base)
    if not path.exists():
        return None
    try:
        return Checkpoint.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def checkpoint_valid(scan_id: str, stage: str, base: Optional[Path] = None) -> bool:
    """Deterministic validity: completed + checkpoint file + all outputs exist."""
    checkpoint = read_checkpoint(scan_id, stage, base)
    if checkpoint is None or checkpoint.status != "completed":
        return False
    if checkpoint.scan_id != scan_id or checkpoint.stage != stage:
        return False
    return bool(checkpoint.output_files) and all(
        Path(f).exists() for f in checkpoint.output_files)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
