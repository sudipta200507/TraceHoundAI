"""AI analysis + recommendation schemas (Phase 9)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

from backend.app.ai.schemas.finding import AIFinding


class AIRecommendation(BaseModel):
    recommendation_id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    # May be empty only for model-shaped deviations normalized by
    # reasoning._coerce_recommendations, which always attaches a
    # "without cited evidence" rationale in that case.
    evidence_ids: list[str] = Field(default_factory=list)
    rationale: str = ""
    priority: Literal["low", "medium", "high"] = "medium"


class AIAnalysis(BaseModel):
    scan_id: str = Field(min_length=1)
    model: str = Field(min_length=1)
    findings: list[AIFinding] = Field(default_factory=list)
    recommendations: list[AIRecommendation] = Field(default_factory=list)
    executive_summary: str = ""
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: Literal["completed", "failed"] = "completed"
    error: str = ""
