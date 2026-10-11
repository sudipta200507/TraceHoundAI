"""AI attack-path schemas (Phase 9) — hypotheses only, never executables."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AttackPathStep(BaseModel):
    asset: str = Field(min_length=1)
    observed_condition: str = Field(min_length=1)
    relationship: str = ""
    hypothesis: str = Field(min_length=1)
    required_verification: str = Field(min_length=1)


class AIAttackPath(BaseModel):
    attack_path_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    starting_asset: str = Field(min_length=1)
    steps: list[AttackPathStep] = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    status: str = "hypothesis"
