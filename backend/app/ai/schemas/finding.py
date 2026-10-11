"""AI finding schemas (Phase 9) — evidence IDs mandatory, confidence separate."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

ClaimType = Literal["observed_fact", "hypothesis", "verified_finding", "unknown"]
Severity = Literal["info", "low", "medium", "high", "critical"]
VerificationStatus = Literal["unverified", "supported", "verified", "rejected"]


class AIFinding(BaseModel):
    finding_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    classification: ClaimType = "hypothesis"
    severity: Severity = "medium"
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(min_length=1)
    observed_facts: list[str] = Field(default_factory=list)
    reasoning: str = ""
    verification_status: VerificationStatus = "unverified"
    next_manual_steps: list[str] = Field(default_factory=list)
    # Structured entity claims — each entry is validated against cited evidence.
    cves: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def _ids_required(cls, v):
        if not v:
            raise ValueError("evidence_ids must list at least one Evidence ID")
        return v
