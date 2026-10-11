"""Pipeline stage definitions (Phase 11) — deterministic order + dependencies.

A later stage never executes before its dependencies are valid. Statuses:
pending | running | completed | failed | skipped | blocked.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

StageStatus = Literal["pending", "running", "completed", "failed", "skipped", "blocked"]


class StageDefinition(BaseModel):
    stage_id: str
    name: str
    depends_on: list[str] = Field(default_factory=list)
    requires_active_policy: bool = False


class StageResult(BaseModel):
    stage_id: str
    name: str = ""
    status: StageStatus = "pending"
    started_at: str = ""
    completed_at: str = ""
    duration_ms: float = 0.0
    inputs: list[str] = Field(default_factory=list)
    outputs: list[str] = Field(default_factory=list)
    error: str = ""


STAGES: list[StageDefinition] = [
    StageDefinition(stage_id="scope_validation", name="Scope validation"),
    StageDefinition(stage_id="asset_discovery", name="Asset discovery",
                    depends_on=["scope_validation"]),
    StageDefinition(stage_id="live_discovery", name="DNS/live-host discovery",
                    depends_on=["asset_discovery"]),
    StageDefinition(stage_id="port_service", name="Port/service discovery",
                    depends_on=["live_discovery"], requires_active_policy=True),
    StageDefinition(stage_id="fingerprinting", name="Technology fingerprinting",
                    depends_on=["live_discovery"]),
    StageDefinition(stage_id="endpoint_discovery", name="Endpoint discovery",
                    depends_on=["live_discovery"]),
    StageDefinition(stage_id="screenshot_capture", name="Screenshot capture",
                    depends_on=["live_discovery"]),
    StageDefinition(stage_id="vulnerability_verification",
                    name="Nuclei vulnerability verification",
                    depends_on=["live_discovery"], requires_active_policy=True),
    StageDefinition(stage_id="security_enrichment",
                    name="NVD/CISA KEV enrichment",
                    depends_on=["vulnerability_verification"]),
    StageDefinition(stage_id="ai_analysis", name="Qwen3 8B analysis",
                    depends_on=["security_enrichment"]),
    StageDefinition(stage_id="ai_validation", name="AI validation",
                    depends_on=["ai_analysis"]),
    StageDefinition(stage_id="report_generation", name="Markdown report",
                    depends_on=["ai_validation"]),
]

STAGE_IDS: list[str] = [s.stage_id for s in STAGES]
