"""Scan API schemas (Phase 11) — Pydantic validation on every boundary."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class ScanCreateRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    scan_id: Optional[str] = None
    authorize_active: bool = False
    approved_by: str = ""
    reason: str = ""


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    root_domain: str = ""
    reachability: dict[str, Any] = Field(default_factory=dict)
    scope: dict[str, Any] = Field(default_factory=dict)


class StageStatusResponse(BaseModel):
    stage: str
    name: str = ""
    status: str
    started_at: str = ""
    completed_at: str = ""
    duration_ms: float = 0.0
    error: str = ""


class ScanStatusResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    scan_mode: str = "passive"
    execution_enabled: bool = False
    reachability: dict[str, Any] = Field(default_factory=dict)
    current_stage: str = ""
    started_at: str = ""
    completed_at: str = ""
    stages: list[StageStatusResponse] = Field(default_factory=list)
    error: str = ""
    report_path: str = ""


class ScanStagesResponse(BaseModel):
    scan_id: str
    stages: list[StageStatusResponse] = Field(default_factory=list)


class FindingResponse(BaseModel):
    finding_id: str
    title: str = ""
    severity: str = ""
    confidence: float = 0.0
    classification: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    verification_status: str = ""


class ScanFindingsResponse(BaseModel):
    scan_id: str
    findings: list[FindingResponse] = Field(default_factory=list)


class ScanReportResponse(BaseModel):
    scan_id: str
    report_path: str
    markdown: str
    pdf_path: str = ""
    pdf_available: bool = False


class StageCountResponse(BaseModel):
    stage: str
    name: str = ""
    status: str = ""
    inputs: int = 0
    outputs: int = 0
    output_file: str = ""
    error: str = ""


class ScanSummaryResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    scan_mode: str = "passive"
    execution_enabled: bool = False
    assets: int = 0
    live_hosts: int = 0
    open_ports: int = 0
    services: int = 0
    technologies: int = 0
    endpoints: int = 0
    screenshots: int = 0
    vulnerability_observations: int = 0
    cves_enriched: int = 0
    ai_findings: int = 0
    stages: list[StageCountResponse] = Field(default_factory=list)


class PipelineResultResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    stages: list[StageStatusResponse] = Field(default_factory=list)
    findings_count: int = 0
    asset_count: int = 0
    live_host_count: int = 0
    port_count: int = 0
    endpoint_count: int = 0
    vulnerability_count: int = 0
    report_path: str = ""
    error: str = ""


class PreflightResponse(BaseModel):
    target: str
    scope_allowed: bool = False
    scope_reason: str = ""
    effective_scope: dict[str, Any] = Field(default_factory=dict)
    missing_required_tools: list[str] = Field(default_factory=list)
    policy: dict[str, Any] = Field(default_factory=dict)
    model_available: bool = False
    directories_ok: bool = False
    ready: bool = False
