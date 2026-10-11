"""TraceHoundAI evidence models (Phase 3) — deterministic, Pydantic, no LLM."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class EvidenceSource(str, Enum):
    SUBFINDER = "subfinder"
    CRTSH = "crtsh"
    DNSX = "dnsx"
    HTTPX = "httpx"
    NAABU = "naabu"
    NMAP = "nmap"
    WHATWEB = "whatweb"
    KATANA = "katana"
    GOWITNESS = "gowitness"
    NUCLEI = "nuclei"
    MANUAL = "manual"
    CORRELATOR = "correlator"
    VERIFIER = "verifier"


class EvidenceType(str, Enum):
    ASSET = "asset"
    SUBDOMAIN = "subdomain"
    DNS = "dns"
    LIVE_HOST = "live_host"
    HTTP = "http"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    ENDPOINT = "endpoint"
    SCREENSHOT = "screenshot"
    VULNERABILITY = "vulnerability"
    CERTIFICATE = "certificate"
    HEADER = "header"
    TLS = "tls"


class EvidenceStatus(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    VERIFIED = "verified"
    REJECTED = "rejected"


class Evidence(BaseModel):
    """A single deterministic fact. The LLM is never the source of truth."""

    id: str = Field(pattern=r"^E\d{3,}$")
    type: EvidenceType
    source: EvidenceSource
    target: str = Field(min_length=1)
    observed_value: str = Field(min_length=1)
    normalized_value: str = Field(min_length=1)
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_reference: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target", mode="before")
    @classmethod
    def _strip_target(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError("target must be a non-empty string")
        return v.strip()


class ScanContext(BaseModel):
    """Lightweight scan association: scan_id + target + evidence IDs."""

    scan_id: str = Field(min_length=1)
    target: str = Field(min_length=1)
    scope: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)


class EvidencedClaim(BaseModel):
    """Future AI finding shape — a claim linked to evidence IDs."""

    finding_id: str = Field(min_length=1)
    claim: str = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    status: Literal["proposed", "supported", "rejected", "verified"] = "proposed"

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def _non_empty_ids(cls, v):
        if not v:
            raise ValueError("evidence_ids must not be empty")
        return v


# Backwards-compatible alias used in Task 1 wording.
EvidenceTarget = str
ScopeDecisionRef = Optional[str]
