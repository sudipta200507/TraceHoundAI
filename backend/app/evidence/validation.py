"""Deterministic evidence validation (Phase 3) — no LLM."""

from __future__ import annotations

import re

from backend.app.evidence.models import Evidence, EvidenceStatus

_ID_RE = re.compile(r"^E\d{3,}$")


def validate_evidence(evidence: Evidence) -> list[str]:
    """Return a list of problems; empty means valid."""
    problems: list[str] = []
    if not evidence.id or not _ID_RE.match(evidence.id):
        problems.append("evidence must have an ID like E001")
    if not evidence.source:
        problems.append("evidence must have a source")
    if not evidence.type:
        problems.append("evidence must have a type")
    if not (evidence.target or "").strip():
        problems.append("empty/invalid target")
    if not (0.0 <= evidence.confidence <= 1.0):
        problems.append("confidence must be within [0, 1]")
    if evidence.status == EvidenceStatus.OBSERVED:
        if not (evidence.raw_reference or "").strip():
            problems.append("observed evidence requires a raw_reference")
    if evidence.status == EvidenceStatus.VERIFIED:
        meta = evidence.metadata or {}
        if not meta.get("verified_by"):
            problems.append("verified evidence must set metadata.verified_by")
        if not meta.get("verification_ref"):
            problems.append("verified evidence must set metadata.verification_ref")
    if evidence.status == EvidenceStatus.INFERRED:
        if not (evidence.metadata or {}).get("derived_from"):
            problems.append("inferred evidence should set metadata.derived_from")
    return problems


def assert_valid(evidence: Evidence) -> Evidence:
    problems = validate_evidence(evidence)
    if problems:
        raise ValueError("; ".join(problems))
    return evidence
