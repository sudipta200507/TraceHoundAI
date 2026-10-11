"""Generic normalizer interface (Phase 3).

Future recon modules convert raw tool output -> Evidence via these helpers.
No Subfinder/Nmap/Nuclei parsers are implemented in this phase.
"""

from __future__ import annotations

from typing import Any

from backend.app.evidence.models import (
    Evidence,
    EvidenceSource,
    EvidenceStatus,
    EvidenceType,
)


def normalize_value(value: str, lowercase: bool = True) -> str:
    """Deterministic string normalization: strip, collapse spaces, optional lower."""
    s = " ".join((value or "").split())
    return s.lower() if lowercase else s


def build_observed_evidence(
    *,
    id: str,
    type: EvidenceType | str,
    source: EvidenceSource | str,
    target: str,
    observed_value: str,
    raw_reference: str,
    confidence: float = 1.0,
    lowercase: bool = True,
    metadata: dict[str, Any] | None = None,
) -> Evidence:
    t = type if isinstance(type, EvidenceType) else EvidenceType(type)
    s = source if isinstance(source, EvidenceSource) else EvidenceSource(source)
    return Evidence(
        id=id,
        type=t,
        source=s,
        target=target.strip(),
        observed_value=observed_value,
        normalized_value=normalize_value(observed_value, lowercase=lowercase),
        status=EvidenceStatus.OBSERVED,
        confidence=confidence,
        raw_reference=raw_reference,
        metadata=dict(metadata or {}),
    )


def subdomain_record_to_evidence(
    *,
    id: str,
    subdomain: str,
    target: str,
    raw_reference: str = "data/raw/subdomain/subfinder.json",
) -> Evidence:
    """Tiny deterministic example: a subfinder-like hostname string -> Evidence."""
    return build_observed_evidence(
        id=id,
        type=EvidenceType.SUBDOMAIN,
        source=EvidenceSource.SUBFINDER,
        target=target,
        observed_value=subdomain,
        raw_reference=raw_reference,
        metadata={"tool": "subfinder"},
    )
