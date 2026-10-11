"""AI finding validator (Phase 9) — deterministic acceptance gate.

A finding is accepted only when:
  1. every cited Evidence ID exists in the current scan,
  2. no cited ID belongs to another scan,
  3. CVE claims exist in the scan's verified CVE set,
  4. `verified` status is backed by verification evidence.
Anything else is downgraded (hypothesis/unverified) or rejected.
The model is never trusted.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from backend.app.ai.schemas.finding import AIFinding


class AIValidationResult(BaseModel):
    accepted: bool
    downgraded: bool = False
    reasons: list[str] = []


def validate_finding(
    finding: AIFinding,
    evidence_by_id: dict[str, dict[str, Any]],
    verified_cves: set[str],
    scan_evidence_ids: set[str] | None = None,
) -> AIValidationResult:
    reasons: list[str] = []
    known = set(evidence_by_id)
    allowed = scan_evidence_ids if scan_evidence_ids is not None else known

    for eid in finding.evidence_ids:
        if eid not in known:
            reasons.append(f"nonexistent Evidence ID cited: {eid}")
        elif eid not in allowed:
            reasons.append(f"cross-scan Evidence ID cited: {eid}")

    text = " ".join([finding.title, finding.description, finding.reasoning]).upper()
    import re

    for cve in sorted(set(re.findall(r"CVE-(?:19\d{2}|20\d{2})-\d{4,7}", text))):
        if cve not in {c.upper() for c in verified_cves}:
            reasons.append(f"unsupported CVE claim: {cve}")
    for cve in finding.cves:
        if cve.upper() not in {c.upper() for c in verified_cves}:
            reasons.append(f"unsupported CVE claim: {cve}")

    if finding.verification_status == "verified":
        cited = [evidence_by_id[e] for e in finding.evidence_ids if e in evidence_by_id]
        backed = any(str(e.get("status", "")).lower() == "verified" for e in cited)
        nvd_backed = any(
            str(e.get("nvd_status", "") or "") == "confirmed_by_nvd" for e in cited)
        if not (backed or nvd_backed):
            reasons.append("false verified status: no verification evidence cited")

    if any("nonexistent" in r or "cross-scan" in r for r in reasons):
        return AIValidationResult(accepted=False, downgraded=False, reasons=reasons)
    if reasons:
        return AIValidationResult(accepted=True, downgraded=True, reasons=reasons)
    return AIValidationResult(accepted=True, downgraded=False, reasons=[])
