"""CVE correlation + verified security context (Phase 8).

CVE IDs are accepted ONLY from explicit scanner fields (template-id, name,
description, references, tags, cve-id) — never from technology names.
verified_context.json keeps scanner_observation / cve_identity /
nvd_enrichment / kev_enrichment strictly separated, with per-CVE evidence
traceability. Anti-hallucination rules are enforced programmatically.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from backend.app.enrichment.cisa_kev import CISAKEVContext, KEV_URL, check_kev
from backend.app.enrichment.nuclei import NucleiFinding, run_nuclei
from backend.app.enrichment.nvd import NVDContext, lookup_cve
from backend.app.evidence.evidence_id import EvidenceIdGenerator
from backend.app.evidence.models import Evidence, EvidenceSource, EvidenceType
from backend.app.evidence.normalizer import build_observed_evidence
from backend.app.safety.scope_validator import ScopeConfig, ScopePolicy

STAGE_NAME = "vulnerability_verification"

CVE_RE = re.compile(r"\bCVE-(?:19\d{2}|20\d{2})-\d{4,7}\b")


class CVEContext(BaseModel):
    cve_id: str
    scanner_observed: bool = False
    origin: str = "scanner"
    evidence_ids: list[str] = Field(default_factory=list)


class VerifiedFinding(BaseModel):
    cve_id: str
    scanner_observed: bool = False
    nvd_confirmed: bool = False
    nvd_status: str = "unknown"
    known_exploited: bool = False
    kev_status: str = "unknown"
    severity: str = ""
    cvss_score: Optional[float] = None
    evidence_ids: list[str] = Field(default_factory=list)
    nvd: NVDContext | None = None
    kev: CISAKEVContext | None = None


class VerifiedSecurityContext(BaseModel):
    scan_id: str
    target: str
    findings: list[VerifiedFinding] = Field(default_factory=list)
    rejected: list[dict[str, str]] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    checkpoint: dict[str, Any] = Field(default_factory=dict)


def extract_cve_ids(text: str) -> list[str]:
    """Strict CVE syntax only. Technology names can never produce a CVE here."""
    seen: list[str] = []
    for match in CVE_RE.findall((text or "").upper()):
        if match not in seen:
            seen.append(match)
    return seen


def cves_from_finding(finding: NucleiFinding) -> list[str]:
    """Collect CVEs from explicit scanner fields only (never technology names)."""
    parts: list[str] = []
    for value in [finding.template_id, finding.name, finding.description,
                  finding.matcher_name, *finding.tags, *finding.reference]:
        if value:
            parts.append(str(value))
    parts.extend(finding.cve_ids)
    out: list[str] = []
    for part in parts:
        for cve in extract_cve_ids(part):
            if cve not in out:
                out.append(cve)
    return out


def validate_verified_context(ctx: VerifiedSecurityContext) -> list[str]:
    """Enforce RULES 1-6. Returns problems; empty means valid."""
    problems: list[str] = []
    for finding in ctx.findings:
        if not CVE_RE.fullmatch(finding.cve_id):
            problems.append(f"RULE 6: invalid CVE ID accepted: {finding.cve_id}")
        if not finding.evidence_ids:
            problems.append(f"RULE 1: {finding.cve_id} has no supporting evidence")
        known = {e.id for e in ctx.evidence}
        for eid in finding.evidence_ids:
            if eid not in known:
                problems.append(f"RULE 1: {finding.cve_id} references unknown {eid}")
        if finding.nvd_confirmed and finding.nvd_status != "confirmed_by_nvd":
            problems.append(f"RULE 3/4: {finding.cve_id} claims NVD confirmation "
                            "without confirmed_by_nvd status")
    return problems


def project_root() -> Path:
    return Path(__file__).resolve().parents[4]


def run_verification(
    scan_id: str,
    targets: list[str],
    config: Optional[ScopeConfig] = None,
    policy: Optional[ScopePolicy] = None,
    nuclei_runner=None,
    nvd_fetcher: Optional[Callable[[str, int], str]] = None,
    kev_fetcher: Optional[Callable[[str, int], str]] = None,
    base: Optional[Path] = None,
    generator: Optional[EvidenceIdGenerator] = None,
) -> VerifiedSecurityContext:
    """Nuclei -> CVE extraction -> NVD + KEV enrichment -> verified context.

    Each enrichment failure is isolated per CVE (unavailable/error, never
    rewritten as not vulnerable). No LLM anywhere in this stage.
    """
    root = base or project_root()
    started = datetime.now(timezone.utc).isoformat()

    nuclei_run = run_nuclei(targets, scan_id, config, policy,
                            **({"runner": nuclei_runner} if nuclei_runner else {}))
    rejected: list[dict[str, str]] = list(nuclei_run.rejected)
    anchor = sorted({r.target for r in nuclei_run.results})
    target = anchor[0] if anchor else ""

    # Per-finding CVE evidence (observed, never verified yet).
    gen = generator or EvidenceIdGenerator()
    evidence: list[Evidence] = []
    cve_evidence: dict[str, list[str]] = {}
    cve_severity: dict[str, str] = {}
    for result in nuclei_run.results:
        for finding in result.findings:
            for cve in cves_from_finding(finding):
                eid = gen.next()
                cve_evidence.setdefault(cve, []).append(eid)
                if finding.severity and cve not in cve_severity:
                    cve_severity[cve] = finding.severity
                observed = f"{finding.template_id} {finding.severity} {finding.matched_at}".strip()
                evidence.append(build_observed_evidence(
                    id=eid, type=EvidenceType.VULNERABILITY, source=EvidenceSource.NUCLEI,
                    target=finding.host or result.target,
                    observed_value=observed or finding.template_id,
                    raw_reference=f"data/raw/nuclei/{scan_id}/nuclei.jsonl",
                    metadata={"tool": "nuclei", "scan_id": scan_id,
                              "template_id": finding.template_id,
                              "severity": finding.severity, "cve_id": cve}))

    # Raw Nuclei checkpoint (always preserved, even if enrichment fails).
    nuclei_dir = root / "data" / "raw" / "nuclei" / scan_id
    nuclei_dir.mkdir(parents=True, exist_ok=True)
    nuclei_file = nuclei_dir / "nuclei.jsonl"
    nuclei_file.write_text("\n".join(
        r.stdout for r in nuclei_run.results if r.stdout), encoding="utf-8")

    # KEV catalog: single fetch, reused for every CVE.
    kev_catalog: Optional[str] = None
    kev_failed = False
    if cve_evidence:
        try:
            from backend.app.enrichment.cisa_kev import _default_fetcher
            kev_catalog = (kev_fetcher or _default_fetcher)(KEV_URL, 30)
        except Exception as exc:
            kev_failed = True
            rejected.append({"value": "cisa-kev-catalog",
                             "reason": f"KEV unavailable: {exc}"})
        (root / "data" / "raw" / "cisa_kev" / scan_id).mkdir(
            parents=True, exist_ok=True)
        (root / "data" / "raw" / "cisa_kev" / scan_id / "kev.json").write_text(
            kev_catalog or "", encoding="utf-8")

    findings: list[VerifiedFinding] = []
    for cve in sorted(cve_evidence):
        try:
            nvd_ctx, nvd_raw = lookup_cve(cve, fetcher=nvd_fetcher)
        except Exception as exc:
            nvd_ctx, nvd_raw = NVDContext(cve_id=cve, nvd_status="unavailable"), ""
            rejected.append({"value": cve, "reason": f"NVD unavailable: {exc}"})
        (root / "data" / "raw" / "nvd" / scan_id).mkdir(parents=True, exist_ok=True)
        (root / "data" / "raw" / "nvd" / scan_id / f"{cve}.json").write_text(
            nvd_raw, encoding="utf-8")
        if kev_failed or kev_catalog is None:
            kev_ctx = CISAKEVContext(cve_id=cve, kev_status="unavailable")
        else:
            try:
                from backend.app.enrichment.cisa_kev import parse_kev_catalog
                kev_ctx = parse_kev_catalog(cve, kev_catalog)
            except Exception as exc:
                kev_ctx = CISAKEVContext(cve_id=cve, kev_status="unavailable")
                rejected.append({"value": cve, "reason": f"KEV parse failed: {exc}"})
        findings.append(VerifiedFinding(
            cve_id=cve, scanner_observed=True,
            nvd_confirmed=nvd_ctx.nvd_status == "confirmed_by_nvd",
            nvd_status=nvd_ctx.nvd_status,
            known_exploited=kev_ctx.known_exploited, kev_status=kev_ctx.kev_status,
            severity=cve_severity.get(cve, ""), cvss_score=nvd_ctx.cvss_score,
            evidence_ids=list(cve_evidence[cve]), nvd=nvd_ctx, kev=kev_ctx))

    ctx = VerifiedSecurityContext(
        scan_id=scan_id, target=target, findings=findings, rejected=rejected,
        evidence=evidence,
        checkpoint={"scan_id": scan_id, "stage": STAGE_NAME, "status": "completed",
                    "started_at": started,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "output_files": [str(nuclei_file)]})
    problems = validate_verified_context(ctx)
    if problems:
        raise RuntimeError(f"verified context failed anti-hallucination rules: {problems}")
    out_file = root / "data" / "processed" / "verified_context.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(ctx.model_dump_json(indent=2), encoding="utf-8")
    ctx.checkpoint["output_files"].append(str(out_file))
    return ctx
