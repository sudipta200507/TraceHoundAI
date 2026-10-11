"""AI finding orchestration (Phase 9) — deterministic, model output untrusted.

generate_analysis(): prompt -> injected model call -> JSON parse (failures
captured, never silently repaired) -> Pydantic -> ai_validator +
hallucination_guard (downgrade/reject) -> raw + processed checkpoints.
The model cannot execute tools, authorize scans, or create evidence.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from backend.app.ai.context_builder import build_context, evidence_index, verified_cve_set
from backend.app.ai.ollama_client import LLMConfig
from backend.app.ai.prompts.finding_analysis import build_finding_prompt
from backend.app.ai.schemas.analysis import AIAnalysis, AIRecommendation
from backend.app.ai.schemas.attack_path import AIAttackPath
from backend.app.ai.schemas.finding import AIFinding
from backend.app.validation.ai_validator import validate_finding
from backend.app.validation.hallucination_guard import check_finding


def _coerce_recommendations(items: Any) -> tuple[list[AIRecommendation], int]:
    """Normalize recommendation drafts. Plain strings become objects with an
    explicit no-evidence rationale (marked, never silently trusted); malformed
    entries are skipped and counted. Returns (valid, skipped)."""
    valid: list[AIRecommendation] = []
    skipped = 0
    counter = 0
    for item in items if isinstance(items, list) else []:
        try:
            if isinstance(item, str):
                counter += 1
                valid.append(AIRecommendation(
                    recommendation_id=f"R{counter:03d}",
                    text=item.strip(),
                    evidence_ids=[],
                    rationale="Model-provided recommendation without cited "
                              "evidence — verify manually before acting.",
                    priority="medium"))
            elif isinstance(item, dict):
                valid.append(AIRecommendation(**item))
            else:
                skipped += 1
        except Exception:
            skipped += 1
    return valid, skipped


def _coerce_findings(items: Any) -> tuple[list[AIFinding], int]:
    """Parse finding drafts individually; malformed entries are skipped and
    counted instead of destroying the whole analysis."""
    valid: list[AIFinding] = []
    skipped = 0
    for item in items if isinstance(items, list) else []:
        try:
            valid.append(AIFinding(**item) if isinstance(item, dict)
                         else AIFinding.model_validate(item))
        except Exception:
            skipped += 1
    return valid, skipped


def _is_timeout_error(exc: Exception) -> bool:
    """True for slow-model timeouts (retryable) as opposed to a down model."""
    kind = type(exc).__name__.lower()
    text = f"{kind} {exc}".lower()
    return "timeout" in kind or "timed out" in text or "timeout" in text


def parse_model_json(raw_text: str) -> dict[str, Any]:
    """Extract a JSON object from model output. Raises ValueError when broken."""
    text = (raw_text or "").strip()
    if not text:
        raise ValueError("empty model response")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("model response contains no JSON object")
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed model JSON: {exc}") from exc


def _finalize_finding(
    finding: AIFinding,
    evidence_by_id: dict[str, dict[str, Any]],
    verified_cves: set[str],
    scan_ids: set[str],
) -> tuple[AIFinding, list[str]]:
    val = validate_finding(finding, evidence_by_id, verified_cves, scan_ids)
    flags = check_finding(finding, evidence_by_id, verified_cves)
    problems = list(val.reasons) + [f for f in flags if f not in val.reasons]
    if not val.accepted:
        updated = finding.model_copy(update={
            "classification": "unknown", "verification_status": "rejected",
            "confidence": min(finding.confidence, 0.2)})
        return updated, problems
    if val.downgraded or flags:
        updated = finding.model_copy(update={
            "classification": "hypothesis" if finding.classification == "verified_finding"
                              else finding.classification,
            "verification_status": "unverified"})
        return updated, problems
    return finding, problems


def project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def generate_analysis(
    scan_id: str,
    scan_snapshot: dict[str, Any],
    generate_fn: Callable[[str, str], str],
    model: str = "qwen3:8b",
    max_chars: int = 8000,
    base: Optional[Path] = None,
    max_attempts: int = 2,
) -> AIAnalysis:
    """Run one analysis pass. Model failures are captured, never repaired.

    Malformed (e.g. truncated) model output is retried up to max_attempts
    times — each attempt is checkpointed separately. Model-call errors fail
    immediately so a down model never triggers repeated long waits.
    """
    root = base or project_root()
    evidence = list(scan_snapshot.get("evidence", []) or [])
    by_id = evidence_index(evidence)
    scan_ids = set(by_id)
    verified = set(verified_cve_set(scan_snapshot.get("verified_context")))
    context = build_context(scan_snapshot, max_chars=max_chars)
    system, user = build_finding_prompt(context)

    raw_dir = root / "data" / "raw" / "ai" / scan_id
    raw_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    raw_file = raw_dir / f"response_{stamp}.json"
    prompt_file = raw_dir / f"prompt_{stamp}.json"

    try:
        raw_text = generate_fn(system, user)
    except Exception as exc:
        if _is_timeout_error(exc):
            # Slow local model (not a down model): one retry with a halved
            # context. A smaller prompt processes much faster and usually
            # still carries the key evidence.
            try:
                small = max(2000, max_chars // 2)
                system, user = build_finding_prompt(
                    build_context(scan_snapshot, max_chars=small))
                raw_text = generate_fn(system, user)
            except Exception as exc2:
                analysis = AIAnalysis(scan_id=scan_id, model=model, findings=[],
                                      status="failed",
                                      error=f"model call failed: {exc} "
                                            f"(retry: {exc2})")
                raw_file.write_text(json.dumps(
                    {"scan_id": scan_id, "model": model,
                     "error": f"{exc} (retry: {exc2})",
                     "timestamp": stamp}, indent=2), encoding="utf-8")
                return analysis
        else:
            analysis = AIAnalysis(scan_id=scan_id, model=model, findings=[],
                                  status="failed", error=f"model call failed: {exc}")
            raw_file.write_text(json.dumps(
                {"scan_id": scan_id, "model": model, "error": str(exc),
                 "timestamp": stamp}, indent=2), encoding="utf-8")
            return analysis
    prompt_file.write_text(json.dumps(
        {"scan_id": scan_id, "model": model, "system": system, "user": user,
         "timestamp": stamp}, indent=2), encoding="utf-8")

    payload: dict[str, Any] = {}
    finding_list: list[AIFinding] = []
    rec_list: list[AIRecommendation] = []
    for attempt in range(1, max(1, max_attempts) + 1):
        attempt_file = raw_dir / f"response_{stamp}_attempt{attempt}.json"
        try:
            payload = parse_model_json(raw_text)
            finding_list, skipped_findings = _coerce_findings(payload.get("findings", []))
            rec_list, skipped_recs = _coerce_recommendations(payload.get("recommendations", []))
            if (not finding_list and not rec_list
                    and (skipped_findings + skipped_recs) > 0):
                raise ValueError(
                    f"no usable findings or recommendations "
                    f"(skipped {skipped_findings + skipped_recs} malformed entries)")
            break
        except Exception as exc:
            attempt_file.write_text(json.dumps(
                {"scan_id": scan_id, "model": model, "attempt": attempt,
                 "raw_response": raw_text,
                 "error": f"parse failed: {exc}", "timestamp": stamp}, indent=2),
                encoding="utf-8")
            if attempt >= max(1, max_attempts):
                raw_file.write_text(json.dumps(
                    {"scan_id": scan_id, "model": model, "raw_response": raw_text,
                     "error": f"parse failed after {attempt} attempts: {exc}",
                     "timestamp": stamp}, indent=2),
                    encoding="utf-8")
                return AIAnalysis(scan_id=scan_id, model=model, findings=[],
                                  status="failed", error=f"malformed model output: {exc}")
            try:
                raw_text = generate_fn(system, user)
            except Exception as exc:
                raw_file.write_text(json.dumps(
                    {"scan_id": scan_id, "model": model, "raw_response": raw_text,
                     "error": f"model call failed: {exc}", "timestamp": stamp}, indent=2),
                    encoding="utf-8")
                return AIAnalysis(scan_id=scan_id, model=model, findings=[],
                                  status="failed", error=f"model call failed: {exc}")
    try:
        draft = AIAnalysis(scan_id=scan_id, model=model,
                           findings=finding_list,
                           recommendations=rec_list,
                           executive_summary=str(payload.get("executive_summary", "") or ""))
    except Exception as exc:
        raw_file.write_text(json.dumps(
            {"scan_id": scan_id, "model": model, "raw_response": raw_text,
             "error": f"parse failed: {exc}", "timestamp": stamp}, indent=2),
            encoding="utf-8")
        return AIAnalysis(scan_id=scan_id, model=model, findings=[],
                          status="failed", error=f"malformed model output: {exc}")

    final_findings: list[AIFinding] = []
    for finding in draft.findings:
        updated, _ = _finalize_finding(finding, by_id, verified, scan_ids)
        final_findings.append(updated)
    for rec in draft.recommendations:
        missing = [e for e in rec.evidence_ids if e not in by_id]
        if missing:
            rec.evidence_ids = [e for e in rec.evidence_ids if e in by_id]
    analysis = AIAnalysis(scan_id=scan_id, model=model, findings=final_findings,
                          recommendations=draft.recommendations,
                          executive_summary=str(draft.executive_summary or ""),
                          status="completed")
    raw_file.write_text(json.dumps(
        {"scan_id": scan_id, "model": model, "raw_response": raw_text,
         "timestamp": stamp}, indent=2), encoding="utf-8")
    out_file = root / "data" / "processed" / "ai_analysis.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(analysis.model_dump_json(indent=2), encoding="utf-8")
    return analysis


def build_attack_paths(
    attack_path_payloads: list[dict[str, Any]],
    evidence_by_id: dict[str, dict[str, Any]],
) -> list[AIAttackPath]:
    """Parse attack-path drafts; exploit content is rejected, never executed."""
    from backend.app.validation.hallucination_guard import (
        _EXPLOIT_TOKENS,
        _PAYLOAD_PATH_TOKENS,
    )

    out: list[AIAttackPath] = []
    for payload in attack_path_payloads:
        path = AIAttackPath(**payload)
        step_text = " ".join(
            [path.title]
            + [s.hypothesis for s in path.steps]
            + [s.required_verification for s in path.steps]
            + [s.observed_condition for s in path.steps]).lower()
        if any(token in step_text for token in _EXPLOIT_TOKENS):
            continue
        if any(token in step_text for token in _PAYLOAD_PATH_TOKENS):
            continue
        if any(e not in evidence_by_id for e in path.evidence_ids):
            continue
        out.append(path.model_copy(update={"status": "hypothesis"}))
    return out


def default_config() -> LLMConfig:
    from backend.app.ai.ollama_client import load_llm_config

    return load_llm_config()
