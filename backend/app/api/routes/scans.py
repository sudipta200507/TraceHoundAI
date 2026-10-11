"""Scan lifecycle API (Phase 11) — scope-gated, background execution.

POST /api/scans normalizes + validates the target and checks policy BEFORE
creating a job; out-of-scope targets get HTTP 4xx and never start anything.
Execution runs on the process-local FIFO worker; responses return immediately.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

from backend.app.api.schemas.scan import (
    PreflightResponse,
    ScanCreateRequest,
    ScanFindingsResponse,
    ScanReportResponse,
    ScanResponse,
    ScanStagesResponse,
    ScanStatusResponse,
    FindingResponse,
    ScanSummaryResponse,
    StageCountResponse,
    StageStatusResponse,
)
from backend.app.orchestrator.job_manager import JobManager
from backend.app.orchestrator.pipeline import preflight_check, project_root
from backend.app.recon.reachability import probe_target_reachability
from backend.app.safety.execution_policy import (
    ActiveScanAuthorization,
    lab_active_scan_policy,
)
from backend.app.safety.scope_validator import (
    ScanScope,
    create_scan_scope,
    normalize_target,
    validate_target,
)

router = APIRouter(prefix="/api/scans", tags=["scans"])

job_manager = JobManager()

_ACTIVE_POLICY_CACHE: dict[str, object] = {}
_REACHABILITY_CACHE: dict[str, dict] = {}


def _active_policy_for(scan_id: str, approved_by: str, reason: str):
    from backend.app.safety.scope_validator import ScopePolicy
    if not approved_by.strip():
        return None
    authorization = ActiveScanAuthorization(
        scan_id=scan_id, approved_by=approved_by.strip(),
        reason=reason.strip() or "lab scan via API")
    return lab_active_scan_policy(authorization)


def _job_status(scan_id: str) -> ScanStatusResponse:
    job = job_manager.get_job(scan_id)
    if job is None:
        # Post-restart fallback: rebuild read-only status from disk artifacts.
        root = project_root()
        sdir = root / "data" / "processed" / scan_id
        if not sdir.exists():
            raise HTTPException(status_code=404, detail="unknown scan_id")
        try:
            scope_data = json.loads((sdir / "scope.json").read_text(encoding="utf-8"))
        except Exception:
            scope_data = {}
        report_done = (root / "reports" / "generated" / scan_id
                       / "final_report.md").exists()
        disk_stages = _disk_stage_results(sdir)
        return ScanStatusResponse(
            scan_id=scan_id, target=str(scope_data.get("target", "")),
            status="completed" if report_done else "unknown",
            scan_mode="unknown", execution_enabled=False,
            stages=[StageStatusResponse(
                stage=r.stage, name=r.name, status=r.status,
                started_at=r.started_at, completed_at=r.completed_at,
                duration_ms=r.duration_ms, error=r.error) for r in disk_stages],
            report_path=str(root / "reports" / "generated" / scan_id
                            / "final_report.md") if report_done else "")
    return ScanStatusResponse(
        scan_id=job.scan_id, target=job.target, status=job.status,
        scan_mode=job.scan_mode,
        execution_enabled=(job.scan_mode == "authorized"),
        reachability=_REACHABILITY_CACHE.get(job.scan_id, {}),
        current_stage=job.current_stage, started_at=job.started_at,
        completed_at=job.completed_at,
        stages=[StageStatusResponse(stage=r.stage_id, name=r.name, status=r.status,
                                    started_at=r.started_at, completed_at=r.completed_at,
                                    duration_ms=r.duration_ms, error=r.error)
                for r in job.stage_results],
        error=job.error, report_path=job.report_path)


@router.post("", response_model=ScanResponse, status_code=202)
def create_scan(payload: ScanCreateRequest):
    # Normalize first so malformed/injection input is rejected before anything else.
    try:
        normalize_target(payload.target)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"invalid target: {exc}")
    # Ephemeral per-scan scope: the requested root domain becomes this scan's
    # boundary. scope.yaml is never edited and never mutated at runtime.
    try:
        pending_scope = create_scan_scope(payload.target, "pending")
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"out of scope: {exc}")
    decision = validate_target(payload.target, pending_scope.to_scope_config())
    if not decision.allowed:
        raise HTTPException(status_code=422, detail=f"out of scope: {decision.reason}")
    try:
        job = job_manager.create_job(
            decision.target, payload.scan_id,
            scan_mode=("authorized" if payload.authorize_active else "passive"))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    scan_scope = pending_scope.model_copy(update={"scan_id": job.scan_id})
    # Pre-scan reachability diagnostics: real DNS + HTTP probes against the
    # authorized root, published to the user so nothing fails silently.
    reachability = probe_target_reachability(decision.target, scan_scope.to_scope_config())
    _REACHABILITY_CACHE[job.scan_id] = reachability
    policy = None
    if payload.authorize_active:
        try:
            policy = _active_policy_for(job.scan_id, payload.approved_by, payload.reason)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if policy is None:
            raise HTTPException(
                status_code=422,
                detail="active stages require approved_by (no silent elevation)")
        _ACTIVE_POLICY_CACHE[job.scan_id] = policy
    try:
        job_manager.submit(job.scan_id, {"active_policy": policy,
                                         "scan_scope": scan_scope.model_dump(mode="json"),
                                         "active_approval": (
                                             {"approved_by": payload.approved_by.strip(),
                                              "reason": (payload.reason.strip()
                                                         or "lab scan via API")}
                                             if policy is not None else None)})
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return ScanResponse(scan_id=job.scan_id, target=job.target, status=job.status,
                        root_domain=scan_scope.root_domain,
                        reachability=reachability,
                        scope=scan_scope.describe())


@router.get("/{scan_id}", response_model=ScanStatusResponse)
def scan_status(scan_id: str):
    return _job_status(scan_id)


@router.get("/{scan_id}/stages", response_model=ScanStagesResponse)
def scan_stages(scan_id: str):
    status = _job_status(scan_id)
    return ScanStagesResponse(scan_id=status.scan_id, stages=status.stages)


@router.get("/{scan_id}/findings", response_model=ScanFindingsResponse)
def scan_findings(scan_id: str):
    root = project_root()
    findings: list[dict] = []
    for candidate in (root / "data" / "processed" / scan_id / "ai_analysis.json",
                      root / "data" / "processed" / "ai_analysis.json"):
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict) and data.get("scan_id", scan_id) == scan_id:
            findings = data.get("findings", []) or []
            break
    else:
        # No job and no artifacts: unknown scan only when nothing exists at all.
        if job_manager.get_job(scan_id) is None and not findings:
            raise HTTPException(status_code=404, detail="unknown scan_id")
    # Only gate-accepted findings are exposed: the validation stage may have
    # rejected model claims citing nonexistent evidence.
    validation = _read_validation(scan_id)
    accepted = {r.get("finding_id") for r in (validation.get("results") or [])
                if r.get("accepted") is not False}
    if validation.get("results"):
        findings = [f for f in findings
                    if f.get("finding_id") in accepted]
    return ScanFindingsResponse(
        scan_id=scan_id,
        findings=[FindingResponse(
            finding_id=str(f.get("finding_id", "")), title=str(f.get("title", "")),
            severity=str(f.get("severity", "")), confidence=float(f.get("confidence", 0.0)),
            classification=str(f.get("classification", "")),
            evidence_ids=[str(e) for e in (f.get("evidence_ids", []) or [])],
            verification_status=str(f.get("verification_status", "")))
            for f in findings if f.get("finding_id")])


@router.get("/{scan_id}/report", response_model=ScanReportResponse)
def scan_report(scan_id: str):
    root = project_root()
    path = root / "reports" / "generated" / scan_id / "final_report.md"
    if not path.exists():
        if job_manager.get_job(scan_id) is None:
            raise HTTPException(status_code=404, detail="unknown scan_id")
        raise HTTPException(status_code=409, detail="report not available (validation may have failed)")
    pdf_path = root / "reports" / "generated" / scan_id / "final_report.pdf"
    return ScanReportResponse(scan_id=scan_id, report_path=str(path),
                              markdown=path.read_text(encoding="utf-8"),
                              pdf_path=str(pdf_path) if pdf_path.exists() else "",
                              pdf_available=pdf_path.exists())


@router.post("/{scan_id}/cancel", response_model=ScanStatusResponse)
def cancel_scan(scan_id: str):
    job = job_manager.request_cancel(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown scan_id")
    _ACTIVE_POLICY_CACHE.pop(scan_id, None)
    return _job_status(scan_id)


@router.post("/{scan_id}/resume", response_model=ScanStatusResponse)
def resume_scan(scan_id: str, payload: dict | None = Body(default=None)):
    """Resume from the last valid checkpoint. Scope is reloaded from disk and
    must match; completed stages are not repeated. Active stages reuse the
    scan's original explicit authorization — never elevated silently. After
    a backend restart the approval may be re-supplied explicitly in the body
    as {"approved_by": ..., "reason": ...}."""
    import json as _json

    payload = payload or {}
    job = job_manager.get_job(scan_id)
    if job is None:
        # Post-restart recovery: re-register from persisted scope.json so a
        # finished backend process never orphans a resumable scan on disk.
        try:
            scope_data = _json.loads(
                (project_root() / "data" / "processed" / scan_id
                 / "scope.json").read_text(encoding="utf-8"))
            target = str(scope_data.get("target", ""))
        except Exception:
            raise HTTPException(status_code=404, detail="unknown scan_id")
        if not target:
            raise HTTPException(status_code=404, detail="unknown scan_id")
        try:
            job = job_manager.create_job(target, scan_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
    if job.status == "completed":
        raise HTTPException(status_code=409, detail="scan already completed")
    if job.status not in ("failed", "cancelled", "queued"):
        raise HTTPException(status_code=409,
                            detail=f"scan is {job.status}; only failed/cancelled scans resume")
    stored_approval = None
    try:
        stored = _json.loads(
            (project_root() / "data" / "processed" / scan_id
             / "scope.json").read_text(encoding="utf-8")).get("active_approval")
        if isinstance(stored, dict) and stored.get("approved_by"):
            stored_approval = {"approved_by": str(stored["approved_by"]),
                               "reason": str(stored.get("reason", ""))}
    except Exception:
        stored_approval = None
    approval = stored_approval
    if approval is None and str(payload.get("approved_by", "")).strip():
        approval = {"approved_by": str(payload["approved_by"]).strip(),
                    "reason": str(payload.get("reason", "")).strip()
                    or "re-authorized at resume"}
    policy = None
    if approval is not None:
        try:
            policy = _active_policy_for(scan_id, approval["approved_by"],
                                        approval["reason"])
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    job.status = "queued"
    job.cancel_requested = False
    job.error = ""
    try:
        job_manager.submit(job.scan_id, {"active_policy": policy,
                                         "active_approval": approval,
                                         "resume": True})
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _job_status(scan_id)


@router.post("/preflight", response_model=PreflightResponse)
def preflight(payload: ScanCreateRequest):
    try:
        normalized = normalize_target(payload.target)
        target = normalized.host
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"invalid target: {exc}")
    check = preflight_check(target)
    return PreflightResponse(
        target=check["target"], scope_allowed=check["scope_allowed"],
        scope_reason=check["scope_reason"],
        effective_scope=check.get("effective_scope", {}) or {},
        missing_required_tools=check["missing_required_tools"],
        policy=check["policy"], model_available=check["model_available"],
        directories_ok=check["directories_ok"], ready=check["ready"])


@router.get("/{scan_id}/report.md", response_class=PlainTextResponse)
def scan_report_markdown(scan_id: str):
    return scan_report(scan_id).markdown


@router.get("/{scan_id}/report.pdf")
def scan_report_pdf(scan_id: str):
    path = project_root() / "reports" / "generated" / scan_id / "final_report.pdf"
    if not path.exists():
        if job_manager.get_job(scan_id) is None:
            raise HTTPException(status_code=404, detail="unknown scan_id")
        raise HTTPException(status_code=409, detail="PDF report not available")
    return FileResponse(str(path), media_type="application/pdf",
                        filename=f"{scan_id}-report.pdf")


def _generated_file(scan_id: str, filename: str, media_type: str):
    path = project_root() / "reports" / "generated" / scan_id / filename
    if not path.exists():
        if job_manager.get_job(scan_id) is None:
            raise HTTPException(status_code=404, detail="unknown scan_id")
        raise HTTPException(status_code=409, detail=f"{filename} not available")
    return FileResponse(str(path), media_type=media_type,
                        filename=f"{scanId_to_filename(scan_id)}-{filename}")


def scanId_to_filename(scan_id: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_", ".") else "_"
                   for c in scan_id) or "scan"


@router.get("/{scan_id}/appendix.md", response_class=PlainTextResponse)
def scan_report_appendix(scan_id: str):
    root = project_root()
    path = root / "reports" / "generated" / scan_id / "technical_appendix.md"
    if not path.exists():
        if job_manager.get_job(scan_id) is None:
            raise HTTPException(status_code=404, detail="unknown scan_id")
        raise HTTPException(status_code=409, detail="appendix not available")
    return path.read_text(encoding="utf-8")


@router.get("/{scan_id}/appendix.md/download")
def scan_report_appendix_download(scan_id: str):
    return _generated_file(scan_id, "technical_appendix.md", "text/markdown")


@router.get("/{scan_id}/inventory.json")
def scan_inventory_json(scan_id: str):
    return _generated_file(scan_id, "inventory.json", "application/json")


@router.get("/{scan_id}/inventory.csv")
def scan_inventory_csv(scan_id: str):
    return _generated_file(scan_id, "endpoints.csv", "text/csv")


def _read_validation(scan_id: str) -> dict:
    """Load this scan's ai_validation.json when it exists ({} otherwise)."""
    path = project_root() / "data" / "processed" / scan_id / "ai_validation.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _count_file_json(path: Path, key: str) -> int:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    return len(data.get(key, []) or []) if isinstance(data, dict) else 0


def _count_jsonl(path: Path) -> int:
    try:
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    except Exception:
        return 0


def _disk_stage_results(sdir: Path) -> list:
    """Rebuild stage results from checkpoint files (post-restart fallback)."""
    from backend.app.orchestrator.stages import STAGES

    results = []
    for definition in STAGES:
        try:
            data = json.loads(
                (sdir / "checkpoints" / f"{definition.stage_id}.json").read_text(
                    encoding="utf-8"))
        except Exception:
            continue
        results.append(StageStatusResponse(
            stage=definition.stage_id, name=definition.name,
            status=str(data.get("status", "unknown")),
            started_at=str(data.get("started_at", "")),
            completed_at=str(data.get("completed_at", "")),
            duration_ms=0.0, error=str(data.get("error", ""))))
    return results


@router.get("/{scan_id}/summary", response_model=ScanSummaryResponse)
def scan_summary(scan_id: str):
    """Real per-stage counts from this scan's processed outputs. Never estimated.

    Falls back to on-disk artifacts when the job registry is empty (e.g.
    after a backend restart): statuses come from stage checkpoints.
    """
    job = job_manager.get_job(scan_id)
    root = project_root()
    sdir = root / "data" / "processed" / scan_id
    if job is None and not sdir.exists():
        raise HTTPException(status_code=404, detail="unknown scan_id")

    def _load(name: str) -> dict:
        try:
            data = json.loads((sdir / name).read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    assets = _load("asset_list.json").get("assets", []) or []
    live = _load("live_hosts.json").get("hosts", []) or []
    ports_data = _load("port_service_data.json").get("hosts", []) or []
    finger = _load("fingerprint_data.json").get("hosts", []) or []
    endpoints = _load("endpoint_data.json").get("hosts", []) or []
    shots = _load("screenshot_data.json").get("screenshots", []) or []
    verified = _load("verified_context.json").get("findings", []) or []
    analysis = _load("ai_analysis.json")
    n_ports = sum(len(h.get("ports", []) or []) for h in ports_data)
    n_services = sum(1 for h in ports_data for p in (h.get("ports", []) or [])
                     if p.get("service"))
    n_tech = sum(len(h.get("technologies", []) or []) for h in finger)
    n_endpoints = sum(len(h.get("endpoints", []) or []) for h in endpoints)
    n_shots = sum(1 for s in shots if s.get("status") == "captured")
    nuclei_lines = 0
    for candidate in (root / "data" / "raw" / "nuclei" / scan_id / "nuclei.jsonl",):
        if candidate.exists():
            nuclei_lines = _count_jsonl(candidate)

    by_file = {
        "asset_discovery": (len(assets), 0),
        "live_discovery": (len(assets), len(live)),
        "port_service": (len(live), n_ports),
        "fingerprinting": (len(live), n_tech),
        "endpoint_discovery": (len(live), n_endpoints),
        "screenshot_capture": (len(live), n_shots),
        "vulnerability_verification": (len(live), nuclei_lines),
        "security_enrichment": (nuclei_lines, len(verified)),
        "ai_analysis": (len(verified), len(analysis.get("findings", []) or [])),
        "report_generation": (len(analysis.get("findings", []) or []),
                              1 if (root / "reports" / "generated" / scan_id
                                    / "final_report.md").exists() else 0),
    }
    stages = []
    results = job.stage_results if job is not None else _disk_stage_results(sdir)
    for result in results:
        sid = getattr(result, "stage_id", None) or result.stage
        inputs, outputs = by_file.get(sid, (0, 0))
        output_file = ""
        try:
            import json as _json
            checkpoint = _json.loads(
                (sdir / "checkpoints" / f"{sid}.json").read_text(
                    encoding="utf-8"))
            files = checkpoint.get("output_files", []) or []
            output_file = files[0] if files else ""
        except Exception:
            output_file = ""
        stages.append(StageCountResponse(
            stage=sid, name=result.name, status=result.status,
            inputs=inputs, outputs=outputs, output_file=output_file,
            error=result.error))
    if job is not None:
        target = job.target
        status = job.status
        scan_mode = job.scan_mode
    else:
        scope_data = _load("scope.json")
        target = str(scope_data.get("target", ""))
        report_done = (root / "reports" / "generated" / scan_id
                       / "final_report.md").exists()
        status = "completed" if report_done else "unknown"
        scan_mode = "authorized" if report_done else "unknown"
    return ScanSummaryResponse(
        scan_id=scan_id, target=target, status=status,
        scan_mode=scan_mode, execution_enabled=(scan_mode == "authorized"),
        assets=len(assets), live_hosts=len(live), open_ports=n_ports,
        services=n_services, technologies=n_tech, endpoints=n_endpoints,
        screenshots=n_shots, vulnerability_observations=nuclei_lines,
        cves_enriched=len(verified),
        ai_findings=len(analysis.get("findings", []) or []), stages=stages)
