"""End-to-end pipeline (Phase 11) — coordinates existing stages, adds nothing new.

Deterministic order: scope -> asset -> live -> ports -> fingerprint ->
endpoints -> screenshots -> nuclei -> enrichment-record -> AI -> validation
-> report. Later stages never run before valid dependencies. Active stages
(ports, nuclei) execute only with an explicit lab policy; by default they
are marked blocked without invoking any subprocess. One shared
EvidenceIdGenerator keeps IDs unique across the whole scan.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from backend.app.core.logger import get_logger, stage_log
from backend.app.evidence.evidence_id import EvidenceIdGenerator
from backend.app.orchestrator.checkpoint import (
    Checkpoint,
    checkpoint_valid,
    now_iso,
    write_checkpoint,
)
from backend.app.orchestrator.stages import STAGE_IDS, STAGES, StageResult
from backend.app.reporting.report_builder import build_report_context
from backend.app.safety.scope_validator import (
    ScanScope,
    ScopeConfig,
    create_scan_scope,
    load_scope_config,
    validate_target,
)

log = get_logger("tracehound.pipeline")

PROCESSED_FILES = {
    "asset_discovery": "asset_list.json",
    "live_discovery": "live_hosts.json",
    "port_service": "port_service_data.json",
    "fingerprinting": "fingerprint_data.json",
    "endpoint_discovery": "endpoint_data.json",
    "screenshot_capture": "screenshot_data.json",
    "vulnerability_verification": "verified_context.json",
    "ai_analysis": "ai_analysis.json",
}


class PipelineResult(BaseModel):
    scan_id: str
    target: str
    status: str = "failed"
    stages: list[StageResult] = Field(default_factory=list)
    findings_count: int = 0
    asset_count: int = 0
    live_host_count: int = 0
    port_count: int = 0
    endpoint_count: int = 0
    vulnerability_count: int = 0
    report_path: str = ""
    error: str = ""


# Stages that only need live_hosts.json and never consume each other's
# outputs. They run concurrently in threads (subprocess-bound, GIL-free)
# once live_discovery completes — the middle of the scan, previously the
# longest strictly-serial stretch. Recording stays in STAGES order, so
# checkpoints, progress events and results are deterministic.
PARALLEL_GROUP = ("port_service", "fingerprinting", "endpoint_discovery",
                  "screenshot_capture", "vulnerability_verification")

MAX_PARALLEL_WORKERS = 4

# Stages that run even when a dependency did not complete: the report is
# evidence-based, and AI validation degrades to "no AI findings" when the
# model is slow or down — instead of blocking the whole scan.
TOLERANT_STAGES = frozenset({"report_generation", "ai_validation"})


def project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def scan_dir(scan_id: str, base: Optional[Path] = None) -> Path:
    d = (base or project_root()) / "data" / "processed" / scan_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _read_json(path: Path) -> Optional[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _canonical(base: Path, name: str) -> Path:
    return base / "data" / "processed" / name


def _stage_input(scan_id: str, base: Path, name: str) -> Path | dict[str, Any]:
    """Per-scan copy wins (isolation + resume); else canonical path."""
    per_scan = base / "data" / "processed" / scan_id / name
    if per_scan.exists():
        return per_scan
    return _canonical(base, name)


def _snapshot_copy(scan_id: str, base: Path, name: str) -> str:
    src = _canonical(base, name)
    if not src.exists():
        return ""
    dest = base / "data" / "processed" / scan_id / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)
    return str(dest)


def _load_union(scan_id: str, base: Path) -> list[dict[str, Any]]:
    data = _read_json(base / "data" / "processed" / scan_id / "evidence.json")
    if isinstance(data, list):
        return data
    return []


def _evidence_sort_key(item: dict[str, Any]) -> int:
    try:
        return int(str(item.get("id", "") or "E0")[1:] or 0)
    except (TypeError, ValueError):
        return 0


def _save_union(scan_id: str, base: Path, union: list[dict[str, Any]]) -> str:
    path = base / "data" / "processed" / scan_id / "evidence.json"
    # ID-ordered on every save: parallel stages issue IDs in completion
    # order, but the persisted union stays deterministic for readers.
    ordered = sorted(union, key=_evidence_sort_key)
    path.write_text(json.dumps(ordered, indent=2), encoding="utf-8")
    return str(path)


def _load_scan_scope(scan_id: str, base: Path) -> Optional[ScanScope]:
    """Reload the persisted per-scan scope; None when absent or legacy."""
    data = _read_json(base / "data" / "processed" / scan_id / "scope.json")
    if not isinstance(data, dict) or not data.get("root_domain"):
        return None
    try:
        return ScanScope(
            scan_id=str(data.get("scan_id", scan_id)),
            root_domain=str(data["root_domain"]),
            created_at=str(data.get("created_at", "")),
            policy=data.get("policy", {}) if isinstance(data.get("policy"), dict) else {},
            allowed_ips=data.get("allowed_ips", []) or [],
            allowed_cidrs=data.get("allowed_cidrs", []) or [],
            active_approval=(dict(data["active_approval"])
                             if isinstance(data.get("active_approval"), dict) else None),
        )
    except Exception:
        return None


def _resume_start(union: list[dict[str, Any]]) -> int:
    numbers = []
    for item in union:
        eid = str(item.get("id", "") or "")
        if eid.startswith("E") and eid[1:].isdigit():
            numbers.append(int(eid[1:]))
    return max(numbers, default=0) + 1


def _active_allowed(policy: Optional[Any]) -> bool:
    if policy is None:
        return False
    return bool(not policy.dry_run and policy.allow_active_scanning)


def run_pipeline(
    scan_id: str,
    target: str,
    config: Optional[ScopeConfig] = None,
    active_policy: Any = None,
    base: Optional[Path] = None,
    runners: Optional[dict[str, Any]] = None,
    ai_generate_fn: Optional[Callable[[str, str], str]] = None,
    resume: bool = False,
    should_stop: Optional[Callable[[], bool]] = None,
    scan_scope: Optional[Any] = None,
    on_stage: Optional[Callable[[Any], None]] = None,
    active_approval: Optional[dict[str, str]] = None,
) -> PipelineResult:
    """Execute the full controlled pipeline. All external calls injectable.

    Scope resolution (never silently changed):
    - an explicit ScanScope (or its dict form) wins and is verified by id;
    - else an explicit legacy ScopeConfig is honored (tests/back-compat);
    - else a ScanScope is derived from the requested target (normal path).

    on_stage, when given, receives each StageResult as it completes so the
    job manager can publish live progress.
    """
    runners = runners or {}
    root = base or project_root()
    if scan_scope is not None:
        scope_obj = scan_scope if isinstance(scan_scope, ScanScope) else ScanScope(**scan_scope)
        if scope_obj.scan_id != scan_id:
            raise ValueError(
                f"scan scope belongs to {scope_obj.scan_id}, not {scan_id}")
        cfg = scope_obj.to_scope_config()
    elif config is not None:
        cfg = config
        scope_obj = None
    else:
        scope_obj = create_scan_scope(target, scan_id)
        cfg = scope_obj.to_scope_config()
    sdir = scan_dir(scan_id, root)
    union: list[dict[str, Any]] = _load_union(scan_id, root) if resume else []
    gen = EvidenceIdGenerator(start=_resume_start(union) if resume and union else 1)
    results: list[StageResult] = []
    errors: list[str] = []
    stopped = False
    # Parallel stages share the union list and the ID generator — both are
    # guarded (generator has its own lock; union extend+save takes this one).
    state_lock = threading.Lock()

    def _record(stage_id: str, name: str, status: str, started: str,
                outputs: Optional[list[str]] = None, error: str = "",
                t0: float = 0.0) -> StageResult:
        completed = now_iso()
        result = StageResult(
            stage_id=stage_id, name=name, status=status, started_at=started,
            completed_at=completed, duration_ms=(time.perf_counter() - t0) * 1000.0,
            outputs=outputs or [], error=error)
        write_checkpoint(Checkpoint(
            scan_id=scan_id, stage=stage_id, status=status, started_at=started,
            completed_at=completed, output_files=outputs or [], error=error), root)
        results.append(result)
        stage_log(log, scan_id, stage_id, status, result.duration_ms)
        if on_stage is not None:
            try:
                on_stage(result)
            except Exception:
                pass
        return result

    def _skip_remaining(from_index: int, reason: str) -> None:
        for definition in STAGES[from_index:]:
            _record(definition.stage_id, definition.name, "skipped",
                    now_iso(), [], reason, time.perf_counter())

    # -- stage 1: scope ----------------------------------------------------
    # On resume the persisted scope is reloaded and must match exactly —
    # the scope is never silently changed mid-scan.
    t0, started = time.perf_counter(), now_iso()
    if resume:
        persisted = _load_scan_scope(scan_id, root)
        if persisted is not None:
            if scope_obj is not None and persisted.root_domain != scope_obj.root_domain:
                reason = (f"scope changed during resume: {persisted.root_domain} "
                          f"!= {scope_obj.root_domain}")
                _record("scope_validation", "Scope validation", "failed",
                        started, [], reason, t0)
                return PipelineResult(scan_id=scan_id, target=target, status="failed",
                                      stages=results, error=reason)
            scope_obj = persisted
            cfg = scope_obj.to_scope_config()
    decision = validate_target(target, cfg)
    if not decision.allowed:
        _record("scope_validation", "Scope validation", "failed",
                started, [], decision.reason, t0)
        return PipelineResult(scan_id=scan_id, target=target, status="failed",
                              stages=results, error=decision.reason)
    scope_file = sdir / "scope.json"
    if scope_obj is not None:
        payload = scope_obj.model_dump(mode="json")
    else:
        payload = {"scan_id": scan_id, "root_domain": None,
                   "allowed_root_domains": []}
    payload.update({"target": decision.target,
                    "matched_rule": decision.matched_rule})
    if active_approval:
        payload["active_approval"] = dict(active_approval)
    scope_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _record("scope_validation", "Scope validation", "completed",
            started, [str(scope_file)], t0=t0)
    normalized_target = decision.target

    # -- helpers ------------------------------------------------------------
    def _resume_ok(stage_id: str) -> bool:
        return resume and checkpoint_valid(scan_id, stage_id, root)

    def _extend_union(evidence: list[Any]) -> None:
        with state_lock:
            for item in evidence:
                union.append(item.model_dump(mode="json")
                             if hasattr(item, "model_dump") else dict(item))
            union.sort(key=_evidence_sort_key)
            _save_union(scan_id, root, union)

    def _invoke(definition) -> tuple[str, list[str], str]:
        """Run one stage in a worker thread. Returns (status, outputs, error)."""
        try:
            outputs = _run_stage(
                definition.stage_id, scan_id, normalized_target, cfg, active_policy,
                root, sdir, runners, ai_generate_fn, gen, union, _extend_union,
                _stage_input, _snapshot_copy)
            return ("completed", outputs, "")
        except _BlockedStage as exc:
            return ("blocked", [], str(exc))
        except Exception as exc:
            return ("failed", [], str(exc)[:1000])

    def _record_outcome(definition, status: str, outputs: list[str],
                        error: str, t0: float, started: str) -> None:
        if status == "completed":
            _record(definition.stage_id, definition.name, status, started,
                    outputs, t0=t0)
        elif status == "blocked":
            _record(definition.stage_id, definition.name, status, started,
                    [], error, t0)
        else:
            _record(definition.stage_id, definition.name, status, started,
                    [], error, t0)
            errors.append(f"{definition.stage_id}: {error}")

    def _dep_blocker(definition) -> str:
        dep_status = {r.stage_id: r.status for r in results}
        missing = [d for d in definition.depends_on
                   if dep_status.get(d) not in ("completed", "skipped")]
        if missing and definition.stage_id not in TOLERANT_STAGES:
            return f"missing dependencies: {missing}"
        return ""

    # -- stages 2..12 --------------------------------------------------------
    idx = 1
    while idx < len(STAGES):
        definition = STAGES[idx]
        stage_id = definition.stage_id
        if stage_id in PARALLEL_GROUP:
            # Collect the contiguous parallel group, then run it together.
            group: list[tuple[int, Any]] = []
            while idx < len(STAGES) and STAGES[idx].stage_id in PARALLEL_GROUP:
                group.append((idx, STAGES[idx]))
                idx += 1
            if should_stop is not None and should_stop():
                stopped = True
                _skip_remaining(group[0][0], "cancelled by operator")
                break
            pending: list[tuple[Any, float, str]] = []
            for _, item in group:
                t0, started = time.perf_counter(), now_iso()
                if _resume_ok(item.stage_id):
                    _record(item.stage_id, item.name, "completed", started,
                            [str(sdir / PROCESSED_FILES[item.stage_id])]
                            if item.stage_id in PROCESSED_FILES else [], t0=t0)
                    continue
                blocker = _dep_blocker(item)
                if blocker:
                    _record(item.stage_id, item.name, "blocked", started,
                            [], blocker, t0)
                    continue
                pending.append((item, t0, started))
            if pending:
                outcomes: dict[str, tuple[str, list[str], str]] = {}
                workers = min(len(pending), MAX_PARALLEL_WORKERS)
                with ThreadPoolExecutor(max_workers=workers,
                                        thread_name_prefix="tracehound-stage") as pool:
                    future_map = {pool.submit(_invoke, item): (item, t0, started)
                                  for item, t0, started in pending}
                    for future in as_completed(future_map):
                        item, _, _ = future_map[future]
                        outcomes[item.stage_id] = future.result()
                for item, t0, started in pending:
                    status, outputs, error = outcomes[item.stage_id]
                    _record_outcome(item, status, outputs, error, t0, started)
            continue
        if should_stop is not None and should_stop():
            stopped = True
            _skip_remaining(idx, "cancelled by operator")
            break
        t0, started = time.perf_counter(), now_iso()
        if _resume_ok(stage_id):
            _record(stage_id, definition.name, "completed", started,
                    [str(sdir / PROCESSED_FILES[stage_id])]
                    if stage_id in PROCESSED_FILES else [], t0=t0)
            idx += 1
            continue
        # Dependency gate: every depends_on must be completed (or skipped
        # only when the stage tolerates it — report tolerates missing AI).
        blocker = _dep_blocker(definition)
        if blocker:
            _record(stage_id, definition.name, "blocked", started, [],
                    blocker, t0)
            idx += 1
            continue
        try:
            outputs = _run_stage(
                stage_id, scan_id, normalized_target, cfg, active_policy,
                root, sdir, runners, ai_generate_fn, gen, union, _extend_union,
                _stage_input, _snapshot_copy)
            _record(stage_id, definition.name, "completed", started, outputs, t0=t0)
        except _BlockedStage as exc:
            _record(stage_id, definition.name, "blocked", started, [], str(exc), t0)
        except Exception as exc:
            _record(stage_id, definition.name, "failed", started, [], str(exc)[:1000], t0)
            errors.append(f"{stage_id}: {exc}")
        idx += 1

    by_id = {r.stage_id: r.status for r in results}
    if stopped:
        status = "cancelled"
    elif by_id.get("scope_validation") != "completed":
        status = "failed"
    elif by_id.get("asset_discovery") != "completed":
        status = "failed"
    elif by_id.get("report_generation") != "completed":
        status = "failed"
    else:
        status = "completed"
    report_path = str(root / "reports" / "generated" / scan_id / "final_report.md")
    if by_id.get("report_generation") != "completed":
        report_path = ""
    counts = _count_results(scan_id, root)
    return PipelineResult(
        scan_id=scan_id, target=normalized_target, status=status, stages=results,
        findings_count=counts["findings"], asset_count=counts["assets"],
        live_host_count=counts["live_hosts"], port_count=counts["ports"],
        endpoint_count=counts["endpoints"],
        vulnerability_count=counts["vulnerabilities"],
        report_path=report_path, error="; ".join(errors)[:2000])


class _BlockedStage(Exception):
    pass


def _run_stage(stage_id: str, scan_id: str, target: str, cfg: ScopeConfig,
               active_policy: Any, root: Path, sdir: Path,
               runners: dict[str, Any], ai_generate_fn: Any,
               gen: EvidenceIdGenerator, union: list[dict[str, Any]],
               extend_union: Callable[[list[Any]], None],
               stage_input: Callable, snapshot_copy: Callable) -> list[str]:
    """Execute one stage with existing implementations. Raises on failure."""
    if stage_id == "asset_discovery":
        from backend.app.recon.subdomain.aggregator import run_discovery
        result = run_discovery(
            target, scan_id, cfg,
            subfinder_runner=runners.get("subfinder_runner"),
            **({"crtsh_fetcher": runners["crtsh_fetcher"]} if runners.get("crtsh_fetcher") else {}),
            base=root, generator=gen)
        extend_union(result.evidence)
        return [snapshot_copy(scan_id, root, "asset_list.json")] + \
            [str(root / "data" / "raw" / "subdomain" / scan_id / f)
             for f in ("subfinder.json", "crtsh.json")]

    if stage_id == "live_discovery":
        from backend.app.recon.discovery.live_hosts import run_live_discovery
        result = run_live_discovery(
            scan_id, stage_input(scan_id, root, "asset_list.json"), cfg,
            dns_runner=runners.get("dns_runner"),
            httpx_runner=runners.get("httpx_runner"),
            base=root, generator=gen)
        extend_union(result.evidence)
        return [snapshot_copy(scan_id, root, "live_hosts.json")]

    if stage_id == "port_service":
        if not _active_allowed(active_policy):
            raise _BlockedStage("active scanning not authorized (dry_run default)")
        from backend.app.recon.ports.aggregator import run_port_service_discovery
        result = run_port_service_discovery(
            scan_id, stage_input(scan_id, root, "live_hosts.json"), cfg, active_policy,
            naabu_runner=runners.get("naabu_runner"),
            nmap_runner=runners.get("nmap_runner"),
            base=root, generator=gen)
        extend_union(result.evidence)
        return [snapshot_copy(scan_id, root, "port_service_data.json")]

    if stage_id == "fingerprinting":
        from backend.app.recon.fingerprint.technologies import run_fingerprint_discovery
        hostnames = _live_hostnames(scan_id, root, stage_input)
        result = run_fingerprint_discovery(
            scan_id, hostnames, cfg, runner=runners.get("tech_runner") or subprocess.run,
            base=root, generator=gen)
        extend_union(result.evidence)
        return [snapshot_copy(scan_id, root, "fingerprint_data.json")]

    if stage_id == "endpoint_discovery":
        from backend.app.recon.endpoints.katana import run_endpoint_discovery
        urls = _live_urls(scan_id, root, stage_input)
        result = run_endpoint_discovery(
            scan_id, urls, cfg, runner=runners.get("katana_runner") or subprocess.run,
            base=root, generator=gen)
        extend_union(result.evidence)
        return [snapshot_copy(scan_id, root, "endpoint_data.json")]

    if stage_id == "screenshot_capture":
        from backend.app.recon.screenshots.gowitness import run_screenshot_capture
        urls = _live_urls(scan_id, root, stage_input)
        kwargs: dict[str, Any] = {"base": root, "generator": gen}
        if runners.get("gowitness_runner"):
            kwargs["runner"] = runners["gowitness_runner"]
        if runners.get("browser_override") is not None:
            kwargs["browser_override"] = runners["browser_override"]
        result = run_screenshot_capture(scan_id, urls, cfg, **kwargs)
        extend_union(result.evidence)
        return [snapshot_copy(scan_id, root, "screenshot_data.json")]

    if stage_id == "vulnerability_verification":
        if not _active_allowed(active_policy):
            raise _BlockedStage("nuclei verification not authorized (dry_run default)")
        from backend.app.enrichment.correlator import run_verification
        urls = _live_urls(scan_id, root, stage_input)
        result = run_verification(
            scan_id, urls, cfg, active_policy,
            nuclei_runner=runners.get("nuclei_runner"),
            nvd_fetcher=runners.get("nvd_fetcher"),
            kev_fetcher=runners.get("kev_fetcher"),
            base=root, generator=gen)
        extend_union(result.evidence)
        snapshot_copy(scan_id, root, "verified_context.json")
        return [str(root / "data" / "raw" / "nuclei" / scan_id / "nuclei.jsonl")]

    if stage_id == "security_enrichment":
        verified = _read_verified(scan_id, root)
        if verified is None:
            raise RuntimeError("verified_context.json missing after verification")
        return [str(sdir / "verified_context.json")]

    if stage_id == "ai_analysis":
        from backend.app.ai.reasoning import (
            build_attack_paths,
            generate_analysis,
            parse_model_json,
        )
        from backend.app.ai.context_builder import build_context, evidence_index
        from backend.app.ai.prompts.attack_path import build_attack_path_prompt
        snapshot = _ai_snapshot(scan_id, target, root, sdir, union)
        generate = ai_generate_fn or runners.get("ai_generate_fn")
        if generate is None:
            generate = _default_generate_fn()
        analysis = generate_analysis(scan_id, snapshot, generate, base=root)
        if analysis.status == "failed":
            raise RuntimeError(f"AI analysis failed: {analysis.error}")
        # Second pass: attack-path hypotheses (same model, validated the same
        # way). A failure here degrades to zero paths — never fails the stage.
        attack_paths: list[dict[str, Any]] = []
        try:
            system, user = build_attack_path_prompt(
                build_context(snapshot, max_chars=8000))
            payload = parse_model_json(generate(system, user))
            paths = build_attack_paths(
                payload.get("attack_paths", []) if isinstance(payload, dict) else [],
                evidence_index(union))
            attack_paths = [p.model_dump(mode="json") for p in paths]
        except Exception as exc:
            # Degrades to zero paths — never fails the stage. (Logged, not
            # raised: there is no error channel here by design.)
            log.warning("scan %s: attack-path pass degraded: %s", scan_id, exc)
        attack_file = sdir / "attack_paths.json"
        attack_file.write_text(json.dumps(
            {"scan_id": scan_id, "attack_paths": attack_paths}, indent=2),
            encoding="utf-8")
        return [snapshot_copy(scan_id, root, "ai_analysis.json"), str(attack_file)]

    if stage_id == "ai_validation":
        from backend.app.ai.schemas.finding import AIFinding
        from backend.app.validation.ai_validator import validate_finding
        from backend.app.validation.hallucination_guard import check_finding
        # Per-scan file only: the canonical ai_analysis.json may hold another
        # scan's data. A missing/failed analysis degrades to an empty gate
        # (completed, zero findings) instead of blocking the report.
        validated = _read_json(sdir / "ai_analysis.json") or {}
        if not isinstance(validated, dict) or not validated.get("findings"):
            gate_file = sdir / "ai_validation.json"
            gate_file.write_text(json.dumps(
                {"scan_id": scan_id, "results": []}, indent=2), encoding="utf-8")
            return [str(gate_file)]
        by_id = {str(e.get("id")): e for e in union}
        verified_cves = {str(v.get("cve_id", "")).upper()
                         for v in ((_read_json(sdir / "verified_context.json") or {})
                                   .get("findings", []))}
        gate_results = []
        for item in validated.get("findings", []) or []:
            finding = AIFinding(**item)
            verdict = validate_finding(finding, by_id, verified_cves, set(by_id))
            flags = check_finding(finding, by_id, verified_cves)
            gate_results.append({"finding_id": finding.finding_id,
                                 "accepted": verdict.accepted,
                                 "downgraded": verdict.downgraded,
                                 "flags": flags})
        gate_file = sdir / "ai_validation.json"
        gate_file.write_text(json.dumps(
            {"scan_id": scan_id, "results": gate_results}, indent=2), encoding="utf-8")
        return [str(gate_file)]

    if stage_id == "report_generation":
        from backend.app.reporting.pdf import write_pdf_report
        from backend.app.reporting.renderer import (
            write_appendix,
            write_endpoints_csv,
            write_inventory_json,
            write_report,
        )
        from backend.app.reporting.report_builder import (
            build_endpoints_csv_rows,
            build_inventory_document,
        )
        snapshot = _report_snapshot(scan_id, target, root, sdir, union)
        context = build_report_context(snapshot)
        out = root / "reports" / "generated" / scan_id / "final_report.md"
        write_report(context, out)
        pdf_out = root / "reports" / "generated" / scan_id / "final_report.pdf"
        write_pdf_report(context, pdf_out)
        appendix_out = root / "reports" / "generated" / scan_id / "technical_appendix.md"
        write_appendix(context, appendix_out)
        inventory_out = root / "reports" / "generated" / scan_id / "inventory.json"
        write_inventory_json(build_inventory_document(context), inventory_out)
        csv_out = root / "reports" / "generated" / scan_id / "endpoints.csv"
        write_endpoints_csv(build_endpoints_csv_rows(context), csv_out)
        return [str(out), str(pdf_out), str(appendix_out),
                str(inventory_out), str(csv_out)]

    raise ValueError(f"unknown stage: {stage_id}")


def _read_json(path: Path):
    try:
        import json as _json
        data = _json.loads(path.read_text(encoding="utf-8"))
        return data
    except Exception:
        return None


def _live_hostnames(scan_id: str, root: Path, stage_input: Callable) -> list[str]:
    data = _read_json(stage_input(scan_id, root, "live_hosts.json")) or {}
    if isinstance(data, dict):
        return [str(h.get("hostname", "")) for h in data.get("hosts", []) if h.get("hostname")]
    return []


def _live_urls(scan_id: str, root: Path, stage_input: Callable) -> list[str]:
    data = _read_json(stage_input(scan_id, root, "live_hosts.json")) or {}
    urls: list[str] = []
    if isinstance(data, dict):
        for host in data.get("hosts", []) or []:
            urls.extend(str(u) for u in (host.get("urls", []) or []))
            if not host.get("urls") and host.get("hostname"):
                urls.append(f"https://{host['hostname']}")
    return sorted(set(urls))


def _default_generate_fn() -> Callable[[str, str], str]:
    from backend.app.ai.ollama_client import OllamaClient
    client = OllamaClient()
    if not client.model_available():
        raise RuntimeError("Ollama model qwen3:8b unavailable; AI findings not fabricated")
    return client.generate


def _ai_snapshot(scan_id: str, target: str, root: Path, sdir: Path,
                 union: list[dict[str, Any]]) -> dict[str, Any]:
    verified = _read_verified(scan_id, root) or {}
    scope_data: dict[str, Any] = {}
    try:
        scope_data = json.loads((sdir / "scope.json").read_text(
            encoding="utf-8"))
    except Exception:
        scope_data = {}
    live = _read_json(sdir / "live_hosts.json") or {}
    hosts = [str(h.get("hostname", "")) for h in live.get("hosts", [])] if live else []
    return {"scan_id": scan_id, "target": target,
            "scope": {"allowed_domains": scope_data.get("matched_rule", "")},
            "evidence": union, "verified_context": verified,
            "live_hosts": hosts, "relationships": []}


def _read_verified(scan_id: str, root: Path) -> Optional[dict[str, Any]]:
    """Per-scan verified context only — the canonical file may hold another
    scan's data and must never leak across scans."""
    return _read_json(root / "data" / "processed" / scan_id / "verified_context.json")


def _report_snapshot(scan_id: str, target: str, root: Path, sdir: Path,
                     union: list[dict[str, Any]]) -> dict[str, Any]:
    def _load(name: str) -> dict[str, Any]:
        # Per-scan files only: canonical files may hold another scan's data
        # (e.g. a previous scan's ai_analysis.json) and must never leak
        # into this scan's report.
        return _read_json(sdir / name) or {}

    live = _load("live_hosts.json")
    ports = _load("port_service_data.json")
    finger = _load("fingerprint_data.json")
    endpoints = _load("endpoint_data.json")
    validation = _load("ai_validation.json")
    analysis = _load("ai_analysis.json")
    verified = _read_verified(scan_id, root) or {}
    accepted_ids: set[str] | None = None
    if validation.get("results"):
        rejected = {r["finding_id"] for r in validation["results"]
                    if r.get("accepted") is False}
        accepted_ids = {str(f.get("finding_id")) for f in analysis.get("findings", [])} - rejected
    findings = [f for f in analysis.get("findings", [])
                if accepted_ids is None or str(f.get("finding_id")) in accepted_ids]

    hosts_by_name: dict[str, dict[str, Any]] = {}
    for host in live.get("hosts", []) or []:
        hosts_by_name.setdefault(str(host.get("hostname")), {"hostname": str(host.get("hostname"))})
    for host in ports.get("hosts", []) or []:
        entry = hosts_by_name.setdefault(str(host.get("hostname")), {"hostname": str(host.get("hostname"))})
        entry["ports"] = [f"{p.get('port')}/{p.get('protocol', 'tcp')}" for p in host.get("ports", [])]
        entry["port_details"] = [{"port": str(p.get("port", "")),
                                  "protocol": str(p.get("protocol", "tcp") or "tcp"),
                                  "service": str(p.get("service", "") or ""),
                                  "version": str(p.get("version", "") or "")}
                                 for p in host.get("ports", [])]
    for host in finger.get("hosts", []) or []:
        entry = hosts_by_name.setdefault(str(host.get("hostname")), {"hostname": str(host.get("hostname"))})
        entry["technologies"] = [t.get("name", "") for t in host.get("technologies", [])]
        entry["technology_details"] = [
            {"name": str(t.get("name", "") or ""),
             "version": str(t.get("version", "") or ""),
             "evidence": ", ".join(t.get("evidence_ids", []) or [])}
            for t in host.get("technologies", [])]
    for host in endpoints.get("hosts", []) or []:
        entry = hosts_by_name.setdefault(str(host.get("hostname")), {"hostname": str(host.get("hostname"))})
        entry["endpoints"] = [e.get("path", "") for e in host.get("endpoints", [])]
    for host in live.get("hosts", []) or []:
        entry = hosts_by_name.setdefault(str(host.get("hostname")), {"hostname": str(host.get("hostname"))})
        entry.setdefault("urls", host.get("urls", []))
    shots = [{**s, "path": ("../../" + s["path"] if str(s.get("path", "")).startswith("data/") else s.get("path", ""))}
             for s in ((_load("screenshot_data.json")).get("screenshots", []) or [])]
    # Methodology reflects what ACTUALLY ran, read from this scan's own
    # stage checkpoints — never a static list of stage names.
    from backend.app.orchestrator.stages import STAGES as _STAGE_DEFS
    stage_names = {d.stage_id: d.name for d in _STAGE_DEFS}
    ran_names = []
    for stage_id, name in stage_names.items():
        cp = _read_json(sdir / "checkpoints" / f"{stage_id}.json") or {}
        if cp.get("status") == "completed":
            ran_names.append(name)
    # Per-scan scope ONLY — never the static scope.yaml file. The persisted
    # scope.json written at scope_validation is authoritative for this scan.
    scope_data = _read_json(sdir / "scope.json") or {}
    scope_cfg = {
        "root_domain": scope_data.get("root_domain", target),
        "allowed_domains": [scope_data["root_domain"]] if scope_data.get("root_domain") else [],
        "allowed_root_domains": ([scope_data["root_domain"]]
                                 if scope_data.get("root_domain") else []),
        "allowed_subdomains": [],
        "allowed_ips": scope_data.get("allowed_ips", []) or [],
        "allowed_cidrs": scope_data.get("allowed_cidrs", []) or [],
        "matched_rule": scope_data.get("matched_rule", ""),
    }
    duration = ""
    try:
        scope_cp = _read_json(sdir / "checkpoints" / "scope_validation.json") or {}
        start = scope_cp.get("started_at", "")
        if start:
            from datetime import datetime as _dt
            delta = (_dt.now(timezone.utc) - _dt.fromisoformat(start))
            minutes, seconds = divmod(int(delta.total_seconds()), 60)
            duration = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"
    except Exception:
        duration = ""
    return {
        "scan_id": scan_id, "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration": duration,
        "model": analysis.get("model", "qwen3:8b") if isinstance(analysis, dict) else "qwen3:8b",
        "scope": scope_cfg,
        "stages_run": ran_names,
        "methodology": [{"stage": name, "ran": name in ran_names}
                        for name in stage_names.values()],
        "assets": sorted(hosts_by_name.values(), key=lambda a: a["hostname"]),
        "live_host_count": len(hosts_by_name),
        "open_port_count": sum(len(v.get("ports", [])) for v in hosts_by_name.values()),
        "technology_count": sum(len(v.get("technologies", [])) for v in hosts_by_name.values()),
        "endpoint_count": sum(len(v.get("endpoints", [])) for v in hosts_by_name.values()),
        "evidence": union, "verified_context": verified, "findings": findings,
        "ai_analysis": {"recommendations": analysis.get("recommendations", [])},
        "executive_summary": analysis.get("executive_summary", "") or "",
        "attack_paths": (_read_json(sdir / "attack_paths.json") or {}).get(
            "attack_paths", []) or [], "screenshots": shots, "synthetic": False}


def _count_results(scan_id: str, root: Path) -> dict[str, int]:
    def _len_json(name: str, key: str) -> int:
        # Per-scan only (see _report_snapshot): canonical files may be stale.
        data = _read_json(root / "data" / "processed" / scan_id / name)
        if isinstance(data, dict):
            return len(data.get(key, []) or [])
        return 0

    ports = 0
    data = _read_json(
        root / "data" / "processed" / scan_id / "port_service_data.json")
    if isinstance(data, dict):
        ports = sum(len(h.get("ports", []) or []) for h in data.get("hosts", []) or [])
    endpoints = 0
    data = _read_json(
        root / "data" / "processed" / scan_id / "endpoint_data.json")
    if isinstance(data, dict):
        endpoints = sum(len(h.get("endpoints", []) or []) for h in data.get("hosts", []) or [])
    return {"findings": _len_json("ai_analysis.json", "findings"),
            "assets": _len_json("asset_list.json", "assets"),
            "live_hosts": _len_json("live_hosts.json", "hosts"),
            "ports": ports, "endpoints": endpoints,
            "vulnerabilities": _len_json("verified_context.json", "findings")}


def preflight_check(target: str, config: Optional[ScopeConfig] = None) -> dict[str, Any]:
    """Readiness probe — scope, tools, config, policy, model, dirs. No recon.

    Scope is evaluated against an ephemeral per-target ScanScope (never
    persisted here): any well-formed lab root is its own boundary, while
    malformed input raises before anything else runs.
    """
    from backend.app.ai.ollama_client import OllamaClient
    from backend.app.core.tool_manager import check_all_tools

    if config is not None:
        cfg = config
        scope_obj = None
        decision = validate_target(target, cfg)
    else:
        scope_obj = create_scan_scope(target, "preflight")
        cfg = scope_obj.to_scope_config()
        decision = validate_target(target, cfg)
    tools = {t.name: {"available": t.available, "status": t.status, "version": t.version}
             for t in check_all_tools()}
    required = ("subfinder", "dnsx", "httpx", "naabu", "nmap", "katana",
                "gowitness", "nuclei", "ollama")
    missing = [name for name in required if not tools.get(name, {}).get("available")]
    try:
        model_ok = OllamaClient().model_available()
    except Exception:
        model_ok = False
    root = project_root()
    dirs_ok = all((root / "data" / name).exists()
                  for name in ("raw", "processed")) and (root / "config" / "scope.yaml").exists()
    ready = bool(decision.allowed) and not missing and dirs_ok
    return {"target": decision.target, "scope_allowed": decision.allowed,
            "scope_reason": decision.reason,
            "effective_scope": (scope_obj.describe() if scope_obj else {}),
            "tools": tools, "missing_required_tools": missing,
            "policy": {"dry_run": cfg.policy.dry_run,
                       "allow_active_scanning": cfg.policy.allow_active_scanning,
                       "allow_exploitation": cfg.policy.allow_exploitation},
            "model_available": model_ok, "directories_ok": dirs_ok, "ready": ready}
