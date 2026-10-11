"""Phase 11 tests: orchestration end-to-end — every external call mocked.

No real Subfinder/crt.sh/dnsx/httpx/Naabu/Nmap/Katana/GoWitness/Nuclei,
no network, no Internet targets. Lab fixture data only.
"""

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.orchestrator import pipeline as pipeline_module
from backend.app.orchestrator.job_manager import JobManager
from backend.app.orchestrator.pipeline import PipelineResult, run_pipeline
from backend.app.orchestrator.stages import STAGE_IDS
from backend.app.safety.execution_policy import (
    ActiveScanAuthorization,
    lab_active_scan_policy,
)
from backend.app.safety.scope_validator import ScopeConfig


def _lab_config() -> ScopeConfig:
    return ScopeConfig(
        allowed_domains=["example.lab"],
        allowed_subdomains=["www.example.lab", "api.example.lab"],
        allowed_ips=[], allowed_cidrs=[],
    )


def _lab_policy():
    return lab_active_scan_policy(ActiveScanAuthorization(
        scan_id="lab", approved_by="test-harness", reason="phase 11 e2e"))


def _fx() -> dict:
    return json.loads(
        (PROJECT_ROOT / "tests" / "fixtures" / "pipeline" / "e2e_lab.json")
        .read_text(encoding="utf-8"))


def _lines(records) -> str:
    return "\n".join(json.dumps(r) for r in records)


def _mock_runners(fx: dict, calls: dict | None = None):
    def _runner(cmd, **kw):
        assert kw.get("shell") is False and isinstance(cmd, list)
        exe = str(cmd[0]).replace("\\", "/").lower()
        if calls is not None:
            calls[exe.rsplit("/", 1)[-1]] = calls.get(exe.rsplit("/", 1)[-1], 0) + 1
        if "subfinder" in exe:
            return SimpleNamespace(stdout=fx["subfinder_stdout"], stderr="", returncode=0)
        if "dnsx" in exe:
            return SimpleNamespace(stdout=_lines(fx["dnsx"]), stderr="", returncode=0)
        if "httpx" in exe:
            return SimpleNamespace(stdout=_lines(fx["httpx"]), stderr="", returncode=0)
        if "naabu" in exe:
            host = cmd[cmd.index("-host") + 1]
            lines = [ln for ln in _lines(fx["naabu"]).splitlines()
                     if json.loads(ln)["host"] == host]
            return SimpleNamespace(stdout="\n".join(lines), stderr="", returncode=0)
        if "nmap" in exe:
            return SimpleNamespace(stdout=fx["nmap_xml"], stderr="", returncode=0)
        if "katana" in exe:
            return SimpleNamespace(stdout=_lines(fx["katana"]), stderr="", returncode=0)
        if "gowitness" in exe:
            shot_dir = Path(cmd[cmd.index("--screenshot-path") + 1])
            (shot_dir / "www.example.lab.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            return SimpleNamespace(
                stdout=fx["gowitness_stdout"] + " have-screenshot=true",
                stderr="", returncode=0)
        if "nuclei" in exe:
            return SimpleNamespace(stdout=_lines(fx["nuclei"]), stderr="", returncode=0)
        raise AssertionError(f"unexpected tool: {exe}")

    return _runner


def _runners(fx: dict, calls: dict | None = None):
    runner = _mock_runners(fx, calls)
    return {
        "subfinder_runner": runner, "dns_runner": runner, "httpx_runner": runner,
        "naabu_runner": runner, "nmap_runner": runner, "tech_runner": runner,
        "katana_runner": runner, "gowitness_runner": runner,
        "nuclei_runner": runner,
        "crtsh_fetcher": lambda url, timeout: json.dumps(fx["crtsh"]),
        "nvd_fetcher": lambda url, timeout: '{"totalResults": 0}',
        "kev_fetcher": lambda url, timeout: json.dumps(fx["kev"]),
        "browser_override": (True, "test-browser"),
    }


def _e2e_ai_fn(system: str, user: str) -> str:
    """Cite a real endpoint evidence ID parsed from the prompt context."""
    import re
    endpoint_id = None
    for line in user.splitlines():
        if "type: endpoint" in line:
            match = re.search(r"\[(E\d+)\]", line)
            if match:
                endpoint_id = match.group(1)
                break
    assert endpoint_id, "pipeline must supply endpoint evidence to AI"
    return json.dumps({"findings": [{
        "finding_id": "FIND-001", "title": "Exposed login endpoint",
        "description": f"Endpoint /login observed per [{endpoint_id}].",
        "classification": "hypothesis", "severity": "medium", "confidence": 0.72,
        "evidence_ids": [endpoint_id], "observed_facts": ["/login exists."],
        "reasoning": "Endpoint evidence supports review.",
        "verification_status": "unverified",
        "next_manual_steps": ["Inspect authentication manually."],
        "endpoints": ["/login"]}],
        "recommendations": [{"recommendation_id": "R001",
                             "text": "Review authentication on /login.",
                             "evidence_ids": [endpoint_id],
                             "rationale": "Login exposed.", "priority": "medium"}]})


def _run_e2e(tmp_path: Path, **kw) -> PipelineResult:
    fx = _fx()
    return run_pipeline(
        scan_id="e2e-0001", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=_runners(fx),
        ai_generate_fn=_e2e_ai_fn, **kw)


# -- end-to-end ---------------------------------------------------------------

def test_e2e_order_and_outputs(tmp_path):
    result = _run_e2e(tmp_path)
    assert [s.stage_id for s in result.stages] == STAGE_IDS
    assert all(s.status == "completed" for s in result.stages)
    for stage in ("asset_discovery", "live_discovery", "port_service",
                  "fingerprinting", "endpoint_discovery", "screenshot_capture",
                  "vulnerability_verification"):
        assert (tmp_path / "data" / "processed" / "e2e-0001").exists()


def test_e2e_evidence_continuity(tmp_path):
    result = _run_e2e(tmp_path)
    union = json.loads((tmp_path / "data" / "processed" / "e2e-0001"
                        / "evidence.json").read_text())
    ids = [e["id"] for e in union]
    assert ids == sorted(ids) and len(ids) == len(set(ids))
    assert ids[0] == "E001"
    data = json.loads((tmp_path / "data" / "processed" / "e2e-0001"
                       / "ai_analysis.json").read_text())
    cited = {eid for f in data["findings"] for eid in f["evidence_ids"]}
    assert cited and cited <= set(ids)


def test_e2e_report(tmp_path):
    result = _run_e2e(tmp_path)
    assert result.report_path.endswith("final_report.md")
    text = Path(result.report_path).read_text(encoding="utf-8")
    assert "FIND-001" in text and "E" in text
    assert "example.lab" in text


def test_e2e_status_completed(tmp_path):
    result = _run_e2e(tmp_path)
    assert result.status == "completed"
    assert result.asset_count == 2 and result.findings_count == 1


# -- stage failures -------------------------------------------------------------

def _fail_runner(exe_part: str):
    def _run(cmd, **kw):
        if exe_part in str(cmd[0]).replace("\\", "/").lower():
            raise FileNotFoundError(f"no {exe_part}")
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    return _run


def test_asset_failure(tmp_path):
    # Both asset sources down: the stage fails and dependents block.
    fx = _fx()
    runners = _runners(fx)
    runners["subfinder_runner"] = _fail_runner("subfinder")

    def _crtsh_down(url, timeout):
        raise TimeoutError("crt.sh down")

    runners["crtsh_fetcher"] = _crtsh_down
    result = run_pipeline(
        scan_id="f1", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=runners,
        ai_generate_fn=_e2e_ai_fn)
    by_id = {s.stage_id: s.status for s in result.stages}
    assert by_id["asset_discovery"] == "failed"
    assert by_id["live_discovery"] == "blocked"
    assert result.status == "failed"


def test_asset_partial_source_failure(tmp_path):
    # One asset source down: the other source's results still become assets.
    fx = _fx()
    runners = _runners(fx)
    runners["subfinder_runner"] = _fail_runner("subfinder")
    result = run_pipeline(
        scan_id="f1b", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=runners,
        ai_generate_fn=_e2e_ai_fn)
    by_id = {s.stage_id: s.status for s in result.stages}
    assert by_id["asset_discovery"] == "completed"
    assert result.asset_count >= 1


def test_live_failure(tmp_path):
    fx = _fx()
    runners = _runners(fx)
    runners["dns_runner"] = _fail_runner("dnsx")
    runners["httpx_runner"] = _fail_runner("httpx")
    result = run_pipeline(
        scan_id="f2", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=runners,
        ai_generate_fn=_e2e_ai_fn)
    assert {s.stage_id: s.status for s in result.stages}["live_discovery"] == "failed"


def test_port_failure(tmp_path):
    fx = _fx()
    runners = _runners(fx)
    runners["naabu_runner"] = _fail_runner("naabu")
    result = run_pipeline(
        scan_id="f3", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=runners,
        ai_generate_fn=_e2e_ai_fn)
    assert {s.stage_id: s.status for s in result.stages}["port_service"] == "failed"


def test_fingerprint_partial_and_endpoint_failure(tmp_path):
    fx = _fx()
    runners = _runners(fx)
    runners["katana_runner"] = _fail_runner("katana")
    result = run_pipeline(
        scan_id="f4", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=runners,
        ai_generate_fn=_e2e_ai_fn)
    by_id = {s.stage_id: s.status for s in result.stages}
    assert by_id["fingerprinting"] == "completed"
    assert by_id["endpoint_discovery"] == "failed"


def test_screenshot_failure_isolated(tmp_path):
    fx = _fx()
    runners = _runners(fx)
    runners["gowitness_runner"] = _fail_runner("gowitness")
    result = run_pipeline(
        scan_id="f5", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=runners,
        ai_generate_fn=_e2e_ai_fn)
    by_id = {s.stage_id: s.status for s in result.stages}
    assert by_id["screenshot_capture"] == "failed"
    assert by_id["vulnerability_verification"] == "completed"


def test_nuclei_failure(tmp_path):
    fx = _fx()
    runners = _runners(fx)
    runners["nuclei_runner"] = _fail_runner("nuclei")
    result = run_pipeline(
        scan_id="f6", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=runners,
        ai_generate_fn=_e2e_ai_fn)
    by_id = {s.stage_id: s.status for s in result.stages}
    assert by_id["vulnerability_verification"] == "failed"
    assert by_id["security_enrichment"] == "blocked"


def test_nvd_kev_unavailable(tmp_path):
    fx = _fx()
    runners = _runners(fx)

    def _down(url, timeout):
        raise TimeoutError("offline")

    runners["nvd_fetcher"] = _down
    runners["kev_fetcher"] = _down
    result = run_pipeline(
        scan_id="f7", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=runners,
        ai_generate_fn=_e2e_ai_fn)
    assert {s.stage_id: s.status for s in result.stages}[
        "vulnerability_verification"] == "completed"


def test_ollama_unavailable(tmp_path):
    fx = _fx()

    def _down(system, user):
        raise TimeoutError("no model")

    result = run_pipeline(
        scan_id="f8", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=_runners(fx),
        ai_generate_fn=_down)
    by_id = {s.stage_id: s.status for s in result.stages}
    assert by_id["ai_analysis"] == "failed"
    assert by_id["report_generation"] == "completed"


def test_ai_malformed(tmp_path):
    fx = _fx()
    result = run_pipeline(
        scan_id="f9", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=_runners(fx),
        ai_generate_fn=lambda s, u: "garbage {{{")
    assert {s.stage_id: s.status for s in result.stages}["ai_analysis"] == "failed"


def test_ai_validation_failure(tmp_path):
    fx = _fx()
    bad = json.dumps({"findings": [{
        "finding_id": "FIND-9", "title": "Bad", "description": "No evidence.",
        "classification": "hypothesis", "severity": "medium", "confidence": 0.5,
        "evidence_ids": ["E404"], "observed_facts": [], "reasoning": "x",
        "verification_status": "unverified", "next_manual_steps": []}],
        "recommendations": []})
    result = run_pipeline(
        scan_id="f10", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=_runners(fx),
        ai_generate_fn=lambda s, u: bad)
    text = Path(result.report_path).read_text(encoding="utf-8")
    assert "FIND-9" not in text


def test_report_validation_failure():
    from backend.app.reporting.renderer import write_report
    from backend.app.reporting.report_builder import build_report_context

    with pytest.raises(Exception):
        write_report(build_report_context({"scan_id": ""}), "/nonexistent/x.md")


# -- resume ---------------------------------------------------------------------

def test_resume(tmp_path):
    fx = _fx()
    calls: dict = {}
    runners = _runners(fx, calls)
    runners["naabu_runner"] = _fail_runner("naabu")
    first = run_pipeline(
        scan_id="resume-1", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=runners,
        ai_generate_fn=_e2e_ai_fn)
    assert {s.stage_id: s.status for s in first.stages}["port_service"] == "failed"

    calls.clear()
    runners["naabu_runner"] = _mock_runners(fx, calls)
    second = run_pipeline(
        scan_id="resume-1", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=runners,
        ai_generate_fn=_e2e_ai_fn, resume=True)
    assert "subfinder.exe" not in calls and "dnsx.exe" not in calls
    assert "naabu.exe" in calls
    assert {s.stage_id: s.status for s in second.stages}["port_service"] == "completed"
    assert second.status == "completed"
    assert Path(second.report_path).exists()


# -- scope ------------------------------------------------------------------------

def _never_runner(cmd, **kw):
    raise AssertionError("no tool may execute for rejected targets")


def test_scope_accepted():
    from backend.app.safety.scope_validator import validate_target
    assert validate_target("example.lab", _lab_config()).allowed is True


def test_scope_rejected():
    runners = _runners(_fx())
    for bad in ("evil.com", "example.lab.attacker.com", "evil.com;whoami", "$(whoami)"):
        result = run_pipeline(
            scan_id="sx", target=bad, config=_lab_config(),
            active_policy=_lab_policy(), base=Path("/nonexistent-base"),
            runners=runners, ai_generate_fn=_e2e_ai_fn)
        assert result.status == "failed"


# -- job manager ---------------------------------------------------------------------

def test_job_lifecycle():
    manager = JobManager(pipeline_fn=lambda **kw: PipelineResult(
        scan_id=kw["scan_id"], target=kw.get("target", ""), status="completed"))
    job = manager.create_job("example.lab")
    assert job.scan_id == "example-lab-0001" and job.status == "queued"
    manager.submit(job.scan_id, {})
    deadline = time.time() + 10
    while manager.get_job(job.scan_id).status == "queued" and time.time() < deadline:
        time.sleep(0.05)
    assert manager.get_job(job.scan_id).status == "completed"


def test_duplicate_scan_id():
    manager = JobManager(pipeline_fn=lambda **kw: None)
    manager.create_job("example.lab", scan_id="dup-1")
    with pytest.raises(ValueError):
        manager.create_job("example.lab", scan_id="dup-1")


def test_cancel():
    started = __import__("threading").Event()
    release = __import__("threading").Event()

    def _slow(**kw):
        started.set()
        assert release.wait(timeout=10)
        return PipelineResult(scan_id=kw["scan_id"], target="", status="completed")

    manager = JobManager(pipeline_fn=_slow)
    job = manager.create_job("example.lab")
    manager.submit(job.scan_id, {})
    assert started.wait(timeout=10)
    manager.request_cancel(job.scan_id)
    release.set()
    deadline = time.time() + 10
    while manager.get_job(job.scan_id).status == "running" and time.time() < deadline:
        time.sleep(0.05)
    assert manager.get_job(job.scan_id).status == "cancelled"


# -- API ------------------------------------------------------------------------------

def _api_client(monkeypatch):
    from fastapi.testclient import TestClient

    import backend.app.api.routes.scans as scans_module
    from backend.main import app

    def _fake_pipeline(scan_id, target, should_stop=None, **kw):
        return PipelineResult(scan_id=scan_id, target=target, status="completed",
                              report_path="")

    manager = JobManager(pipeline_fn=_fake_pipeline)
    monkeypatch.setattr(scans_module, "job_manager", manager)
    return TestClient(app), manager


def test_api_create_and_status(monkeypatch):
    client, _ = _api_client(monkeypatch)
    created = client.post("/api/scans", json={"target": "example.lab"})
    assert created.status_code == 202
    sid = created.json()["scan_id"]
    deadline = time.time() + 10
    while client.get(f"/api/scans/{sid}").json()["status"] == "queued" \
            and time.time() < deadline:
        time.sleep(0.05)
    assert client.get(f"/api/scans/{sid}").json()["status"] == "completed"


def test_api_out_of_scope(monkeypatch):
    # Per-scan scope: any well-formed root becomes its own boundary (accepted),
    # while malformed / non-domain / non-allow-listed-IP roots are rejected.
    client, _ = _api_client(monkeypatch)
    accepted = client.post("/api/scans", json={"target": "evil.com"})
    assert accepted.status_code == 202
    assert accepted.json()["root_domain"] == "evil.com"
    for bad in ("", "not a host!!", "http://user@example.lab", "localhost",
                "127.0.0.1", "example.lab:badport", "singlelabel"):
        response = client.post("/api/scans", json={"target": bad})
        assert response.status_code == 422, bad
    # A suffix-shaped input is its own root — but it can never reach the
    # original domain: boundary containment is enforced per scan scope.
    from backend.app.safety.scope_validator import ScanScope, validate_target
    scope = ScanScope(scan_id="t", root_domain="example.lab",
                      created_at="2026-01-01T00:00:00+00:00")
    cfg = scope.to_scope_config()
    assert validate_target("example.lab.attacker.com", cfg).allowed is False
    assert validate_target("attackerlab-target.example", cfg).allowed is False


def test_api_stages_findings_report(monkeypatch):
    client, _ = _api_client(monkeypatch)
    sid = client.post("/api/scans", json={"target": "example.lab"}).json()["scan_id"]
    assert client.get(f"/api/scans/{sid}/stages").status_code == 200
    findings = client.get(f"/api/scans/{sid}/findings")
    assert findings.status_code == 200 and findings.json()["scan_id"] == sid
    assert client.get(f"/api/scans/{sid}/report").status_code in (200, 409)


def test_api_preflight(monkeypatch):
    client, _ = _api_client(monkeypatch)
    response = client.post("/api/scans/preflight", json={"target": "example.lab"})
    assert response.status_code == 200
    assert response.json()["scope_allowed"] is True


def test_api_cancel(monkeypatch):
    client, _ = _api_client(monkeypatch)
    assert client.post("/api/scans/unknown-id/cancel").status_code == 404
    sid = client.post("/api/scans", json={"target": "example.lab"}).json()["scan_id"]
    cancelled = client.post(f"/api/scans/{sid}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] in ("cancelled", "completed", "running")


def test_api_scan_mode_agreement(monkeypatch):
    client, _ = _api_client(monkeypatch)
    passive = client.post("/api/scans", json={"target": "example.lab"}).json()["scan_id"]
    assert client.get(f"/api/scans/{passive}").json()["scan_mode"] == "passive"
    active = client.post("/api/scans", json={
        "target": "example.lab", "authorize_active": True,
        "approved_by": "tester", "reason": "mode agreement test"}).json()["scan_id"]
    status = client.get(f"/api/scans/{active}").json()
    assert status["scan_mode"] == "authorized"
    assert status["execution_enabled"] is True
    denied = client.post("/api/scans", json={
        "target": "example.lab", "authorize_active": True,
        "approved_by": "", "reason": "x"})
    assert denied.status_code == 422


def test_api_disk_fallback_after_restart(monkeypatch, tmp_path):
    import backend.app.api.routes.scans as scans_module

    sid = "disk-fallback-0001"
    sdir = tmp_path / "data" / "processed" / sid
    (sdir / "checkpoints").mkdir(parents=True)
    (sdir / "scope.json").write_text(json.dumps(
        {"scan_id": sid, "target": "example.lab", "root_domain": "example.lab",
         "matched_rule": "allowed_root_domains:example.lab"}))
    (sdir / "asset_list.json").write_text(json.dumps(
        {"scan_id": sid, "target": "example.lab",
         "assets": [{"hostname": "www.example.lab"}]}))
    (sdir / "ai_analysis.json").write_text(json.dumps(
        {"scan_id": sid, "model": "qwen3:8b", "status": "completed",
         "findings": [{"finding_id": "FIND-001", "title": "T",
                       "description": "d", "classification": "hypothesis",
                       "severity": "low", "confidence": 0.5,
                       "evidence_ids": ["E001"], "observed_facts": [],
                       "reasoning": "r", "verification_status": "unverified",
                       "next_manual_steps": []}]}))
    (sdir / "checkpoints" / "asset_discovery.json").write_text(json.dumps(
        {"scan_id": sid, "stage": "asset_discovery", "status": "completed",
         "started_at": "", "completed_at": "", "output_files": ["x"], "error": ""}))
    reports = tmp_path / "reports" / "generated" / sid
    reports.mkdir(parents=True)
    (reports / "final_report.md").write_text("# TraceHoundAI Security Assessment\n")
    monkeypatch.setattr(scans_module, "project_root", lambda: tmp_path)

    from fastapi.testclient import TestClient
    from backend.main import app
    client = TestClient(app)
    assert client.get(f"/api/scans/{sid}").json()["status"] == "completed"
    summary = client.get(f"/api/scans/{sid}/summary").json()
    assert summary["assets"] == 1 and summary["ai_findings"] == 1
    assert client.get(f"/api/scans/{sid}/findings").json()["findings"][0][
        "finding_id"] == "FIND-001"
    assert client.get(f"/api/scans/{sid}/report").status_code == 200
    assert client.get("/api/scans/unknown-id-xyz").status_code == 404


def test_no_exploitation_stage():
    assert "exploit" not in " ".join(STAGE_IDS)
    from backend.app.enrichment.nuclei import build_nuclei_command
    # Exploit families are explicitly excluded from verification templates.
    assert "exploit" in ",".join(build_nuclei_command("nuclei-exe"))
    from backend.app.safety.execution_policy import check_execution_policy
    assert check_execution_policy("exploitation").allowed is False
    assert check_execution_policy("exploit").allowed is False


# -- AI failure resilience ------------------------------------------------------

def _timed_out_model(system: str, user: str) -> str:
    raise TimeoutError("Ollama request timed out: timed out")


def test_ai_timeout_still_produces_report(tmp_path):
    # Slow model: ai_analysis fails, but validation degrades to empty and
    # the evidence-based report still generates (status completed).
    fx = _fx()
    result = run_pipeline(
        scan_id="ai-t1", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=_runners(fx),
        ai_generate_fn=_timed_out_model)
    by_id = {s.stage_id: s.status for s in result.stages}
    assert by_id["ai_analysis"] == "failed"
    assert by_id["ai_validation"] == "completed"
    assert by_id["report_generation"] == "completed"
    assert result.status == "completed"
    assert result.report_path.endswith("final_report.md")
    assert result.findings_count == 0


def test_stale_canonical_analysis_ignored(tmp_path):
    # A previous scan's canonical ai_analysis.json must never leak into
    # this scan's report (regression: stale F001/CVE-2023-5561 failed it).
    fx = _fx()
    proc = tmp_path / "data" / "processed"
    proc.mkdir(parents=True, exist_ok=True)
    (proc / "ai_analysis.json").write_text(json.dumps({
        "scan_id": "someone-else", "model": "qwen3:8b", "status": "completed",
        "findings": [{"finding_id": "F001", "title": "Stale finding",
                      "description": "CVE-2023-5561 seen on another scan.",
                      "classification": "observed_fact", "severity": "high",
                      "confidence": 0.9, "evidence_ids": ["E999"],
                      "observed_facts": ["stale"], "reasoning": "stale",
                      "verification_status": "verified",
                      "next_manual_steps": ["stale"]}],
        "recommendations": [], "executive_summary": "", "error": ""}),
        encoding="utf-8")
    result = run_pipeline(
        scan_id="ai-t2", target="example.lab", config=_lab_config(),
        active_policy=_lab_policy(), base=tmp_path, runners=_runners(fx),
        ai_generate_fn=_timed_out_model)
    assert result.status == "completed"
    text = Path(result.report_path).read_text(encoding="utf-8")
    assert "CVE-2023-5561" not in text and "Stale finding" not in text
