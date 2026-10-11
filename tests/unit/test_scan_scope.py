"""Phase 14 tests: dynamic per-scan authorized target scope.

No real reconnaissance — mocked runners/fetchers and synthetic lab roots only.
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.orchestrator.pipeline import run_pipeline
from backend.app.orchestrator.stages import STAGE_IDS
from backend.app.safety.exceptions import InvalidTargetError
from backend.app.safety.execution_policy import (
    ActiveScanAuthorization,
    check_execution_policy,
    lab_active_scan_policy,
)
from backend.app.safety.scope_validator import (
    ScanScope,
    ScopeConfig,
    create_scan_scope,
    validate_target,
)


def _lab_policy():
    return lab_active_scan_policy(ActiveScanAuthorization(
        scan_id="lab", approved_by="test-harness", reason="phase 14"))


def _scan_config(root: str) -> ScopeConfig:
    return create_scan_scope(root, "s-test").to_scope_config()


# -- root acceptance / normalization -------------------------------------------

def test_root_domain_accepted():
    scope = create_scan_scope("lab-target.example", "s1")
    assert scope.root_domain == "lab-target.example"


def test_root_domain_normalized():
    scope = create_scan_scope("  HTTPS://LAB-Target.Example.:8443/path ", "s1")
    assert scope.root_domain == "lab-target.example"


def test_subdomain_accepted():
    cfg = _scan_config("lab-target.example")
    assert validate_target("lab-target.example", cfg).allowed is True
    assert validate_target("www.lab-target.example", cfg).allowed is True
    assert validate_target("deep.nested.lab-target.example", cfg).allowed is True


def test_sibling_domain_rejected():
    cfg = _scan_config("target-a.example")
    assert validate_target("target-b.example", cfg).allowed is False
    assert validate_target("example", cfg).allowed is False


def test_suffix_attack_rejected():
    cfg = _scan_config("lab-target.example")
    assert validate_target("lab-target.example.attacker.com", cfg).allowed is False
    assert validate_target("attackerlab-target.example", cfg).allowed is False
    assert validate_target("evil.com", cfg).allowed is False
    assert validate_target("lab-target.example.evil.com", cfg).allowed is False


def test_attacker_domain_rejected():
    cfg = _scan_config("lab-target.example")
    decision = validate_target("evil.com", cfg)
    assert decision.allowed is False and decision.risk_level == "blocked"


def test_malformed_target_rejected():
    for bad in ("", "   ", "not a host!!", "http://user@example.lab",
                "example.lab:badport", "a" * 300 + ".example"):
        with pytest.raises(InvalidTargetError):
            create_scan_scope(bad, "s1")


def test_localhost_and_bare_names_rejected():
    for bad in ("localhost", "LOCALHOST", "intranet", "singlelabel"):
        with pytest.raises(InvalidTargetError):
            create_scan_scope(bad, "s1")


def test_ip_rejected_by_default():
    with pytest.raises(InvalidTargetError):
        create_scan_scope("127.0.0.1", "s1")
    with pytest.raises(InvalidTargetError):
        create_scan_scope("192.168.1.1", "s1")


def test_ip_allowed_when_globally_listed():
    global_cfg = ScopeConfig(allowed_ips=["192.0.2.10"], allowed_cidrs=[])
    scope = create_scan_scope("192.0.2.10", "s1", global_cfg)
    assert validate_target("192.0.2.10", scope.to_scope_config()).allowed is True


# -- isolation / persistence ----------------------------------------------------

def test_multiple_scan_scopes_isolated():
    cfg_a = _scan_config("target-a.example")
    cfg_b = _scan_config("target-b.example")
    assert validate_target("www.target-a.example", cfg_a).allowed is True
    assert validate_target("www.target-a.example", cfg_b).allowed is False
    assert validate_target("www.target-b.example", cfg_a).allowed is False
    assert validate_target("www.target-b.example", cfg_b).allowed is True


def test_scope_persisted_through_checkpoint(tmp_path):
    scope = create_scan_scope("target-a.example", "s1")
    path = scope.save(tmp_path / "scope.json")
    loaded = ScanScope.load(path)
    assert loaded.root_domain == "target-a.example"
    assert loaded.scan_id == "s1"
    assert validate_target("x.target-a.example",
                           loaded.to_scope_config()).allowed is True


def test_discovered_out_of_scope_rejected():
    cfg = _scan_config("lab-target.example")
    assert validate_target("mail.lab-target.example", cfg).allowed is True
    assert validate_target("lab-target.example.attacker.com", cfg).allowed is False


# -- policy modes -----------------------------------------------------------------

def test_passive_mode():
    assert check_execution_policy("passive_discovery").allowed is True


def test_explicit_active_lab_authorization():
    assert check_execution_policy("active_port_scan").allowed is False
    assert check_execution_policy("active_port_scan", _lab_policy()).allowed is True
    assert check_execution_policy("vulnerability_verification", _lab_policy()).allowed is True


def test_active_scan_denied_by_default():
    assert check_execution_policy("active_port_scan").allowed is False
    assert check_execution_policy("nuclei_verification").allowed is False


def test_exploitation_always_denied():
    assert check_execution_policy("exploitation", _lab_policy()).allowed is False
    assert check_execution_policy("exploit", _lab_policy()).allowed is False


# -- pipeline with per-scan scope (mocked stages) ----------------------------------

def _fx() -> dict:
    return json.loads(
        (PROJECT_ROOT / "tests" / "fixtures" / "pipeline" / "e2e_lab.json")
        .read_text(encoding="utf-8"))


def _mock_runners(fx: dict):
    def _runner(cmd, **kw):
        exe = str(cmd[0]).replace("\\", "/").lower()
        if "subfinder" in exe:
            out = "www.target-a.example\napi.target-a.example\n"
        elif "dnsx" in exe:
            out = "\n".join(json.dumps(
                {"host": h, "a": ["192.0.2.10"]})
                for h in ("www.target-a.example", "api.target-a.example"))
        elif "httpx" in exe:
            out = "\n".join(json.dumps(
                {"host": h, "url": f"https://{h}", "status_code": 200})
                for h in ("www.target-a.example", "api.target-a.example"))
        elif "naabu" in exe:
            host = cmd[cmd.index("-host") + 1]
            out = json.dumps({"host": host, "ip": "192.0.2.10",
                              "port": 443, "protocol": "tcp", "status": "open"})
        elif "nmap" in exe:
            out = ("<?xml version=\"1.0\"?><nmaprun><host>"
                   "<address addr=\"192.0.2.10\" addrtype=\"ipv4\"/><ports>"
                   "<port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/>"
                   "<service name=\"https\"/></port></ports></host></nmaprun>")
        elif "katana" in exe:
            out = json.dumps({"endpoint": "https://www.target-a.example/login"})
        elif "gowitness" in exe:
            out = "screenshot saved"
        elif "nuclei" in exe:
            out = ""
        else:
            raise AssertionError(f"unexpected tool: {exe}")
        return SimpleNamespace(stdout=out, stderr="", returncode=0)

    return {
        "subfinder_runner": _runner, "dns_runner": _runner, "httpx_runner": _runner,
        "naabu_runner": _runner, "nmap_runner": _runner, "tech_runner": _runner,
        "katana_runner": _runner, "gowitness_runner": _runner,
        "nuclei_runner": _runner,
        "crtsh_fetcher": lambda url, timeout: json.dumps(
            [{"name_value": "www.target-a.example"}]),
        "nvd_fetcher": lambda url, timeout: '{"totalResults": 0}',
        "kev_fetcher": lambda url, timeout: '{"vulnerabilities": []}',
        "browser_override": (True, "test-browser"),
    }


def _ai_fn(system: str, user: str) -> str:
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
        "description": f"Endpoint observed per [{endpoint_id}].",
        "classification": "hypothesis", "severity": "medium", "confidence": 0.7,
        "evidence_ids": [endpoint_id], "observed_facts": ["login exists."],
        "reasoning": "Evidence supports review.",
        "verification_status": "unverified",
        "next_manual_steps": ["Inspect manually."]}],
        "recommendations": []})


def test_pipeline_dynamic_scope(tmp_path):
    result = run_pipeline(
        scan_id="dyn-1", target="target-a.example", active_policy=_lab_policy(),
        base=tmp_path, runners=_mock_runners(_fx()), ai_generate_fn=_ai_fn)
    assert result.status == "completed"
    assert [s.stage_id for s in result.stages] == STAGE_IDS
    scope_data = json.loads((tmp_path / "data" / "processed" / "dyn-1"
                             / "scope.json").read_text())
    assert scope_data["root_domain"] == "target-a.example"
    assert result.asset_count == 2
    assert result.findings_count == 1


def test_pipeline_two_roots_isolated(tmp_path):
    first = run_pipeline(
        scan_id="iso-a", target="target-a.example", active_policy=_lab_policy(),
        base=tmp_path, runners=_mock_runners(_fx()), ai_generate_fn=_ai_fn)
    assert first.status == "completed"
    # Same tool outputs run under a different root: target-a discoveries are
    # all out of scope there. The second scan may only contain its own
    # authorized root (target-b.example) — never any target-a host. This
    # exercises the stage that stops tool output referencing different hosts
    # from becoming assets in another scan.
    quiet_ai = lambda system, user: '{"findings": [], "recommendations": []}'
    second = run_pipeline(
        scan_id="iso-b", target="target-b.example", active_policy=_lab_policy(),
        base=tmp_path, runners=_mock_runners(_fx()), ai_generate_fn=quiet_ai)
    assets = json.loads((tmp_path / "data" / "processed" / "iso-b"
                         / "asset_list.json").read_text())["assets"]
    hostnames = [str(a.get("hostname")) for a in assets]
    assert all(h == "target-b.example" or h.endswith(".target-b.example")
               for h in hostnames)
    assert all("target-a.example" not in h for h in hostnames)
    assert second.status == "completed"


def test_resume_preserves_original_scope(tmp_path):
    result = run_pipeline(
        scan_id="rs-1", target="target-a.example", active_policy=_lab_policy(),
        base=tmp_path, runners=_mock_runners(_fx()), ai_generate_fn=_ai_fn)
    assert result.status == "completed"
    # Tamper the persisted scope, then resume: must fail, never silently switch.
    scope_file = tmp_path / "data" / "processed" / "rs-1" / "scope.json"
    data = json.loads(scope_file.read_text())
    data["root_domain"] = "other.example"
    scope_file.write_text(json.dumps(data))
    resumed = run_pipeline(
        scan_id="rs-1", target="target-a.example", active_policy=_lab_policy(),
        base=tmp_path, runners=_mock_runners(_fx()), ai_generate_fn=_ai_fn,
        resume=True)
    assert resumed.status == "failed"
    assert any(s.stage_id == "scope_validation" and s.status == "failed"
               for s in resumed.stages)
    # Untouched resume keeps the original root and completes.
    data["root_domain"] = "target-a.example"
    scope_file.write_text(json.dumps(data))
    resumed_ok = run_pipeline(
        scan_id="rs-1", target="target-a.example", active_policy=_lab_policy(),
        base=tmp_path, runners=_mock_runners(_fx()), ai_generate_fn=_ai_fn,
        resume=True)
    assert resumed_ok.status == "completed"


# -- API ---------------------------------------------------------------------------

def _api_client(monkeypatch):
    from fastapi.testclient import TestClient

    import backend.app.api.routes.scans as scans_module
    from backend.main import app

    from backend.app.orchestrator.pipeline import PipelineResult

    def _fake_pipeline(scan_id, target, should_stop=None, **kw):
        return PipelineResult(scan_id=scan_id, target=target, status="completed",
                              report_path="")

    manager = scans_module.JobManager(pipeline_fn=_fake_pipeline)
    monkeypatch.setattr(scans_module, "job_manager", manager)
    return TestClient(app)


def test_api_create_dynamic_root(monkeypatch):
    client = _api_client(monkeypatch)
    response = client.post("/api/scans", json={"target": "target-c.example"})
    assert response.status_code == 202
    body = response.json()
    assert body["root_domain"] == "target-c.example"
    assert "target-c.example" in body["scope"]["allows"]


def test_api_preflight_effective_scope(monkeypatch):
    client = _api_client(monkeypatch)
    response = client.post("/api/scans/preflight", json={"target": "target-c.example"})
    assert response.status_code == 200
    body = response.json()
    assert body["scope_allowed"] is True
    assert body["effective_scope"]["root_domain"] == "target-c.example"


def test_api_rejects_malformed_and_localhost(monkeypatch):
    client = _api_client(monkeypatch)
    for bad in ("", "localhost", "127.0.0.1", "not a host!!"):
        assert client.post("/api/scans", json={"target": bad}).status_code == 422, bad
