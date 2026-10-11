"""Phase 8 tests: nuclei + NVD + KEV + verified context — mocked, no scans."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.enrichment.cisa_kev import check_kev, parse_kev_catalog
from backend.app.enrichment.correlator import (
    cves_from_finding,
    extract_cve_ids,
    run_verification,
    validate_verified_context,
)
from backend.app.enrichment.nuclei import (
    build_nuclei_command,
    get_nuclei_executable,
    parse_nuclei_output,
    run_nuclei,
)
from backend.app.enrichment.nvd import build_nvd_url, lookup_cve, parse_nvd_response
from backend.app.safety.exceptions import ExecutionPolicyError
from backend.app.safety.execution_policy import (
    ActiveScanAuthorization,
    check_execution_policy,
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
        scan_id="lab", approved_by="test-harness", reason="phase 8 unit test"))


def _fixture(*parts: str) -> str:
    return (PROJECT_ROOT / "tests" / "fixtures" / Path(*parts)).read_text(encoding="utf-8")


def _ok_runner(stdout: str, code: int = 0):
    def _run(cmd, **kw):
        assert kw.get("shell") is False and isinstance(cmd, list)
        return SimpleNamespace(stdout=stdout, stderr="" if code == 0 else "err", returncode=code)

    return _run


def _never_runner(cmd, **kw):
    raise AssertionError("tool must not execute without authorization")


def _nuclei_stdout() -> str:
    return _fixture("nuclei", "nuclei_sample.jsonl")


def _nvd_fetcher(url: str, timeout: int) -> str:
    assert "services.nvd.nist.gov" in url
    return _fixture("nvd", "nvd_sample.json")


def _kev_fetcher(url: str, timeout: int) -> str:
    assert "cisa.gov" in url
    return _fixture("cisa_kev", "kev_sample.json")


def test_nuclei_command():
    cmd = build_nuclei_command("nuclei-exe")
    assert cmd[:4] == ["nuclei-exe", "-jsonl", "-silent", "-nc"]
    assert "-severity" in cmd and "medium,high,critical" in cmd
    assert "-etags" in cmd and "intrusive" in ",".join(cmd)
    assert all(isinstance(a, str) for a in cmd)


def test_nuclei_exe():
    assert "nuclei" in get_nuclei_executable().lower()


def test_scope_enforcement():
    run = run_nuclei(["evil.com"], "s", _lab_config(), _lab_policy(), runner=_never_runner)
    assert run.results == [] and len(run.rejected) == 1


def test_active_policy():
    assert check_execution_policy("vulnerability_verification").allowed is False
    assert check_execution_policy("nuclei_verification").allowed is False
    assert check_execution_policy("vulnerability_verification", _lab_policy()).allowed is True


def test_jsonl_parsing():
    findings = parse_nuclei_output(_nuclei_stdout(), "example.lab")
    assert len(findings) == 3
    assert all(f.template_id for f in findings)


def test_missing_fields():
    findings = parse_nuclei_output('{"template-id": "x/y", "host": "h"}', "t")
    assert findings[0].severity == "" and findings[0].cve_ids == []
    assert parse_nuclei_output("garbage\n", "t") == []


def test_severity():
    by_tpl = {f.template_id: f for f in parse_nuclei_output(_nuclei_stdout(), "t")}
    assert by_tpl["http/server-header"].severity == "info"
    assert by_tpl["ssl/tls-version"].severity == "low"


def test_template_id():
    findings = parse_nuclei_output(_nuclei_stdout(), "t")
    assert "http/cves/2026/CVE-2026-90001.yaml" in [f.template_id for f in findings]


def test_matched_url():
    findings = parse_nuclei_output(_nuclei_stdout(), "t")
    cve = next(f for f in findings if f.cve_ids)
    assert cve.matched_at == "https://www.example.lab/login"


def test_cve_extraction():
    findings = parse_nuclei_output(_nuclei_stdout(), "t")
    cve = next(f for f in findings if f.cve_ids)
    assert cve.cve_ids == ["CVE-2026-90001"]


def test_invalid_cve_rejection():
    assert extract_cve_ids("CVE-123-45 CVE-ABCD-EFGH nginx 1.x") == []
    assert extract_cve_ids("cve-2026-90001 and CVE-2026-90001") == ["CVE-2026-90001"]


def test_nvd_request_construction(monkeypatch):
    import urllib.request as urlrequest

    from backend.app.enrichment import nvd as nvd_module

    seen: dict[str, str] = {}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"totalResults": 0}'

    def _fake_open(req, timeout=30):
        seen["url"] = req.full_url
        seen["ua"] = req.get_header("User-agent")
        seen["has_key"] = str(req.get_header("Apikey") is not None)
        return _Resp()

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(urlrequest, "urlopen", _fake_open)
    nvd_module.lookup_cve("CVE-2026-90001")
    assert "cveId=CVE-2026-90001" in seen["url"]
    assert "TraceHoundAI" in seen["ua"]
    assert seen["has_key"] == "False"
    monkeypatch.setenv("NVD_API_KEY", "test-key-123")
    nvd_module.lookup_cve("CVE-2026-90001")
    assert seen["has_key"] == "True"


def test_nvd_url():
    url = build_nvd_url("cve-2026-90001")
    assert "services.nvd.nist.gov" in url and "CVE-2026-90001" in url


def test_nvd_parsing():
    ctx, _ = lookup_cve("CVE-2026-90001", fetcher=_nvd_fetcher)
    assert ctx.nvd_status == "confirmed_by_nvd"
    assert ctx.cvss_score == 7.5 and ctx.severity == "high"
    assert ctx.references == ["https://example.lab/advisories/LAB-90001"]


def test_nvd_not_found():
    ctx, _ = lookup_cve("CVE-2026-99999", fetcher=lambda u, t: '{"totalResults": 0}')
    assert ctx.nvd_status == "not_found" and ctx.cvss_score is None


def test_nvd_failure():
    def _boom(url, timeout):
        raise TimeoutError("nvd down")

    with pytest.raises(TimeoutError):
        lookup_cve("CVE-2026-90001", fetcher=_boom)


def test_kev_parsing():
    ctx, _ = check_kev("CVE-2026-90001", catalog_text=_fixture("cisa_kev", "kev_sample.json"))
    assert ctx.known_exploited is True and ctx.kev_status == "listed"
    assert ctx.vendor_project == "Example"


def test_kev_present():
    ctx, _ = check_kev("CVE-2026-90001", catalog_text=_fixture("cisa_kev", "kev_sample.json"))
    assert ctx.date_added == "2026-02-01" and ctx.due_date == "2026-03-01"


def test_kev_absent():
    ctx, _ = check_kev("CVE-2026-99999", catalog_text=_fixture("cisa_kev", "kev_sample.json"))
    assert ctx.known_exploited is False and ctx.kev_status == "not_listed"


def test_kev_failure():
    with pytest.raises(ConnectionError):
        check_kev("CVE-2026-90001", fetcher=lambda u, t: (_ for _ in ()).throw(
            ConnectionError("kev down")))


def test_cve_correlation():
    findings = parse_nuclei_output(_nuclei_stdout(), "t")
    assert cves_from_finding(next(f for f in findings if f.cve_ids)) == ["CVE-2026-90001"]
    plain = next(f for f in findings if f.template_id == "ssl/tls-version")
    assert cves_from_finding(plain) == []


def test_evidence_integration(tmp_path):
    ctx = run_verification(
        "s-ev", ["https://www.example.lab"], _lab_config(), _lab_policy(),
        _ok_runner(_nuclei_stdout()), _nvd_fetcher, _kev_fetcher, tmp_path)
    assert len(ctx.evidence) >= 1
    assert all(e.source.value == "nuclei" and e.type.value == "vulnerability"
               for e in ctx.evidence)
    assert all(e.status.value == "observed" for e in ctx.evidence)


def test_verified_context(tmp_path):
    ctx = run_verification(
        "s-vc", ["https://www.example.lab"], _lab_config(), _lab_policy(),
        _ok_runner(_nuclei_stdout()), _nvd_fetcher, _kev_fetcher, tmp_path)
    assert len(ctx.findings) == 1
    f = ctx.findings[0]
    assert f.cve_id == "CVE-2026-90001" and f.scanner_observed is True
    assert f.nvd_confirmed is True and f.known_exploited is True
    data = json.loads((tmp_path / "data" / "processed" / "verified_context.json").read_text())
    assert data["findings"][0]["cve_id"] == "CVE-2026-90001"


def test_traceability(tmp_path):
    ctx = run_verification(
        "s-tr", ["https://www.example.lab"], _lab_config(), _lab_policy(),
        _ok_runner(_nuclei_stdout()), _nvd_fetcher, _kev_fetcher, tmp_path)
    known = {e.id for e in ctx.evidence}
    for f in ctx.findings:
        assert f.evidence_ids and set(f.evidence_ids) <= known
    assert validate_verified_context(ctx) == []


def test_no_llm():
    pkg = PROJECT_ROOT / "backend" / "app" / "enrichment"
    for py in pkg.glob("*.py"):
        text = py.read_text(encoding="utf-8").lower()
        for term in ("langchain", "ollama", "openai", "qwen", "transformers", "crewai"):
            assert term not in text, f"{py.name} must not depend on {term}"


def test_checkpoints(tmp_path):
    ctx = run_verification(
        "s-ck", ["https://www.example.lab"], _lab_config(), _lab_policy(),
        _ok_runner(_nuclei_stdout()), _nvd_fetcher, _kev_fetcher, tmp_path)
    assert (tmp_path / "data" / "raw" / "nuclei" / "s-ck" / "nuclei.jsonl").exists()
    assert (tmp_path / "data" / "raw" / "nvd" / "s-ck").exists()
    assert (tmp_path / "data" / "raw" / "cisa_kev" / "s-ck" / "kev.json").exists()
    assert len(ctx.checkpoint["output_files"]) >= 2


def test_scan_id_separation(tmp_path):
    kw = dict(config=_lab_config(), policy=_lab_policy(),
              nuclei_runner=_ok_runner(_nuclei_stdout()),
              nvd_fetcher=_nvd_fetcher, kev_fetcher=_kev_fetcher, base=tmp_path)
    r1 = run_verification("scan-A", ["https://www.example.lab"], **kw)
    r2 = run_verification("scan-B", ["https://www.example.lab"], **kw)
    assert (tmp_path / "data" / "raw" / "nuclei" / "scan-A").exists()
    assert (tmp_path / "data" / "raw" / "nuclei" / "scan-B").exists()
    assert r1.evidence[0].raw_reference != r2.evidence[0].raw_reference


def test_partial_failure(tmp_path):
    def _nvd_flaky(url, timeout):
        raise TimeoutError("nvd down")

    ctx = run_verification(
        "s-pf", ["https://www.example.lab"], _lab_config(), _lab_policy(),
        _ok_runner(_nuclei_stdout()), _nvd_flaky, _kev_fetcher, tmp_path)
    f = ctx.findings[0]
    assert f.nvd_status == "unavailable" and f.nvd_confirmed is False
    assert f.scanner_observed is True
    assert any("NVD unavailable" in r["reason"] for r in ctx.rejected)


def test_secrets():
    src = (PROJECT_ROOT / "backend" / "app" / "enrichment" / "nvd.py").read_text()
    assert "os.environ.get(\"NVD_API_KEY" in src
    assert 'apiKey = "' not in src and "apiKey = '" not in src
    assert "nvd_api_key =" not in src.lower()


def test_injection(tmp_path):
    def _never(cmd, **kw):
        raise AssertionError("must not execute")

    for bad in ["evil.com;whoami", "$(whoami)", "evil.com && whoami"]:
        run = run_nuclei([bad], "s", _lab_config(), _lab_policy(), runner=_never)
        assert run.results == [] and len(run.rejected) == 1


def test_nuclei_timeout_salvages_partial_output():
    import subprocess
    from types import SimpleNamespace

    partial = ('{"template-id": "http/misconfig", "host": "www.example.lab", '
               '"matched-at": "https://www.example.lab", "type": "http"}\n')

    def _hang(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, timeout=1, output=partial.encode())

    run = run_nuclei(["www.example.lab"], "s", _lab_config(), _lab_policy(),
                     runner=_hang)
    assert len(run.results) == 1
    assert run.results[0].findings[0].template_id == "http/misconfig"
    assert any("timed out" in r["reason"] for r in run.rejected)


def test_nuclei_timeout_without_output_fails_cleanly():
    import subprocess

    def _hang(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, timeout=1)

    run = run_nuclei(["www.example.lab"], "s", _lab_config(), _lab_policy(),
                     runner=_hang)
    assert run.results[0].findings == []
    assert any("timed out" in r["reason"] for r in run.rejected)

