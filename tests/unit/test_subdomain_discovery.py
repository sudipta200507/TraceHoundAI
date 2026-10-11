"""Phase 4 tests: passive subdomain discovery — mocked only, no real recon."""

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.recon.subdomain.aggregator import (
    aggregate,
    build_evidence,
    normalize_hostname,
    run_discovery,
    write_asset_list,
    write_raw_checkpoint,
)
from backend.app.recon.subdomain.crtsh import parse_crtsh_response, query_crtsh
from backend.app.recon.subdomain.subfinder import (
    build_subfinder_command,
    get_subfinder_executable,
    parse_subfinder_output,
    run_subfinder,
)
from backend.app.safety.exceptions import ScopeViolationError
from backend.app.safety.execution_policy import check_execution_policy
from backend.app.safety.scope_validator import ScopeConfig


def _lab_config() -> ScopeConfig:
    return ScopeConfig(
        allowed_domains=["example.lab"],
        allowed_subdomains=[
            "www.example.lab",
            "app.example.lab",
            "api.example.lab",
            "mail.example.lab",
        ],
        allowed_ips=[],
        allowed_cidrs=[],
    )


def _fixture(name: str):
    return json.loads(
        (PROJECT_ROOT / "tests" / "fixtures" / "subdomain" / name).read_text(
            encoding="utf-8"
        )
    )


def _mock_runner(stdout: str, code: int = 0):
    def _run(cmd, **kw):
        assert kw.get("shell") is False
        assert isinstance(cmd, list)
        return SimpleNamespace(stdout=stdout, stderr="" if code == 0 else "boom", returncode=code)

    return _run


def test_subfinder_command_construction():
    cmd = build_subfinder_command("subfinder-exe", "example.lab")
    assert cmd == ["subfinder-exe", "-d", "example.lab", "-silent"]
    assert all(isinstance(a, str) for a in cmd)


def test_subfinder_result_parsing():
    assert parse_subfinder_output("a.example.lab\n\n  b.example.lab  \n") == [
        "a.example.lab",
        "b.example.lab",
    ]


def test_crtsh_response_parsing():
    raw = json.dumps(_fixture("crtsh_sample.json"))
    hosts = parse_crtsh_response(raw)
    assert "www.example.lab" in hosts and "mail.example.lab" in hosts
    assert hosts == sorted(hosts) and len(hosts) == len(set(hosts))


def test_wildcard_removal():
    assert normalize_hostname("*.example.lab") == "example.lab"
    raw = json.dumps([{"name_value": "*.example.lab"}])
    assert parse_crtsh_response(raw) == ["example.lab"]


def test_hostname_normalization():
    assert normalize_hostname("WWW.Example.LAB") == "www.example.lab"
    assert normalize_hostname("www.example.lab.") == "www.example.lab"
    assert normalize_hostname("  api.example.lab  ") == "api.example.lab"


def test_deduplication():
    assets, _ = aggregate(
        ["api.example.lab", "www.example.lab"], ["api.example.lab", "mail.example.lab"],
        "example.lab", _lab_config(),
    )
    assert sorted(a.hostname for a in assets) == [
        "api.example.lab", "mail.example.lab", "www.example.lab",
    ]


def test_source_provenance():
    assets, _ = aggregate(["api.example.lab"], ["api.example.lab"], "example.lab", _lab_config())
    assert assets[0].sources == ["crtsh", "subfinder"]
    assets2, _ = aggregate(["api.example.lab"], [], "example.lab", _lab_config())
    assert assets2[0].sources == ["subfinder"]


def test_scope_filtering():
    assets, _ = aggregate(
        ["www.example.lab", "app.example.lab"], [], "example.lab", _lab_config()
    )
    assert {a.hostname for a in assets} == {"www.example.lab", "app.example.lab"}


def test_out_of_scope_rejection():
    assets, rejected = aggregate(
        ["evil.com", "example.lab.attacker.com"], ["evil.com"], "example.lab", _lab_config()
    )
    assert assets == []
    assert {r.value for r in rejected} >= {"evil.com", "example.lab.attacker.com"}


def test_evidence_creation():
    assets, _ = aggregate(["api.example.lab"], ["api.example.lab"], "example.lab", _lab_config())
    ev = build_evidence(assets, "scan-test")
    assert len(ev) == 2 and all(e.status.value == "observed" for e in ev)
    assert {e.source.value for e in ev} == {"subfinder", "crtsh"}
    assert all(e.raw_reference.startswith("data/raw/subdomain/scan-test/") for e in ev)


def test_evidence_id_assignment():
    assets, _ = aggregate(["api.example.lab", "www.example.lab"], [], "example.lab", _lab_config())
    ev = build_evidence(assets, "scan-ids")
    assert [e.id for e in ev] == ["E001", "E002"]
    assert assets[0].evidence_ids == ["E001"]


def test_raw_checkpoint_creation(tmp_path):
    files = write_raw_checkpoint("s1", "example.lab", "a\n", ["a"], "[]", [], tmp_path)
    assert len(files) == 2
    assert (tmp_path / "data" / "raw" / "subdomain" / "s1" / "subfinder.json").exists()
    assert (tmp_path / "data" / "raw" / "subdomain" / "s1" / "crtsh.json").exists()


def test_asset_list_creation(tmp_path):
    assets, _ = aggregate(["api.example.lab"], ["api.example.lab"], "example.lab", _lab_config())
    build_evidence(assets, "s2")
    p = write_asset_list("s2", "example.lab", assets, tmp_path)
    data = json.loads(Path(p).read_text(encoding="utf-8"))
    assert data["scan_id"] == "s2" and data["assets"][0]["hostname"] == "api.example.lab"
    assert data["assets"][0]["sources"] == ["crtsh", "subfinder"]


def test_duplicate_asset_handling():
    assets, _ = aggregate(
        ["api.example.lab", "API.EXAMPLE.LAB ", "api.example.lab."],
        ["api.example.lab"], "example.lab", _lab_config(),
    )
    assert len(assets) == 1 and assets[0].sources == ["crtsh", "subfinder"]


def test_malformed_hostname_handling():
    assets, rejected = aggregate(["not a host!!", "", "a" * 300], [], "example.lab", _lab_config())
    assert assets == [] and len(rejected) >= 2


def test_command_failure_handling():
    with pytest.raises(RuntimeError):
        run_subfinder("example.lab", _lab_config(), runner=_mock_runner("x", code=1))


def test_crtsh_http_failure_handling():
    def _boom(url, timeout):
        raise ConnectionError("down")

    with pytest.raises(RuntimeError):
        query_crtsh("example.lab", _lab_config(), fetcher=_boom)


def test_crtsh_transient_failure_retried():
    calls = {"n": 0}

    def _flaky(url, timeout):
        calls["n"] += 1
        if calls["n"] < 3:
            raise TimeoutError("transient")
        return '[{"name_value": "www.example.lab"}]'

    result = query_crtsh("example.lab", _lab_config(), fetcher=_flaky)
    assert result.hostnames == ["www.example.lab"]
    assert calls["n"] == 3


def test_safety_gate_enforcement():
    with pytest.raises(ScopeViolationError):
        run_subfinder("evil.com", _lab_config(), runner=_mock_runner("evil.com"))
    with pytest.raises(ScopeViolationError):
        query_crtsh("evil.com", _lab_config(), fetcher=lambda u, t: "[]")
    with pytest.raises(ScopeViolationError):
        aggregate(["evil.com"], [], "evil.com", _lab_config())


def test_no_shell_injection():
    with pytest.raises(Exception):
        run_subfinder("example.lab; rm -rf /", _lab_config(), runner=_mock_runner("x"))
    cmd = build_subfinder_command("exe", "example.lab")
    assert isinstance(cmd, list)


def test_scan_id_separation(tmp_path):
    def _runner(cmd, **kw):
        return SimpleNamespace(stdout="api.example.lab\n", stderr="", returncode=0)

    def fetcher(url, timeout):
        assert "crt.sh" in url
        return json.dumps([{"name_value": "api.example.lab"}])

    r1 = run_discovery("example.lab", "scan-A", _lab_config(), _runner, fetcher, tmp_path)
    r2 = run_discovery("example.lab", "scan-B", _lab_config(), _runner, fetcher, tmp_path)
    assert r1.scan_id != r2.scan_id
    assert (tmp_path / "data" / "raw" / "subdomain" / "scan-A").exists()
    assert (tmp_path / "data" / "raw" / "subdomain" / "scan-B").exists()
    assert r1.evidence[0].raw_reference != r2.evidence[0].raw_reference
    assert r1.checkpoint["status"] == "completed" and "output_files" in r1.checkpoint


def test_passive_discovery_allowed_by_policy():
    assert check_execution_policy("passive_discovery").allowed is True
    assert check_execution_policy("active").allowed is False
    assert "subfinder" in get_subfinder_executable().lower()


def test_fixtures_are_lab_only():
    sf = _fixture("subfinder_sample.json")
    cs = _fixture("crtsh_sample.json")
    blob = json.dumps([sf, cs])
    assert "example.com" not in blob and "example.lab" in blob
