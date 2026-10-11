"""Phase 5 tests: DNS + live HTTP discovery — mocked only, zero real network."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.tool_manager import PROJECTDISCOVERY_HTTPX_EXE
from backend.app.recon.discovery.httpx import (
    build_httpx_command,
    get_httpx_executable,
    parse_httpx_output,
    run_httpx,
)
from backend.app.recon.discovery.live_hosts import (
    build_live_evidence,
    correlate_dns_http,
    run_live_discovery,
)
from backend.app.recon.dns.dnsx import (
    build_dnsx_command,
    get_dnsx_executable,
    parse_dnsx_output,
    run_dnsx,
)
from backend.app.safety.exceptions import ScopeViolationError
from backend.app.safety.execution_policy import check_execution_policy
from backend.app.safety.scope_validator import ScopeConfig


def _lab_config() -> ScopeConfig:
    return ScopeConfig(
        allowed_domains=["example.lab"],
        allowed_subdomains=["www.example.lab", "api.example.lab", "mail.example.lab"],
        allowed_ips=[], allowed_cidrs=[],
    )


def _fixture(*parts: str):
    return (PROJECT_ROOT / "tests" / "fixtures" / Path(*parts)).read_text(encoding="utf-8")


def _dns_stdout() -> str:
    return "\n".join(json.dumps(r) for r in json.loads(_fixture("dns", "dnsx_sample.json")))


def _http_stdout() -> str:
    return "\n".join(json.dumps(r) for r in json.loads(_fixture("httpx", "httpx_sample.json")))


def _ok_runner(stdout: str, code: int = 0):
    def _run(cmd, **kw):
        assert kw.get("shell") is False and isinstance(cmd, list)
        return SimpleNamespace(stdout=stdout, stderr="" if code == 0 else "err", returncode=code)

    return _run


def test_dnsx_command_construction():
    cmd = build_dnsx_command("dnsx-exe")
    assert cmd == ["dnsx-exe", "-json", "-silent", "-a", "-resp"]
    assert "dnsx" in get_dnsx_executable().lower()


def test_dnsx_output_parsing():
    res = parse_dnsx_output(_dns_stdout(), "s1")
    by_host = {r.hostname: r for r in res}
    assert by_host["www.example.lab"].resolved
    assert by_host["www.example.lab"].addresses == ["192.0.2.10"]
    assert by_host["ghost.example.lab"].resolved is False


def test_dns_record_extraction():
    res = parse_dnsx_output(_dns_stdout())
    www = next(r for r in res if r.hostname == "api.example.lab")
    assert www.record_type == "A" and www.record_value == "192.0.2.11"


def test_dns_failure_handling():
    with pytest.raises(RuntimeError):
        run_dnsx(["www.example.lab"], "s", _lab_config(), runner=_ok_runner("x", code=2))


def test_httpx_executable_selection():
    exe = get_httpx_executable()
    assert exe == PROJECTDISCOVERY_HTTPX_EXE


def test_python_httpx_protection():
    import httpx as pyhttpx

    assert "site-packages" in pyhttpx.__file__.replace("\\", "/")
    assert get_httpx_executable() != "httpx"
    assert "go" in get_httpx_executable().replace("\\", "/").lower()


def test_httpx_command_construction():
    cmd = build_httpx_command(PROJECTDISCOVERY_HTTPX_EXE)
    assert cmd[0] == PROJECTDISCOVERY_HTTPX_EXE and "-json" in cmd and "-silent" in cmd
    assert all(isinstance(a, str) for a in cmd)


def test_json_probe_parsing():
    res = parse_httpx_output(_http_stdout())
    assert len(res) == 2 and all(r.host for r in res)


def test_http_status_extraction():
    by_host = {r.host: r for r in parse_httpx_output(_http_stdout())}
    assert by_host["www.example.lab"].status_code == 200
    assert by_host["api.example.lab"].status_code == 301


def test_url_extraction():
    by_host = {r.host: r for r in parse_httpx_output(_http_stdout())}
    assert by_host["www.example.lab"].url == "https://www.example.lab"


def test_title_extraction():
    by_host = {r.host: r for r in parse_httpx_output(_http_stdout())}
    assert by_host["www.example.lab"].title == "Example Lab"


def test_webserver_extraction():
    by_host = {r.host: r for r in parse_httpx_output(_http_stdout())}
    assert by_host["www.example.lab"].webserver == "ExampleServer"


def test_technology_extraction():
    by_host = {r.host: r for r in parse_httpx_output(_http_stdout())}
    assert "ExampleStack" in by_host["www.example.lab"].technologies


def test_live_host_aggregation():
    dns = parse_dnsx_output(_dns_stdout(), "s")
    probes = parse_httpx_output(_http_stdout())
    hosts = correlate_dns_http(dns, probes)
    assert sorted(h.hostname for h in hosts) == ["api.example.lab", "www.example.lab"]
    www = next(h for h in hosts if h.hostname == "www.example.lab")
    assert www.resolved_addresses == ["192.0.2.10"] and www.status == "live"


def test_dns_http_correlation():
    dns = parse_dnsx_output(_dns_stdout(), "s")
    probes = parse_httpx_output(_http_stdout())
    hosts = correlate_dns_http(dns, probes)
    # ghost.example.lab resolved nothing and has no probe -> excluded.
    assert "ghost.example.lab" not in [h.hostname for h in hosts]


def test_evidence_creation():
    dns = parse_dnsx_output(_dns_stdout(), "sev")
    probes = parse_httpx_output(_http_stdout())
    hosts = correlate_dns_http(dns, probes)
    ev = build_live_evidence(hosts, dns, probes, "sev")
    kinds = {(e.source.value, e.type.value) for e in ev}
    assert ("dnsx", "dns") in kinds and ("httpx", "http") in kinds
    assert all(e.raw_reference.startswith("data/raw/") for e in ev)


def test_evidence_id_assignment():
    dns = parse_dnsx_output(_dns_stdout(), "sids")
    probes = parse_httpx_output(_http_stdout())
    hosts = correlate_dns_http(dns, probes)
    ev = build_live_evidence(hosts, dns, probes, "sids")
    assert [e.id for e in ev] == [f"E{i:03d}" for i in range(1, len(ev) + 1)]
    assert all(h.evidence_ids for h in hosts)


def _never_runner(cmd, **kw):
    raise AssertionError("tool must not execute for out-of-scope input")


def test_scope_enforcement():
    run = run_dnsx(["evil.com"], "s", _lab_config(), runner=_never_runner)
    assert run.results == []
    assert any(r["value"] == "evil.com" for r in run.rejected)
    run2 = run_httpx(["evil.com"], "s", _lab_config(), runner=_never_runner)
    assert run2.results == []
    assert any(r["value"] == "evil.com" for r in run2.rejected)
    run3 = run_dnsx(["www.example.lab", "evil.com"], "s", _lab_config(),
                    runner=_ok_runner(_dns_stdout()))
    assert any(r["value"] == "evil.com" for r in run3.rejected)
    assert all(r.hostname != "evil.com" for r in run3.results)


def test_raw_checkpointing(tmp_path):
    asset_list = {"scan_id": "a1", "target": "example.lab",
                  "assets": [{"hostname": "www.example.lab"}, {"hostname": "api.example.lab"}]}
    res = run_live_discovery("s-check", asset_list, _lab_config(),
                             _ok_runner(_dns_stdout()), _ok_runner(_http_stdout()),
                             tmp_path)
    assert (tmp_path / "data" / "raw" / "dns" / "s-check" / "dnsx.json").exists()
    assert (tmp_path / "data" / "raw" / "httpx" / "s-check" / "httpx.json").exists()
    assert (tmp_path / "data" / "processed" / "live_hosts.json").exists()
    assert len(res.checkpoint["output_files"]) == 3


def test_scan_id_separation(tmp_path):
    asset_list = {"scan_id": "a1", "target": "example.lab",
                  "assets": [{"hostname": "www.example.lab"}]}
    r1 = run_live_discovery("scan-A", asset_list, _lab_config(),
                            _ok_runner(_dns_stdout()), _ok_runner(_http_stdout()), tmp_path)
    r2 = run_live_discovery("scan-B", asset_list, _lab_config(),
                            _ok_runner(_dns_stdout()), _ok_runner(_http_stdout()), tmp_path)
    assert (tmp_path / "data" / "raw" / "dns" / "scan-A").exists()
    assert (tmp_path / "data" / "raw" / "dns" / "scan-B").exists()
    assert r1.evidence[0].raw_reference != r2.evidence[0].raw_reference


def test_command_injection_resistance():
    from backend.app.safety.gate import authorize_tool_execution

    # The gate itself rejects shell metacharacters outright.
    with pytest.raises(Exception):
        authorize_tool_execution("example.lab; rm -rf /", "dns_resolution", _lab_config())
    with pytest.raises(Exception):
        authorize_tool_execution("$(whoami)", "http_discovery", _lab_config())
    # Batch wrappers never execute the tool for such input — they reject it.
    r1 = run_dnsx(["example.lab; rm -rf /"], "s", _lab_config(), runner=_never_runner)
    assert r1.results == [] and len(r1.rejected) == 1
    r2 = run_httpx(["$(whoami)"], "s", _lab_config(), runner=_never_runner)
    assert r2.results == [] and len(r2.rejected) == 1


def test_malformed_output_handling():
    assert parse_dnsx_output("not json\n{\"host\": \"www.example.lab\", \"a\": [\"192.0.2.10\"]}\n")[
        0
    ].hostname == "www.example.lab"
    assert parse_httpx_output("garbage\n" + _http_stdout().splitlines()[0]) != []
