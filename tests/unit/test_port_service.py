"""Phase 6 tests: port/service discovery — mocked only, zero real scanning."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.recon.ports.aggregator import (
    correlate_ports_services,
    run_port_service_discovery,
)
from backend.app.recon.ports.naabu import (
    build_naabu_command,
    get_naabu_executable,
    parse_naabu_output,
    run_naabu,
)
from backend.app.recon.ports.nmap import (
    build_nmap_command,
    get_nmap_executable,
    parse_nmap_xml,
    run_nmap,
)
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
        scan_id="lab", approved_by="test-harness", reason="phase 6 unit test"))


def _fixture(*parts: str) -> str:
    return (PROJECT_ROOT / "tests" / "fixtures" / Path(*parts)).read_text(encoding="utf-8")


def _naabu_stdout() -> str:
    return "\n".join(json.dumps(r) for r in json.loads(_fixture("ports", "naabu_sample.json")))


def _ok_runner(stdout: str, code: int = 0):
    def _run(cmd, **kw):
        assert kw.get("shell") is False and isinstance(cmd, list)
        return SimpleNamespace(stdout=stdout, stderr="" if code == 0 else "err", returncode=code)

    return _run


def _live_hosts() -> dict:
    return {"scan_id": "live-1", "target": "example.lab",
            "hosts": [{"hostname": "api.example.lab"}, {"hostname": "www.example.lab"}]}


def test_naabu_command_construction():
    cmd = build_naabu_command("naabu-exe", "api.example.lab")
    assert cmd == ["naabu-exe", "-host", "api.example.lab", "-json", "-silent", "-top-ports", "100"]


def test_naabu_executable_selection():
    assert "naabu" in get_naabu_executable().lower()


def test_naabu_json_parsing():
    ports = parse_naabu_output(_naabu_stdout(), "api.example.lab")
    assert [(p.port, p.protocol, p.status) for p in ports] == [
        (22, "tcp", "open"), (80, "tcp", "open"),
        (443, "tcp", "open"), (443, "tcp", "open"),
    ]


def test_naabu_deduplicates_identical_lines():
    stdout = ('{"host": "h", "ip": "192.0.2.1", "port": 443, "protocol": "tcp"}\n'
              '{"host": "h", "ip": "192.0.2.1", "port": 443, "protocol": "tcp"}\n'
              '{"host": "h", "ip": "192.0.2.2", "port": 443, "protocol": "tcp"}')
    ports = parse_naabu_output(stdout, "h")
    # Same host/port/proto/ip collapses; distinct IPs are kept as observations.
    assert [(p.port, p.ip) for p in ports] == [(443, "192.0.2.1"), (443, "192.0.2.2")]


def test_naabu_failure_handling():
    run = run_naabu(["api.example.lab"], "s", _lab_config(), _lab_policy(),
                    runner=_ok_runner("x", code=1))
    assert run.results == [] and any("api.example.lab" in r["value"] for r in run.rejected)


def test_nmap_command_construction():
    cmd = build_nmap_command("nmap", "api.example.lab", [443, 22, 80])
    assert cmd == ["nmap", "-sV", "-p", "22,80,443", "-oX", "-", "api.example.lab"]
    assert "-A" not in cmd and not any("script" in a for a in cmd)


def test_nmap_executable_selection():
    assert get_nmap_executable().strip() != ""


def test_nmap_xml_parsing():
    recs = parse_nmap_xml(_fixture("nmap", "nmap_sample.xml"))
    assert len(recs) == 4


def test_open_port_parsing():
    recs = parse_nmap_xml(_fixture("nmap", "nmap_sample.xml"))
    assert all(r.state == "open" for r in recs)
    assert {r.port for r in recs} == {22, 80, 443}


def test_service_parsing():
    by_port = {r.port: r for r in parse_nmap_xml(_fixture("nmap", "nmap_sample.xml")) if r.host != "www.example.lab" or True}
    recs = [r for r in parse_nmap_xml(_fixture("nmap", "nmap_sample.xml")) if r.port == 443 and r.address == "192.0.2.11"]
    assert recs[0].service_name == "https"


def test_product_parsing():
    recs = [r for r in parse_nmap_xml(_fixture("nmap", "nmap_sample.xml")) if r.port == 22]
    assert recs[0].product == "OpenSSH"


def test_version_parsing():
    recs = [r for r in parse_nmap_xml(_fixture("nmap", "nmap_sample.xml")) if r.port == 22]
    assert recs[0].version == "9.0"


def test_unknown_version_handling():
    recs = [r for r in parse_nmap_xml(_fixture("nmap", "nmap_sample.xml"))
            if r.port == 443 and r.address == "192.0.2.10"]
    assert recs[0].product == "" and recs[0].version == ""
    recs80 = [r for r in parse_nmap_xml(_fixture("nmap", "nmap_sample.xml")) if r.port == 80]
    assert recs80[0].product == "ExampleServer" and recs80[0].version == ""


def _naabu_host_runner():
    """Mock naabu honoring -host: only lines for the requested host are returned."""

    def _run(cmd, **kw):
        assert kw.get("shell") is False and isinstance(cmd, list)
        host = cmd[cmd.index("-host") + 1] if "-host" in cmd else ""
        lines = []
        for line in _naabu_stdout().splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("host") == host:
                lines.append(line)
        return SimpleNamespace(stdout="\n".join(lines), stderr="", returncode=0)

    return _run


def test_naabu_nmap_handoff(tmp_path):
    res = run_port_service_discovery(
        "s-handoff", _live_hosts(), _lab_config(), _lab_policy(),
        _naabu_host_runner(), _ok_runner(_fixture("nmap", "nmap_sample.xml")),
        tmp_path)
    api = next(h for h in res.hosts if h.hostname == "api.example.lab")
    assert sorted(p.port for p in api.ports) == [22, 80, 443]
    assert any(p.service == "https" for p in api.ports)


def test_live_hosts_input_enforcement(tmp_path):
    res = run_port_service_discovery(
        "s-live", {"scan_id": "x", "target": "example.lab",
                   "assets": [{"hostname": "www.example.lab"}]},
        _lab_config(), _lab_policy(),
        _ok_runner(_naabu_stdout()), _ok_runner(_fixture("nmap", "nmap_sample.xml")),
        tmp_path)
    # live_hosts.json uses "hosts", not "assets" — nothing to scan.
    assert res.hosts == []


def test_scope_enforcement():
    def _never(cmd, **kw):
        raise AssertionError("must not execute for out-of-scope input")

    run = run_naabu(["evil.com"], "s", _lab_config(), _lab_policy(), runner=_never)
    assert run.results == [] and len(run.rejected) == 1
    run2 = run_nmap({"evil.com": [80]}, "s", _lab_config(), _lab_policy(), runner=_never)
    assert run2.results == [] and len(run2.rejected) == 1


def test_active_scan_policy_enforcement():
    def _never(cmd, **kw):
        raise AssertionError("active scan must not execute without explicit policy")

    # Default policy denies active scans: hosts are rejected, tool never runs.
    run = run_naabu(["api.example.lab"], "s", _lab_config(), None, runner=_never)
    assert run.results == [] and len(run.rejected) == 1
    run2 = run_nmap({"api.example.lab": [443]}, "s", _lab_config(), None, runner=_never)
    assert run2.results == [] and len(run2.rejected) == 1


def test_default_active_scan_denial():
    d = check_execution_policy("active_port_scan")
    assert d.allowed is False
    d2 = check_execution_policy("port_discovery")
    assert d2.allowed is False


def test_explicit_authorization_behavior():
    pol = _lab_policy()
    assert check_execution_policy("active_port_scan", pol).allowed is True
    import pydantic

    with pytest.raises((ExecutionPolicyError, pydantic.ValidationError)):
        lab_active_scan_policy(ActiveScanAuthorization(scan_id="", approved_by="x", reason="y"))


def test_command_injection_resistance():
    def _never(cmd, **kw):
        raise AssertionError("must not execute")

    for bad in ["evil.com;whoami", "$(whoami)", "evil.com && whoami", "evil.com -p 80"]:
        r = run_naabu([bad], "s", _lab_config(), _lab_policy(), runner=_never)
        assert r.results == []
        r2 = run_nmap({bad: [80]}, "s", _lab_config(), _lab_policy(), runner=_never)
        assert r2.results == []


def test_evidence_creation(tmp_path):
    res = run_port_service_discovery(
        "s-ev", _live_hosts(), _lab_config(), _lab_policy(),
        _ok_runner(_naabu_stdout()), _ok_runner(_fixture("nmap", "nmap_sample.xml")),
        tmp_path)
    kinds = {(e.source.value, e.type.value) for e in res.evidence}
    assert ("naabu", "port") in kinds and ("nmap", "service") in kinds
    assert all(e.status.value == "observed" for e in res.evidence)


def test_evidence_ids(tmp_path):
    res = run_port_service_discovery(
        "s-ids", _live_hosts(), _lab_config(), _lab_policy(),
        _ok_runner(_naabu_stdout()), _ok_runner(_fixture("nmap", "nmap_sample.xml")),
        tmp_path)
    assert [e.id for e in res.evidence] == [f"E{i:03d}" for i in range(1, len(res.evidence) + 1)]


def test_port_service_correlation():
    from backend.app.recon.ports.naabu import OpenPort
    ports = [OpenPort(host="h", port=443, protocol="tcp", status="open"),
             OpenPort(host="h", port=22, protocol="tcp", status="open")]
    recs = [r for r in parse_nmap_xml(_fixture("nmap", "nmap_sample.xml")) if r.address == "192.0.2.11"]
    entries = correlate_ports_services(ports, [r for r in recs if r.port in (443, 22)])
    by_port = {e.port: e for e in entries}
    assert by_port[443].service == "https" and by_port[22].product == "OpenSSH"


def test_raw_checkpointing(tmp_path):
    res = run_port_service_discovery(
        "s-raw", _live_hosts(), _lab_config(), _lab_policy(),
        _ok_runner(_naabu_stdout()), _ok_runner(_fixture("nmap", "nmap_sample.xml")),
        tmp_path)
    assert (tmp_path / "data" / "raw" / "ports" / "s-raw" / "naabu.json").exists()
    assert (tmp_path / "data" / "raw" / "nmap" / "s-raw" / "nmap.xml").exists()
    assert len(res.checkpoint["output_files"]) == 3


def test_processed_json(tmp_path):
    res = run_port_service_discovery(
        "s-proc", _live_hosts(), _lab_config(), _lab_policy(),
        _ok_runner(_naabu_stdout()), _ok_runner(_fixture("nmap", "nmap_sample.xml")),
        tmp_path)
    import json as j
    data = j.loads((tmp_path / "data" / "processed" / "port_service_data.json").read_text(encoding="utf-8"))
    assert data["scan_id"] == "s-proc"
    api = next(h for h in data["hosts"] if h["hostname"] == "api.example.lab")
    assert any(p["port"] == 443 and p["service"] == "https" for p in api["ports"])
    assert "<nmaprun" not in (tmp_path / "data" / "processed" / "port_service_data.json").read_text()


def test_scan_id_separation(tmp_path):
    kw = dict(config=_lab_config(), policy=_lab_policy(),
              naabu_runner=_ok_runner(_naabu_stdout()),
              nmap_runner=_ok_runner(_fixture("nmap", "nmap_sample.xml")), base=tmp_path)
    r1 = run_port_service_discovery("scan-A", _live_hosts(), **kw)
    r2 = run_port_service_discovery("scan-B", _live_hosts(), **kw)
    assert (tmp_path / "data" / "raw" / "ports" / "scan-A").exists()
    assert (tmp_path / "data" / "raw" / "ports" / "scan-B").exists()
    assert r1.evidence[0].raw_reference != r2.evidence[0].raw_reference


def test_partial_host_failure(tmp_path):
    def flaky(cmd, **kw):
        if "www.example.lab" in cmd:
            return SimpleNamespace(stdout="", stderr="boom", returncode=1)
        return SimpleNamespace(stdout=_naabu_stdout(), stderr="", returncode=0)

    res = run_port_service_discovery(
        "s-partial", _live_hosts(), _lab_config(), _lab_policy(), flaky,
        _ok_runner(_fixture("nmap", "nmap_sample.xml")), tmp_path)
    assert any(h.hostname == "api.example.lab" for h in res.hosts)
    assert any("www.example.lab" in r["value"] for r in res.rejected)


def test_malformed_naabu_output():
    ports = parse_naabu_output("garbage\n{\"port\": 99999}\n{\"host\": \"h\", \"port\": 80}\n", "h")
    assert [(p.port) for p in ports] == [80]


def test_malformed_nmap_xml():
    with pytest.raises(ValueError):
        parse_nmap_xml("<nmaprun><broken", "h")
    assert parse_nmap_xml('<?xml version="1.0"?><nmaprun></nmaprun>', "h") == []
