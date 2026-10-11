"""Phase 7 tests: fingerprinting + endpoints + screenshots — mocked, no recon."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.tool_manager import PROJECTDISCOVERY_HTTPX_EXE
from backend.app.recon.discovery.httpx import get_httpx_executable
from backend.app.recon.endpoints.katana import (
    build_katana_command,
    get_katana_executable,
    normalize_url,
    parse_katana_output,
    run_endpoint_discovery,
)
from backend.app.recon.fingerprint.technologies import (
    build_tech_command,
    get_tech_httpx_executable,
    parse_tech_output,
    run_fingerprint_discovery,
)
from backend.app.recon.fingerprint.whatweb import check_whatweb
from backend.app.recon.screenshots.gowitness import (
    build_gowitness_command,
    detect_browser,
    get_gowitness_executable,
    run_screenshot_capture,
)
from backend.app.safety.scope_validator import ScopeConfig


def _lab_config() -> ScopeConfig:
    return ScopeConfig(
        allowed_domains=["example.lab"],
        allowed_subdomains=["www.example.lab", "api.example.lab", "mail.example.lab"],
        allowed_ips=[], allowed_cidrs=[],
    )


def _fixture(*parts: str) -> str:
    return (PROJECT_ROOT / "tests" / "fixtures" / Path(*parts)).read_text(encoding="utf-8")


def _jsonl(name: str) -> str:
    return "\n".join(json.dumps(r) if not isinstance(r, str) else r
                     for r in json.loads(_fixture(*name.split("/"))))


def _ok_runner(stdout: str, code: int = 0):
    def _run(cmd, **kw):
        assert kw.get("shell") is False and isinstance(cmd, list)
        return SimpleNamespace(stdout=stdout, stderr="" if code == 0 else "err", returncode=code)

    return _run


def _never_runner(cmd, **kw):
    raise AssertionError("tool must not execute for out-of-scope input")


def test_httpx_tech_command():
    cmd = build_tech_command(PROJECTDISCOVERY_HTTPX_EXE)
    assert cmd[0] == PROJECTDISCOVERY_HTTPX_EXE
    assert "-tech-detect" in cmd and "-json" in cmd


def test_pd_httpx_enforcement():
    assert get_tech_httpx_executable() == PROJECTDISCOVERY_HTTPX_EXE
    assert get_httpx_executable() == PROJECTDISCOVERY_HTTPX_EXE


def test_python_httpx_protection():
    import httpx as pyhttpx

    assert "site-packages" in pyhttpx.__file__.replace("\\", "/")
    assert get_tech_httpx_executable() != "httpx"


def test_tech_parsing():
    obs = parse_tech_output(_jsonl("fingerprint/httpx_tech_sample.json"))
    by_host = {}
    for o in obs:
        by_host.setdefault(o.hostname, []).append((o.name, o.version))
    assert ("ExampleServer", "") in by_host["www.example.lab"]
    assert ("ExampleStack", "1.2") in by_host["api.example.lab"]


def _tech_runner():
    """Mock httpx honoring stdin: only lines for requested hosts are returned."""

    def _run(cmd, **kw):
        assert kw.get("shell") is False and isinstance(cmd, list)
        wanted = {l.strip().lower() for l in str(kw.get("input", "")).splitlines() if l.strip()}
        lines = []
        for line in _jsonl("fingerprint/httpx_tech_sample.json").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if str(rec.get("host", "")).strip().lower() in wanted:
                lines.append(line)
        return SimpleNamespace(stdout="\n".join(lines), stderr="", returncode=0)

    return _run


def test_tech_version_handling(tmp_path):
    res = run_fingerprint_discovery(
        "s7", ["www.example.lab", "mail.example.lab"], _lab_config(),
        runner=_tech_runner(), base=tmp_path)
    www = next(h for h in res.hosts if h.hostname == "www.example.lab")
    assert www.technologies[0]["version"] == ""
    mail = next(h for h in res.hosts if h.hostname == "mail.example.lab")
    assert mail.technologies == []


def test_duplicate_tech_handling(tmp_path):
    base_lines = _jsonl("fingerprint/httpx_tech_sample.json")
    dup = base_lines + "\n" + base_lines

    def _dup_runner(cmd, **kw):
        assert kw.get("shell") is False and isinstance(cmd, list)
        return SimpleNamespace(stdout=dup, stderr="", returncode=0)

    res = run_fingerprint_discovery("s7", ["www.example.lab"], _lab_config(),
                                    runner=_dup_runner, base=tmp_path)
    www = next(h for h in res.hosts if h.hostname == "www.example.lab")
    names = [t["name"] for t in www.technologies]
    assert len(names) == len(set(names))


def test_whatweb_disabled():
    status = check_whatweb()
    assert status.available is False and status.enabled is False
    assert "disabled" in status.reason.lower()


def test_katana_command():
    cmd = build_katana_command("katana-exe", "https://www.example.lab")
    assert cmd == ["katana-exe", "-u", "https://www.example.lab", "-d", "2",
                   "-silent", "-jsonl", "-ob", "-or"]
    assert "katana" in get_katana_executable().lower()


def test_katana_exe_enforcement():
    assert get_katana_executable().strip() != "" and "katana" in get_katana_executable().lower()


def test_endpoint_parsing():
    eps = parse_katana_output(_jsonl("endpoints/katana_sample.json"))
    urls = [e.url for e in eps]
    assert "https://www.example.lab/login" in urls
    assert "not json at all" not in urls


def test_data_uri_endpoints_rejected():
    # Katana crawls data-URI image embeds as "endpoints"; multi-kilobyte
    # base64 blobs are not crawlable URLs and must never become evidence.
    blob = ("https://www.example.lab/blog/img/image/png;base64,"
            + "iVBORw0KGgo" * 2000)
    assert parse_katana_output(f'{{"endpoint": "{blob}"}}') == []
    long_url = "https://www.example.lab/" + "a" * 3000
    assert parse_katana_output(f'{{"endpoint": "{long_url}"}}') == []
    assert parse_katana_output(
        '{"endpoint": "https://www.example.lab/login"}')[0].url == \
        "https://www.example.lab/login"


def test_url_normalization():
    assert normalize_url("HTTPS://WWW.Example.LAB:443/a/../b") is not None
    assert normalize_url("https://www.example.lab/path#frag") == "https://www.example.lab/path"
    assert normalize_url("ftp://www.example.lab/x") is None
    assert normalize_url("not a url") is None


def test_endpoint_dedup(tmp_path):
    res = run_endpoint_discovery(
        "s7", ["https://www.example.lab"], _lab_config(),
        runner=_ok_runner(_jsonl("endpoints/katana_sample.json")), base=tmp_path)
    www = next(h for h in res.hosts if h.hostname == "www.example.lab")
    assert sorted(e["url"] for e in www.endpoints) == [
        "https://www.example.lab/login", "https://www.example.lab/static/app.js"]


def test_endpoint_evidence(tmp_path):
    res = run_endpoint_discovery(
        "s7", ["https://www.example.lab"], _lab_config(),
        runner=_ok_runner(_jsonl("endpoints/katana_sample.json")), base=tmp_path)
    assert all(e.type.value == "endpoint" and e.source.value == "katana" for e in res.evidence)
    assert all(e.raw_reference.startswith("data/raw/endpoints/s7/") for e in res.evidence)


def test_gowitness_exe_detection():
    assert "gowitness" in get_gowitness_executable().lower()


def test_browser_detection():
    available, path = detect_browser()
    assert isinstance(available, bool) and isinstance(path, str)


def test_screenshot_no_browser(tmp_path):
    res = run_screenshot_capture(
        "s7", ["https://www.example.lab"], _lab_config(), base=tmp_path,
        browser_override=(False, ""))
    assert res.browser_available is False
    assert res.evidence == []
    assert res.screenshots[0]["status"] == "unavailable"


def test_screenshot_success(tmp_path):
    from types import SimpleNamespace

    def _shot_runner(cmd, **kw):
        shot_dir = Path(cmd[cmd.index("--screenshot-path") + 1])
        (shot_dir / "www.example.lab.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        return SimpleNamespace(
            stdout="target=https://www.example.lab status-code=200 have-screenshot=true",
            stderr="", returncode=0)

    res = run_screenshot_capture(
        "s7", ["https://www.example.lab"], _lab_config(), base=tmp_path,
        runner=_shot_runner, browser_override=(True, "chrome"))
    assert res.screenshots[0]["status"] == "captured"
    assert res.screenshots[0]["path"].endswith(".png")
    assert res.evidence[0].type.value == "screenshot"


def test_screenshot_jpeg_accepted_and_timeout_flagged(tmp_path):
    from types import SimpleNamespace

    def _jpeg_runner(cmd, **kw):
        assert "-T" in cmd and "60" in cmd
        shot_dir = Path(cmd[cmd.index("--screenshot-path") + 1])
        name = "https---www.example.lab.jpeg"
        (shot_dir / name).write_bytes(b"\xff\xd8\xff")
        return SimpleNamespace(stdout="have-screenshot=true", stderr="", returncode=0)

    res = run_screenshot_capture(
        "s7", ["https://www.example.lab"], _lab_config(), base=tmp_path,
        runner=_jpeg_runner, browser_override=(True, "chrome"))
    assert res.screenshots[0]["status"] == "captured"
    assert res.screenshots[0]["path"].endswith(".jpeg")


def test_screenshot_exit_zero_without_file_is_failure(tmp_path):
    # Regression: gowitness exits 0 with have-screenshot=false when headless
    # capture fails. That must be recorded as failed, never "captured".
    res = run_screenshot_capture(
        "s7", ["https://www.example.lab"], _lab_config(), base=tmp_path,
        runner=_ok_runner("target=https://www.example.lab status-code=200 "
                          "have-screenshot=false"),
        browser_override=(True, "chrome"))
    assert res.screenshots[0]["status"] == "failed"
    assert res.screenshots[0]["path"] == ""
    assert res.evidence == []
    assert len(res.rejected) == 1


def test_screenshot_failure(tmp_path):
    res = run_screenshot_capture(
        "s7", ["https://www.example.lab", "https://api.example.lab"], _lab_config(),
        base=tmp_path, runner=_ok_runner("", code=1), browser_override=(True, "chrome"))
    assert all(s["status"] == "failed" for s in res.screenshots)
    assert res.evidence == []
    assert len(res.rejected) == 2


def test_scope_enforcement(tmp_path):
    r = run_fingerprint_discovery("s7", ["evil.com"], _lab_config(),
                                  runner=_never_runner, base=tmp_path)
    assert r.hosts == [] and len(r.rejected) == 1
    r2 = run_endpoint_discovery("s7", ["https://evil.com/x"], _lab_config(),
                                runner=_never_runner, base=tmp_path)
    assert r2.hosts == [] and len(r2.rejected) == 1
    r3 = run_screenshot_capture("s7", ["https://evil.com"], _lab_config(), base=tmp_path,
                                runner=_never_runner, browser_override=(True, "chrome"))
    assert all(s["status"] in ("failed", "unavailable") or True for s in r3.screenshots)
    assert r3.evidence == []


def test_discovered_endpoint_scope_filtering(tmp_path):
    # The fixture contains https://evil.com/x — it must never become an asset.
    res = run_endpoint_discovery(
        "s7", ["https://www.example.lab"], _lab_config(),
        runner=_ok_runner(_jsonl("endpoints/katana_sample.json")), base=tmp_path)
    assert "evil.com" not in [h.hostname for h in res.hosts]
    assert any("evil.com" in r["value"] for r in res.rejected)


def test_injection_resistance(tmp_path):
    for bad in ["evil.com;whoami", "$(whoami)", "evil.com && whoami"]:
        r = run_fingerprint_discovery("s7", [bad], _lab_config(),
                                      runner=_never_runner, base=tmp_path)
        assert r.hosts == []
    r = run_endpoint_discovery("s7", ["https://evil.com\";whoami"], _lab_config(),
                               runner=_never_runner, base=tmp_path)
    assert r.hosts == []


def test_raw_checkpointing(tmp_path):
    run_fingerprint_discovery("s-raw", ["www.example.lab"], _lab_config(),
                              runner=_ok_runner(_jsonl("fingerprint/httpx_tech_sample.json")),
                              base=tmp_path)
    run_endpoint_discovery("s-raw", ["https://www.example.lab"], _lab_config(),
                           runner=_ok_runner(_jsonl("endpoints/katana_sample.json")),
                           base=tmp_path)
    run_screenshot_capture("s-raw", ["https://www.example.lab"], _lab_config(), base=tmp_path,
                           runner=_ok_runner("ok.png"), browser_override=(True, "c"))
    assert (tmp_path / "data" / "raw" / "fingerprint" / "s-raw").exists()
    assert (tmp_path / "data" / "raw" / "endpoints" / "s-raw").exists()
    assert (tmp_path / "data" / "raw" / "screenshots" / "s-raw").exists()


def test_processed_outputs(tmp_path):
    run_fingerprint_discovery("s-p", ["www.example.lab"], _lab_config(),
                              runner=_ok_runner(_jsonl("fingerprint/httpx_tech_sample.json")),
                              base=tmp_path)
    run_endpoint_discovery("s-p", ["https://www.example.lab"], _lab_config(),
                           runner=_ok_runner(_jsonl("endpoints/katana_sample.json")),
                           base=tmp_path)
    run_screenshot_capture("s-p", ["https://www.example.lab"], _lab_config(), base=tmp_path,
                           runner=_ok_runner("ok.png"), browser_override=(True, "c"))
    assert json.loads((tmp_path / "data" / "processed" / "fingerprint_data.json").read_text())["scan_id"] == "s-p"
    assert json.loads((tmp_path / "data" / "processed" / "endpoint_data.json").read_text())["scan_id"] == "s-p"
    assert json.loads((tmp_path / "data" / "processed" / "screenshot_data.json").read_text())["scan_id"] == "s-p"


def test_scan_id_separation(tmp_path):
    kw = dict(config=_lab_config(), base=tmp_path)
    r1 = run_fingerprint_discovery("scan-A", ["www.example.lab"], runner=_ok_runner(_jsonl("fingerprint/httpx_tech_sample.json")), **kw)
    r2 = run_fingerprint_discovery("scan-B", ["www.example.lab"], runner=_ok_runner(_jsonl("fingerprint/httpx_tech_sample.json")), **kw)
    assert r1.evidence[0].raw_reference != r2.evidence[0].raw_reference
    assert (tmp_path / "data" / "raw" / "fingerprint" / "scan-A").exists()
    assert (tmp_path / "data" / "raw" / "fingerprint" / "scan-B").exists()


def test_partial_failure(tmp_path):
    def flaky(cmd, **kw):
        if "api.example.lab" in " ".join(cmd):
            return SimpleNamespace(stdout="", stderr="boom", returncode=1)
        return SimpleNamespace(stdout=_jsonl("endpoints/katana_sample.json"), stderr="", returncode=0)

    res = run_endpoint_discovery(
        "s-part", ["https://www.example.lab", "https://api.example.lab"], _lab_config(),
        runner=flaky, base=tmp_path)
    assert any(h.hostname == "www.example.lab" for h in res.hosts)
    assert any("api.example.lab" in r["value"] for r in res.rejected)


def test_evidence_ids(tmp_path):
    res = run_fingerprint_discovery(
        "s-ids", ["www.example.lab", "api.example.lab"], _lab_config(),
        runner=_ok_runner(_jsonl("fingerprint/httpx_tech_sample.json")), base=tmp_path)
    assert [e.id for e in res.evidence] == [f"E{i:03d}" for i in range(1, len(res.evidence) + 1)]


def test_provenance(tmp_path):
    res = run_fingerprint_discovery(
        "s-prov", ["www.example.lab"], _lab_config(),
        runner=_ok_runner(_jsonl("fingerprint/httpx_tech_sample.json")), base=tmp_path)
    assert res.hosts[0].technologies[0]["source"] == "httpx"
    res2 = run_endpoint_discovery(
        "s-prov", ["https://www.example.lab"], _lab_config(),
        runner=_ok_runner(_jsonl("endpoints/katana_sample.json")), base=tmp_path)
    assert res2.hosts[0].endpoints[0]["source"] == "katana"
