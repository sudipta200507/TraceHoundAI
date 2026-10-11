"""Phase 10 tests: deterministic Markdown reporting — synthetic data only."""

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.reporting.renderer import render_report, write_report
from backend.app.reporting.report_builder import build_report_context
from backend.app.reporting.validator import validate_report_context


def _ai_snapshot() -> dict:
    return json.loads(
        (PROJECT_ROOT / "tests" / "fixtures" / "ai" / "ai_sample_context.json")
        .read_text(encoding="utf-8"))


def _snapshot(**over) -> dict:
    ai = _ai_snapshot()
    snap = {
        "scan_id": "syn-001", "target": "example.lab",
        "generated_at": "2026-01-03T00:00:00+00:00", "model": "qwen3:8b",
        "scope": {"allowed_domains": ["example.lab"],
                  "allowed_subdomains": ["www.example.lab", "api.example.lab"],
                  "allowed_ips": [], "allowed_cidrs": []},
        "stages_run": ["Asset discovery", "DNS/live-host discovery",
                       "Technology fingerprinting", "Vulnerability verification",
                       "NVD/CISA KEV enrichment", "AI-assisted analysis",
                       "Evidence validation", "Report generation"],
        "assets": [
            {"hostname": "www.example.lab", "ip": "192.0.2.10",
             "urls": ["https://www.example.lab"], "ports": ["443/tcp"],
             "technologies": ["ExampleServer"], "endpoints": ["/login"]},
            {"hostname": "api.example.lab", "ip": "192.0.2.11",
             "urls": ["https://api.example.lab"], "ports": ["443/tcp"],
             "technologies": [], "endpoints": []}],
        "live_host_count": 2, "open_port_count": 2, "technology_count": 1,
        "endpoint_count": 1,
        "evidence": ai["evidence"],
        "verified_context": {"findings": [
            {"cve_id": "CVE-2026-90001", "scanner_observed": True,
             "nvd_status": "confirmed_by_nvd", "cvss_score": 7.5,
             "severity": "high", "kev_status": "not_listed",
             "known_exploited": False, "evidence_ids": ["E050"]}]},
        "findings": [{
            "finding_id": "FIND-001", "title": "Exposed login endpoint",
            "classification": "hypothesis", "severity": "medium", "confidence": 0.78,
            "verification_status": "unverified",
            "description": "Endpoint /login observed per [E034].",
            "observed_facts": ["[E034] /login on www.example.lab"],
            "reasoning": "E034 reports /login; auth posture unknown.",
            "evidence_ids": ["E034"],
            "next_manual_steps": ["Inspect authentication manually."]}],
        "attack_paths": [{
            "attack_path_id": "P001", "title": "Login exposure hypothesis",
            "starting_asset": "www.example.lab",
            "steps": [{"asset": "www.example.lab",
                       "observed_condition": "/login per E034",
                       "relationship": "serves",
                       "hypothesis": "Auth review may be warranted.",
                       "required_verification": "Inspect login manually."}],
            "evidence_ids": ["E034"], "confidence": 0.6}],
        "screenshots": [],
        "synthetic": True,
    }
    snap.update(over)
    snap.setdefault("ai_analysis", {"recommendations": [{
        "recommendation_id": "R001", "text": "Review authentication on /login.",
        "priority": "medium", "rationale": "Login exposed per E034.",
        "evidence_ids": ["E034"]}]})
    return snap


def _ctx(**over):
    return build_report_context(_snapshot(**over))


def test_context_creation():
    ctx = _ctx()
    assert ctx.metadata.scan_id == "syn-001" and len(ctx.assets) == 2


def test_metadata():
    ctx = _ctx()
    assert ctx.metadata.model == "qwen3:8b" and ctx.metadata.model_runtime == "Ollama"


def test_scope_rendering():
    assert "example.lab" in render_report(_ctx())


def test_asset_inventory():
    text = render_report(_ctx())
    assert "www.example.lab" in text and "api.example.lab" in text


def test_finding_rendering():
    text = render_report(_ctx())
    assert "FIND-001" in text and "Exposed login endpoint" in text


def test_evidence_rendering():
    assert "`E034`" in render_report(_ctx())


def test_cve_rendering():
    assert "CVE-2026-90001" in render_report(_ctx())


def test_nvd_rendering():
    assert "confirmed_by_nvd" in render_report(_ctx())


def test_kev_rendering():
    assert "not listed" in render_report(_ctx())


def test_attack_path_rendering():
    text = render_report(_ctx())
    assert "P001" in text and "Hypothesis" in text


def test_recommendation_rendering():
    assert "R001" in render_report(_ctx())


def test_screenshot_missing():
    assert "No screenshots were captured in this scan." in render_report(_ctx())


def test_screenshot_reference():
    ctx = _ctx(screenshots=[{"hostname": "www.example.lab",
                             "url": "https://www.example.lab",
                             "path": "../data/raw/screenshots/syn-001/www.png",
                             "status": "captured"}])
    assert validate_report_context(ctx) == []
    assert "../data/raw/screenshots/syn-001/www.png" in render_report(ctx)


def test_empty_findings():
    snap = _snapshot(findings=[], ai_analysis={"recommendations": []})
    snap["verified_context"] = {"findings": []}
    text = render_report(build_report_context(snap))
    assert "No validated findings" in text \
        and "no CVE observations" in text


def test_empty_endpoints():
    assert "—" in render_report(_ctx())


def test_partial_data():
    snap = _snapshot()
    del snap["open_port_count"]
    assert "Not available" in render_report(build_report_context(snap))


def test_nonexistent_id_rejection():
    snap = _snapshot()
    snap["findings"][0]["evidence_ids"] = ["E999"]
    assert any("E999" in p for p in validate_report_context(build_report_context(snap)))


def test_cross_scan_rejection():
    ctx = _ctx()
    for row in ctx.evidence_table:
        if row["id"] == "E034":
            row["scan"] = "other-scan"
    assert any("cross-scan" in p for p in validate_report_context(ctx))


def test_invalid_severity():
    snap = _snapshot()
    snap["findings"][0]["severity"] = "extreme"
    with pytest.raises(Exception):
        build_report_context(snap)


def test_invalid_confidence():
    snap = _snapshot()
    snap["findings"][0]["confidence"] = 2.0
    with pytest.raises(Exception):
        build_report_context(snap)


def test_false_verified_rejection():
    snap = _snapshot()
    snap["findings"][0]["verification_status"] = "verified"
    assert any("verified" in p.lower()
               for p in validate_report_context(build_report_context(snap)))


def test_secret_detection():
    snap = _snapshot()
    snap["findings"][0]["description"] = "Use api_key: SECRET-123."
    assert any("secret" in p.lower()
               for p in validate_report_context(build_report_context(snap)))


def test_deterministic_ordering():
    snap = _snapshot()
    snap["assets"] = sorted(snap["assets"], key=lambda a: a["hostname"], reverse=True)
    first = [a.hostname for a in build_report_context(snap).assets]
    assert first == sorted(first)


def test_deterministic_rendering():
    assert render_report(_ctx()) == render_report(_ctx())


def test_file_creation(tmp_path):
    out = write_report(_ctx(), tmp_path / "r" / "final_report.md")
    text = out.read_text()
    assert out.exists() and text.startswith("# Security Assessment")
    assert "Final Assessment" in text
    assert "Evidence Index" in text
    assert "Executive Summary" in text


def test_malformed_input():
    with pytest.raises(Exception):
        build_report_context({"target": "example.lab"})
    with pytest.raises(Exception):
        build_report_context(_snapshot(scan_id=""))


def test_no_out_of_scope_assets():
    snap = _snapshot()
    snap["assets"].append({"hostname": "evil.com"})
    assert any("evil.com" in p for p in validate_report_context(build_report_context(snap)))


def test_root_boundary_assets_accepted():
    snap = _snapshot()
    snap["scope"] = {"allowed_domains": [], "allowed_subdomains": [],
                     "allowed_root_domains": ["example.lab"],
                     "allowed_ips": [], "allowed_cidrs": []}
    assert validate_report_context(build_report_context(snap)) == []
    snap["assets"].append({"hostname": "example.lab.attacker.com"})
    assert any("attacker" in p
               for p in validate_report_context(build_report_context(snap)))


def test_pdf_report_writes_selectable_text(tmp_path):
    from backend.app.reporting.pdf import write_pdf_report

    out = write_pdf_report(build_report_context(_snapshot()),
                           tmp_path / "final_report.pdf")
    assert out.exists()
    assert out.read_bytes()[:5] == b"%PDF-"


def test_no_cve_fabrication():
    snap = _snapshot()
    snap["findings"][0]["description"] = "CVE-2026-90002 present."
    assert any("90002" in p for p in validate_report_context(build_report_context(snap)))


def test_no_llm_dependency():
    for module in ("backend/app/reporting/renderer.py",
                   "backend/app/reporting/report_builder.py",
                   "backend/app/reporting/validator.py"):
        text = (PROJECT_ROOT / module).read_text(encoding="utf-8")
        for token in ("OllamaClient", "ollama_client", "generate_analysis",
                      "load_llm_config", "from backend.app.ai", "import openai",
                      "authorize_tool_execution"):
            assert token not in text, f"{module}: {token}"


def test_no_tool_execution():
    text = (PROJECT_ROOT / "backend/app/reporting/renderer.py").read_text()
    assert "subprocess" not in text and "Popen" not in text


# -- concise-report summaries ---------------------------------------------------

def _big_snapshot() -> dict:
    snap = _snapshot()
    snap["assets"] = [
        {"hostname": "a.example.lab", "ip": "192.0.2.10",
         "urls": ["https://a.example.lab"], "ports": ["443/tcp", "80/tcp"],
         "technologies": ["Cloudflare", "Cloudflare"],
         "endpoints": ["/", "/login", "/static/app.js", "/static/app.js"]},
        {"hostname": "b.example.lab", "ip": "192.0.2.11",
         "urls": ["https://b.example.lab"], "ports": ["443/tcp"],
         "technologies": ["Cloudflare"],
         "endpoints": ["/", "/admin", "/wp-login.php"]}]
    snap["live_host_count"] = 2
    snap["open_port_count"] = 3
    snap["technology_count"] = 3
    snap["endpoint_count"] = 7
    return snap


def test_port_groups_collapse_identical_observations():
    from backend.app.reporting.report_builder import build_report_context
    ctx = build_report_context(_big_snapshot())
    by_port = {g["port"]: g for g in ctx.port_groups}
    assert by_port["443"]["host_count"] == 2
    assert by_port["80"]["host_count"] == 1
    text = render_report(ctx)
    assert "4454" not in text  # grouped, not per-host rows in main report


def test_tech_groups_dedupe_repeats():
    from backend.app.reporting.report_builder import build_report_context
    ctx = build_report_context(_big_snapshot())
    cloudflare = [g for g in ctx.tech_groups if g["name"] == "Cloudflare"]
    assert len(cloudflare) == 1 and cloudflare[0]["host_count"] == 2


def test_security_endpoints_filtered_and_capped():
    from backend.app.reporting import report_builder as rb
    from backend.app.reporting.report_builder import build_report_context
    ctx = build_report_context(_big_snapshot())
    paths = {e["path"] for e in ctx.security_endpoints}
    assert "/login" in paths and "/admin" in paths and "/wp-login.php" in paths
    assert "/" not in paths and "/static/app.js" not in paths
    assert ctx.security_endpoints_total == 3
    assert ctx.security_endpoints_truncated is False
    old_cap = rb.MAIN_REPORT_SECURITY_ENDPOINT_CAP
    rb.MAIN_REPORT_SECURITY_ENDPOINT_CAP = 1
    try:
        capped = build_report_context(_big_snapshot())
        assert len(capped.security_endpoints) == 1
        assert capped.security_endpoints_truncated is True
    finally:
        rb.MAIN_REPORT_SECURITY_ENDPOINT_CAP = old_cap


def test_cited_evidence_traceable_to_full_index():
    from backend.app.reporting.report_builder import build_report_context
    ctx = build_report_context(_snapshot())
    full = {r["id"] for r in ctx.evidence_table}
    cited = {r["id"] for r in ctx.cited_evidence}
    assert cited and cited <= full
    assert "`E034`" in render_report(ctx)


def test_linked_remediation_uses_shared_evidence():
    from backend.app.reporting.report_builder import build_report_context
    ctx = build_report_context(_snapshot())
    links = ctx.linked_remediation.get("FIND-001", [])
    assert any(r["recommendation_id"] == "R001" for r in links)


def test_risk_overview_present_without_invention():
    from backend.app.reporting.report_builder import build_report_context
    ctx = build_report_context(_snapshot())
    assert ctx.risk_overview["finding_count"] == 1
    assert "Risk overview" in render_report(ctx)


def test_appendix_holds_full_inventories():
    from backend.app.reporting.renderer import render_appendix
    from backend.app.reporting.report_builder import build_report_context
    ctx = build_report_context(_big_snapshot())
    text = render_appendix(ctx)
    assert "/static/app.js" in text and "/wp-login.php" in text
    assert "Complete Evidence Index" in text


def test_inventory_and_csv_preserve_every_row():
    from backend.app.reporting.renderer import write_endpoints_csv, write_inventory_json
    from backend.app.reporting.report_builder import (
        build_endpoints_csv_rows,
        build_inventory_document,
        build_report_context,
    )
    ctx = build_report_context(_big_snapshot())
    doc = build_inventory_document(ctx)
    assert doc["counts"]["endpoints"] == 7
    assert len(doc["evidence"]) == len(ctx.evidence_table)
    import csv as _csv
    rows = build_endpoints_csv_rows(ctx)
    assert rows[0] == ["hostname", "path", "security_relevant"]
    assert len(rows) == 8  # header + all 7 endpoint rows, no dedup loss
