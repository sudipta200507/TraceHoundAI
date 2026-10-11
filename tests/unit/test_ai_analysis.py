"""Phase 9 tests: local AI analysis — mocked model, deterministic validators."""

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.ai.context_builder import (
    build_context,
    evidence_index,
    verified_cve_set,
)
from backend.app.ai.ollama_client import (
    LLMConfig,
    OllamaClient,
    OllamaTimeout,
    OllamaUnavailable,
    load_llm_config,
)
from backend.app.ai.prompts.finding_analysis import build_finding_prompt
from backend.app.ai.prompts.system import SYSTEM_PROMPT
from backend.app.ai.reasoning import (
    build_attack_paths,
    generate_analysis,
    parse_model_json,
)
from backend.app.ai.schemas.attack_path import AIAttackPath
from backend.app.ai.schemas.finding import AIFinding
from backend.app.validation.ai_validator import validate_finding
from backend.app.validation.hallucination_guard import check_finding


def _snapshot() -> dict:
    return json.loads(
        (PROJECT_ROOT / "tests" / "fixtures" / "ai" / "ai_sample_context.json")
        .read_text(encoding="utf-8"))


def _finding(**kw) -> AIFinding:
    base = dict(finding_id="F001", title="Exposed HTTPS service on api.example.lab",
                description="Port 443/tcp serves HTTPS per [E021].",
                classification="observed_fact", severity="medium", confidence=0.8,
                evidence_ids=["E021"], observed_facts=["Port 443/tcp is open."],
                reasoning="Evidence E021 reports 443/tcp HTTPS.",
                verification_status="unverified",
                next_manual_steps=["Review TLS configuration manually."])
    base.update(kw)
    return AIFinding(**base)


def _by_id(snapshot=None) -> dict:
    snap = snapshot or _snapshot()
    return evidence_index(snap["evidence"])


def _cves(snapshot=None) -> set:
    snap = snapshot or _snapshot()
    return verified_cve_set(snap.get("verified_context"))


def _good_response() -> str:
    return json.dumps({"findings": [{
        "finding_id": "F001", "title": "Exposed login endpoint",
        "description": "Endpoint /login observed per [E034].",
        "classification": "observed_fact", "severity": "medium", "confidence": 0.7,
        "evidence_ids": ["E034"], "observed_facts": ["/login exists."],
        "reasoning": "E034 reports /login.", "verification_status": "unverified",
        "next_manual_steps": ["Inspect authentication manually."],
        "endpoints": ["/login"]}],
        "recommendations": [{"recommendation_id": "R001",
                             "text": "Review authentication on /login.",
                             "evidence_ids": ["E034"], "rationale": "Login exposed.",
                             "priority": "medium"}]})


def test_ollama_config():
    cfg = load_llm_config()
    assert cfg.provider == "ollama" and cfg.model == "qwen3:8b"
    assert cfg.base_url == "http://127.0.0.1:11434"
    assert cfg.temperature <= 0.3


def test_client_construction():
    client = OllamaClient(LLMConfig())
    assert client.config.model == "qwen3:8b"


def test_model_availability():
    import urllib.request as urlrequest

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps({"models": [{"name": "qwen3:8b"}]}).encode()

    def _fake_open(req, timeout=10):
        return _Resp()

    client = OllamaClient(LLMConfig(), opener=_fake_open)
    assert client.model_available() is True
    assert client.model_available("missing-model") is False


def test_timeout():
    def _boom(req, timeout=1):
        raise TimeoutError("slow")

    with pytest.raises(OllamaTimeout):
        OllamaClient(LLMConfig(), opener=_boom).generate("hi")

    import urllib.error

    def _down(req, timeout=1):
        raise urllib.error.URLError("down")

    assert OllamaClient(LLMConfig(), opener=_down).health() is False


def test_context_building():
    ctx = build_context(_snapshot())
    assert "syn-001" in ctx and "CVE-2026-90001" in ctx


def test_evidence_ids_included():
    ctx = build_context(_snapshot())
    for eid in ("E021", "E034", "E050", "E051", "E052"):
        assert f"[{eid}]" in ctx


def test_context_prioritization():
    snap = _snapshot()
    ctx = build_context(snap, max_chars=400)
    assert "CVE-2026-90001" in ctx  # verified context survives tiny budgets


def test_prompt_generation():
    system, user = build_finding_prompt("CTX")
    assert "ONLY source of factual truth" in system or "ONLY source" in system
    assert "CTX" in user and "evidence_ids" in user.lower()


def test_structured_parsing():
    payload = parse_model_json(_good_response())
    assert payload["findings"][0]["finding_id"] == "F001"


def test_malformed_response(tmp_path):
    analysis = generate_analysis("s-bad", _snapshot(), lambda s, u: "not json {{{",
                                 base=tmp_path)
    assert analysis.status == "failed" and analysis.findings == []


def test_truncated_output_retried(tmp_path):
    calls = {"n": 0}

    def _flaky(system, user):
        calls["n"] += 1
        if calls["n"] == 1:
            return '{"findings": [{"finding_id": "F1"'
        return _good_response()

    analysis = generate_analysis("s-retry", _snapshot(), _flaky, base=tmp_path)
    assert analysis.status == "completed" and calls["n"] == 2
    assert analysis.findings[0].finding_id == "F001"


def test_string_recommendations_coerced(tmp_path):
    import json as _json

    def _mixed(system, user):
        payload = _json.loads(_good_response())
        payload["recommendations"] = [
            "Plain string recommendation from model.",
            {"bad": "shape"},
            payload["recommendations"][0],
        ]
        return _json.dumps(payload)

    analysis = generate_analysis("s-coerce", _snapshot(), _mixed, base=tmp_path)
    assert analysis.status == "completed"
    texts = [r.text for r in analysis.recommendations]
    assert "Plain string recommendation from model." in texts
    string_rec = next(r for r in analysis.recommendations
                      if r.text == "Plain string recommendation from model.")
    assert string_rec.evidence_ids == []
    assert "without cited evidence" in string_rec.rationale


def test_missing_evidence_id():
    with pytest.raises(Exception):
        _finding(evidence_ids=[])


def test_nonexistent_id():
    res = validate_finding(_finding(evidence_ids=["E999"]), _by_id(), _cves())
    assert res.accepted is False and any("nonexistent" in r for r in res.reasons)


def test_cross_scan_id():
    snap = _snapshot()
    by_id = _by_id(snap)
    scan_ids = {e for e in by_id if e != "E021"}
    res = validate_finding(_finding(evidence_ids=["E021"]), by_id, _cves(), scan_ids)
    assert res.accepted is False and any("cross-scan" in r for r in res.reasons)


def test_unsupported_cve():
    f = _finding(description="CVE-2026-90002 is present.", cves=["CVE-2026-90002"])
    flags = check_finding(f, _by_id(), _cves())
    assert any("CVE-2026-90002" in flag for flag in flags)


def test_hallucinated_service():
    f = _finding(description="The host runs Apache Struts.", services=["Apache Struts"])
    assert any("Apache Struts" in flag for flag in check_finding(f, _by_id(), _cves()))


def test_hallucinated_tech():
    f = _finding(description="Built with Django.", technologies=["Django"])
    assert any("Django" in flag for flag in check_finding(f, _by_id(), _cves()))


def test_hallucinated_version():
    f = _finding(description="nginx 1.18.0 is running.")
    assert any("1.18.0" in flag for flag in check_finding(f, _by_id(), _cves()))


def test_unsupported_endpoint():
    f = _finding(description="Admin panel at /admin.", endpoints=["/admin"])
    assert any("/admin" in flag for flag in check_finding(f, _by_id(), _cves()))


def test_false_verified():
    f = _finding(verification_status="verified", classification="verified_finding")
    res = validate_finding(f, _by_id(), _cves())
    assert res.accepted is True and res.downgraded is True
    assert any("hallucination" in flag or "verified" in flag
               for flag in check_finding(f, _by_id(), _cves()))


def test_hypothesis_handling():
    f = _finding(classification="hypothesis",
                 description="The HTTPS service may warrant auth review.")
    assert check_finding(f, _by_id(), _cves()) == []
    assert validate_finding(f, _by_id(), _cves()).accepted is True


def test_confidence_validation():
    with pytest.raises(Exception):
        _finding(confidence=1.5)
    f = _finding(severity="high", confidence=0.3)
    assert f.severity == "high" and f.confidence == 0.3


def test_attack_path_evidence(tmp_path):
    paths = build_attack_paths([{
        "attack_path_id": "P001", "title": "Login exposure",
        "starting_asset": "www.example.lab",
        "steps": [{"asset": "www.example.lab", "observed_condition": "/login per E034",
                   "relationship": "serves", "hypothesis": "Auth review warranted.",
                   "required_verification": "Inspect login manually."}],
        "evidence_ids": ["E034"], "confidence": 0.6}], _by_id())
    assert len(paths) == 1 and paths[0].status == "hypothesis"
    assert isinstance(paths[0], AIAttackPath)


def test_attack_path_payload_example_rejected():
    paths = build_attack_paths([{
        "attack_path_id": "P002", "title": "Traversal illustration",
        "starting_asset": "www.example.lab",
        "steps": [{"asset": "www.example.lab",
                   "observed_condition": "dynamic endpoint per E034",
                   "relationship": "serves",
                   "hypothesis": "Unsanitized inputs could allow ../../etc/passwd access.",
                   "required_verification": "Inspect encoding manually."}],
        "evidence_ids": ["E034"], "confidence": 0.5}], _by_id())
    assert paths == []


def test_recommendations(tmp_path):
    analysis = generate_analysis("s-rec", _snapshot(), lambda s, u: _good_response(),
                                 base=tmp_path)
    assert analysis.status == "completed"
    assert analysis.recommendations[0].recommendation_id == "R001"


def test_raw_checkpoint(tmp_path):
    generate_analysis("s-raw", _snapshot(), lambda s, u: _good_response(), base=tmp_path)
    files = list((tmp_path / "data" / "raw" / "ai" / "s-raw").glob("*.json"))
    assert any("prompt" in f.name for f in files) and any("response" in f.name for f in files)


def test_processed_output(tmp_path):
    analysis = generate_analysis("s-proc", _snapshot(), lambda s, u: _good_response(),
                                 base=tmp_path)
    data = json.loads((tmp_path / "data" / "processed" / "ai_analysis.json").read_text())
    assert data["scan_id"] == "s-proc" and data["model"] == "qwen3:8b"
    assert analysis.findings[0].finding_id == "F001"


def test_scan_id_separation(tmp_path):
    kw = dict(base=tmp_path)
    r1 = generate_analysis("scan-A", _snapshot(), lambda s, u: _good_response(), **kw)
    r2 = generate_analysis("scan-B", _snapshot(), lambda s, u: _good_response(), **kw)
    assert (tmp_path / "data" / "raw" / "ai" / "scan-A").exists()
    assert (tmp_path / "data" / "raw" / "ai" / "scan-B").exists()
    assert r1.scan_id != r2.scan_id


def test_no_tool_execution():
    for module in ("backend/app/ai/ollama_client.py", "backend/app/ai/reasoning.py",
                   "backend/app/ai/context_builder.py"):
        text = (PROJECT_ROOT / module).read_text(encoding="utf-8")
        for token in ("import subprocess", "from subprocess", "subprocess.run",
                      "subprocess.Popen", "os.system", "Popen(", "socket.",
                      "authorize_tool_execution"):
            assert token not in text, f"{module} must not contain {token}"


def test_no_exploitation():
    attack_text = (PROJECT_ROOT / "backend/app/ai/prompts/attack_path.py").read_text()
    assert "payload" not in attack_text.lower() or "no " in attack_text.lower()
    paths = build_attack_paths([{
        "attack_path_id": "P002", "title": "Bad", "starting_asset": "www.example.lab",
        "steps": [{"asset": "www.example.lab", "observed_condition": "x per E034",
                   "relationship": "y", "hypothesis": "Run exploit payload now.",
                   "required_verification": "z"}],
        "evidence_ids": ["E034"], "confidence": 0.5}], _by_id())
    assert paths == []


def test_no_secrets():
    for module in ("backend/app/ai/ollama_client.py", "backend/app/ai/reasoning.py"):
        text = (PROJECT_ROOT / module).read_text(encoding="utf-8")
        assert "api_key" not in text.lower() and "sk-" not in text
    assert "127.0.0.1" in (PROJECT_ROOT / "config/llm.yaml").read_text()


def test_model_config():
    cfg = load_llm_config()
    assert cfg.model == "qwen3:8b" and SYSTEM_PROMPT.strip() != ""
    assert "evidence" in SYSTEM_PROMPT.lower()


def test_timeout_retries_once_with_smaller_context(tmp_path):
    from backend.app.ai.ollama_client import OllamaTimeout
    calls = []

    def _flaky(system, user):
        calls.append(len(user))
        if len(calls) == 1:
            raise OllamaTimeout("Ollama request timed out: timed out")
        return _good_response()

    analysis = generate_analysis("s-retry", _snapshot(), _flaky, base=tmp_path)
    assert analysis.status == "completed"
    assert len(calls) == 2 and calls[1] <= calls[0]


def test_down_model_fails_fast_without_retry(tmp_path):
    from backend.app.ai.ollama_client import OllamaUnavailable
    calls = []

    def _down(system, user):
        calls.append(1)
        raise OllamaUnavailable("Ollama unavailable: connection refused")

    analysis = generate_analysis("s-down", _snapshot(), _down, base=tmp_path)
    assert analysis.status == "failed" and len(calls) == 1
