"""Phase 2 tests: scope & safety gate — deterministic, no network recon."""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.safety.exceptions import (
    ExecutionPolicyError,
    ScopeConfigurationError,
    ScopeViolationError,
)
from backend.app.safety.execution_policy import check_execution_policy
from backend.app.safety.gate import authorize_tool_execution
from backend.app.safety.scope_validator import (
    ScopeConfig,
    enforce_scope,
    load_scope_config,
    normalize_target,
    validate_target,
)


def _lab_config() -> ScopeConfig:
    return ScopeConfig(
        allowed_domains=["example.lab"],
        allowed_subdomains=["www.example.lab", "app.example.lab"],
        allowed_ips=["192.0.2.10"],
        allowed_cidrs=["198.51.100.0/24"],
    )


def test_exact_allowed_domain():
    d = validate_target("example.lab", _lab_config())
    assert d.allowed is True
    assert d.matched_rule == "allowed_domains:example.lab"


def test_allowed_subdomain():
    d = validate_target("www.example.lab", _lab_config())
    assert d.allowed is True
    assert d.matched_rule == "allowed_subdomains:www.example.lab"


def test_out_of_scope_domain():
    d = validate_target("example.com", _lab_config())
    assert d.allowed is False
    assert d.matched_rule is None
    assert d.risk_level == "blocked"


def test_domain_suffix_attack():
    # Naive endswith("example.lab") would wrongly allow this.
    d = validate_target("attackerexample.lab", _lab_config())
    assert d.allowed is False


def test_exact_allowed_ip():
    d = validate_target("192.0.2.10", _lab_config())
    assert d.allowed is True
    assert d.matched_rule == "allowed_ips:192.0.2.10"


def test_allowed_cidr():
    d = validate_target("198.51.100.55", _lab_config())
    assert d.allowed is True
    assert d.matched_rule == "allowed_cidrs:198.51.100.0/24"


def test_ip_outside_cidr():
    d = validate_target("203.0.113.9", _lab_config())
    assert d.allowed is False


def test_uppercase_hostname():
    d = validate_target("EXAMPLE.LAB", _lab_config())
    assert d.allowed is True
    assert d.target == "example.lab"


def test_trailing_dot_hostname():
    d = validate_target("example.lab.", _lab_config())
    assert d.allowed is True
    assert d.target == "example.lab"


def test_url_with_scheme():
    d = validate_target("https://example.lab", _lab_config())
    assert d.allowed is True
    assert d.target == "example.lab"


def test_url_with_port():
    d = validate_target("http://example.lab:8080/path", _lab_config())
    assert d.allowed is True
    assert d.target == "example.lab"


def test_url_with_path():
    d = validate_target("https://www.example.lab/some/page?q=1", _lab_config())
    assert d.allowed is True
    assert d.target == "www.example.lab"


def test_malformed_target():
    d = validate_target("http://", _lab_config())
    assert d.allowed is False
    assert d.risk_level == "blocked"


def test_empty_target():
    d = validate_target("   ", _lab_config())
    assert d.allowed is False


def test_localhost_rejection():
    assert validate_target("localhost", _lab_config()).allowed is False
    assert validate_target("127.0.0.1", _lab_config()).allowed is False


def test_active_scanning_blocked_by_default():
    cfg = _lab_config()
    assert cfg.policy.dry_run is True
    assert cfg.policy.allow_active_scanning is False
    decision = check_execution_policy("active", cfg.policy)
    assert decision.allowed is False


def test_exploitation_blocked():
    cfg = _lab_config()
    assert cfg.policy.allow_exploitation is False
    assert check_execution_policy("exploitation", cfg.policy).allowed is False
    assert check_execution_policy("exploit", cfg.policy).allowed is False


def test_dry_run_behavior():
    cfg = _lab_config()
    assert check_execution_policy("passive", cfg.policy).allowed is True
    assert check_execution_policy("active", cfg.policy).allowed is False
    assert "dry_run" in check_execution_policy("active", cfg.policy).reason.lower()


def test_scope_configuration_validation():
    cfg = load_scope_config()
    assert "example.lab" in cfg.allowed_domains
    assert cfg.policy.dry_run is True
    assert cfg.policy.allow_exploitation is False
    with pytest.raises(ScopeConfigurationError):
        load_scope_config("nonexistent-scope-file.yaml")
    with pytest.raises(Exception):
        ScopeConfig(allowed_cidrs=["not-a-cidr"])


def test_api_scope_validation():
    from fastapi.testclient import TestClient

    from backend.main import app

    client = TestClient(app)
    ok = client.post("/api/system/scope/validate", json={"target": "example.lab"})
    assert ok.status_code == 200
    body = ok.json()
    assert body["allowed"] is True
    assert body["matched_rule"] is not None
    denied = client.post(
        "/api/system/scope/validate", json={"target": "evil.com"}
    )
    assert denied.status_code == 200
    assert denied.json()["allowed"] is False
    assert denied.json()["matched_rule"] is None
    assert denied.json()["risk_level"] == "blocked"


# --- Task 11 dangerous cases: must all be rejected under default lab scope ---


def test_suffix_trick_attacker_subdomain():
    assert validate_target("example.lab.attacker.com", _lab_config()).allowed is False


def test_suffix_trick_evil_prefix():
    assert validate_target("example.lab.evil.com", _lab_config()).allowed is False


def test_bare_evil_domain():
    assert validate_target("evil.com", _lab_config()).allowed is False


def test_loopback_ip_rejected():
    assert validate_target("127.0.0.1", _lab_config()).allowed is False


def test_private_ips_rejected_without_explicit_scope():
    assert validate_target("192.168.1.1", _lab_config()).allowed is False
    assert validate_target("10.0.0.1", _lab_config()).allowed is False


def test_private_ip_allowed_only_when_explicit():
    cfg = ScopeConfig(
        allowed_domains=[],
        allowed_subdomains=[],
        allowed_ips=["192.168.1.1"],
        allowed_cidrs=["10.0.0.0/24"],
    )
    assert validate_target("192.168.1.1", cfg).allowed is True
    assert validate_target("10.0.0.9", cfg).allowed is True
    assert validate_target("10.1.0.9", cfg).allowed is False


def test_normalization_never_upgrades_scope():
    t = normalize_target("https://EXAMPLE.LAB.:8080/evil")
    assert t.host == "example.lab"
    assert validate_target("example.lab.attacker.com", _lab_config()).allowed is False


def test_gate_blocks_bypass():
    with pytest.raises(ScopeViolationError):
        authorize_tool_execution("evil.com", "passive", _lab_config())
    with pytest.raises(ExecutionPolicyError):
        authorize_tool_execution("example.lab", "active", _lab_config())
    with pytest.raises(ExecutionPolicyError):
        authorize_tool_execution("example.lab", "exploitation", _lab_config())
    d = authorize_tool_execution("example.lab", "passive", _lab_config())
    assert d.allowed is True
    with pytest.raises(ScopeViolationError):
        enforce_scope("evil.com", _lab_config())
