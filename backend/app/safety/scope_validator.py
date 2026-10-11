"""TraceHoundAI scope & safety gate (Phase 2) — deterministic, no LLM, no network.

NO reconnaissance tool may execute through the pipeline unless the target
passes this gate. The LLM must NEVER control or bypass this module.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Literal, Optional
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

from backend.app.safety.exceptions import (
    InvalidTargetError,
    ScopeConfigurationError,
    ScopeViolationError,
)

# ---------------------------------------------------------------------------
# Pydantic models (strict, LLM-independent)
# ---------------------------------------------------------------------------


class ScopePolicy(BaseModel):
    dry_run: bool = True
    require_explicit_authorization: bool = True
    allow_active_scanning: bool = False
    allow_exploitation: bool = False


class ScopeConfig(BaseModel):
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_subdomains: list[str] = Field(default_factory=list)
    allowed_ips: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    allowed_root_domains: list[str] = Field(default_factory=list)
    policy: ScopePolicy = Field(default_factory=ScopePolicy)

    @field_validator("allowed_domains", "allowed_subdomains", "allowed_root_domains", mode="before")
    @classmethod
    def _normalize_hostnames(cls, v):
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("hostname allow-list must be a list")
        out: list[str] = []
        for item in v:
            if not isinstance(item, str):
                raise ValueError("hostname entries must be strings")
            out.append(item.strip().lower().rstrip("."))
        return out

    @field_validator("allowed_ips", mode="before")
    @classmethod
    def _validate_ips(cls, v):
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("allowed_ips must be a list")
        out: list[str] = []
        for item in v:
            if not isinstance(item, str):
                raise ValueError("IP entries must be strings")
            s = item.strip()
            try:
                ipaddress.ip_address(s)
            except ValueError as exc:
                raise ValueError(f"invalid IP in scope: {item!r}") from exc
            out.append(s)
        return out

    @field_validator("allowed_cidrs", mode="before")
    @classmethod
    def _validate_cidrs(cls, v):
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("allowed_cidrs must be a list")
        out: list[str] = []
        for item in v:
            if not isinstance(item, str):
                raise ValueError("CIDR entries must be strings")
            s = item.strip()
            try:
                ipaddress.ip_network(s, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR in scope: {item!r}") from exc
            out.append(s)
        return out


class Target(BaseModel):
    raw: str
    host: str
    kind: Literal["domain", "ip"]


class ScopeDecision(BaseModel):
    allowed: bool
    reason: str
    target: str
    matched_rule: Optional[str] = None
    risk_level: Literal["low", "medium", "high", "blocked"] = "blocked"


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def get_default_scope_path() -> Path:
    return Path(__file__).resolve().parents[3] / "config" / "scope.yaml"


def load_scope_config(path: Optional[str | Path] = None) -> ScopeConfig:
    cfg_path = Path(path) if path else get_default_scope_path()
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError as exc:
        raise ScopeConfigurationError(f"scope config not found: {cfg_path}") from exc
    scope = data.get("scope", data)
    policy = data.get("policy", scope.get("policy", {}))
    payload = {
        "allowed_domains": scope.get("allowed_domains", []),
        "allowed_subdomains": scope.get("allowed_subdomains", []),
        "allowed_ips": scope.get("allowed_ips", []),
        "allowed_cidrs": scope.get("allowed_cidrs", []),
        "policy": policy if isinstance(policy, dict) else {},
    }
    try:
        return ScopeConfig(**payload)
    except ValidationError as exc:
        raise ScopeConfigurationError(f"invalid scope configuration: {exc}") from exc


# ---------------------------------------------------------------------------
# Normalization (deterministic, no network)
# ---------------------------------------------------------------------------

_HOST_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if ".." in host or host.startswith("-") or host.startswith("."):
        return False
    if "_" in host or " " in host:
        return False
    for label in host.split("."):
        if not label or len(label) > 63 or not _HOST_LABEL_RE.match(label):
            return False
    return True


def normalize_target(raw: str) -> Target:
    """Normalize user-supplied target into canonical (host, kind).

    Never performs network requests. Never truncates suffix attacks.
    Raises InvalidTargetError for malformed input.
    """
    if raw is None or not isinstance(raw, str):
        raise InvalidTargetError("target must be a string")
    s = raw.strip()
    if not s:
        raise InvalidTargetError("target must not be empty")
    if len(s) > 2048:
        raise InvalidTargetError("target too long")
    if any(c.isspace() for c in s):
        # URLs must not contain raw whitespace; bare hosts never do.
        raise InvalidTargetError(f"malformed target: {raw!r}")

    host_candidate: str
    if "://" in s:
        try:
            parts = urlsplit(s)
        except ValueError as exc:
            raise InvalidTargetError(f"malformed URL target: {raw!r}") from exc
        if not parts.hostname:
            raise InvalidTargetError(f"URL has no host: {raw!r}")
        host_candidate = parts.hostname
    else:
        # Bare host form: strip path/query/fragment, reject userinfo tricks.
        for sep in ("/", "?", "#"):
            if sep in s:
                s = s.split(sep, 1)[0]
        if "@" in s:
            raise InvalidTargetError(f"malformed target: {raw!r}")
        host_candidate = s
        # IPv6 literals are not supported in the Phase 2 lab scope.
        if host_candidate.startswith("[") or host_candidate.count(":") > 1:
            raise InvalidTargetError(f"IPv6 targets not supported: {raw!r}")
        if ":" in host_candidate:
            # host:port — port must be numeric 1-65535, otherwise malformed.
            left, _, right = host_candidate.rpartition(":")
            if not left or not right.isdigit() or not (1 <= int(right) <= 65535):
                raise InvalidTargetError(f"malformed host/port: {raw!r}")
            host_candidate = left

    host = host_candidate.strip().lower().rstrip(".")
    if not host:
        raise InvalidTargetError(f"malformed target: {raw!r}")

    # IP literal?
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if isinstance(ip, ipaddress.IPv6Address):
            raise InvalidTargetError("IPv6 targets not supported in Phase 2")
        return Target(raw=raw, host=str(ip), kind="ip")

    if not _is_valid_hostname(host):
        raise InvalidTargetError(f"malformed hostname: {raw!r}")
    return Target(raw=raw, host=host, kind="domain")


# ---------------------------------------------------------------------------
# Deterministic validation (exact matching only — no naive endswith)
# ---------------------------------------------------------------------------


def validate_target(raw: str, config: Optional[ScopeConfig] = None) -> ScopeDecision:
    """Return a ScopeDecision; never raises for out-of-scope targets.

    Malformed input yields allowed=False (risk blocked), never an exception,
    so the HTTP API stays safe. Programmatic callers needing exceptions
    should use enforce_scope().
    """
    cfg = config or load_scope_config()
    try:
        target = normalize_target(raw)
    except InvalidTargetError as exc:
        return ScopeDecision(
            allowed=False,
            reason=str(exc),
            target=(raw or "").strip()[:256],
            matched_rule=None,
            risk_level="blocked",
        )

    if target.kind == "ip":
        if target.host in cfg.allowed_ips:
            return ScopeDecision(
                allowed=True,
                reason=f"exact IP match: {target.host}",
                target=target.host,
                matched_rule=f"allowed_ips:{target.host}",
                risk_level="low",
            )
        try:
            addr = ipaddress.ip_address(target.host)
        except ValueError:
            addr = None
        if addr is not None:
            for cidr in cfg.allowed_cidrs:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                if addr in net:
                    return ScopeDecision(
                        allowed=True,
                        reason=f"IP {target.host} within {cidr}",
                        target=target.host,
                        matched_rule=f"allowed_cidrs:{cidr}",
                        risk_level="medium",
                    )
        return ScopeDecision(
            allowed=False,
            reason=f"IP not in authorized scope: {target.host}",
            target=target.host,
            matched_rule=None,
            risk_level="blocked",
        )

    # Domain: exact matches only — this defeats suffix tricks by construction.
    if target.host in cfg.allowed_domains:
        return ScopeDecision(
            allowed=True,
            reason=f"exact domain match: {target.host}",
            target=target.host,
            matched_rule=f"allowed_domains:{target.host}",
            risk_level="low",
        )
    if target.host in cfg.allowed_subdomains:
        return ScopeDecision(
            allowed=True,
            reason=f"explicit subdomain match: {target.host}",
            target=target.host,
            matched_rule=f"allowed_subdomains:{target.host}",
            risk_level="medium",
        )
    # Scan root boundary: the root itself, or a proper subdomain of it.
    # The dot anchor is what defeats suffix tricks — this is NOT naive
    # endswith("example.lab"), which would wrongly allow "attackerexample.lab".
    for root in cfg.allowed_root_domains:
        if target.host == root:
            return ScopeDecision(
                allowed=True,
                reason=f"scan root match: {target.host}",
                target=target.host,
                matched_rule=f"allowed_root_domains:{root}",
                risk_level="low",
            )
        if target.host.endswith("." + root):
            return ScopeDecision(
                allowed=True,
                reason=f"subdomain of scan root {root}: {target.host}",
                target=target.host,
                matched_rule=f"allowed_root_domains:{root}",
                risk_level="medium",
            )
    return ScopeDecision(
        allowed=False,
        reason=f"domain not in authorized scope: {target.host}",
        target=target.host,
        matched_rule=None,
        risk_level="blocked",
    )


def enforce_scope(raw: str, config: Optional[ScopeConfig] = None) -> ScopeDecision:
    """Strict gate for pipeline code: raises on denial instead of returning False."""
    cfg = config or load_scope_config()
    target = normalize_target(raw)  # raises InvalidTargetError when malformed
    decision = validate_target(raw, cfg)
    if not decision.allowed:
        raise ScopeViolationError(decision.reason)
    return decision


# ---------------------------------------------------------------------------
# Per-scan ephemeral scope (Phase 14) — one authorized root per scan_id.
# config/scope.yaml stays the GLOBAL safety/policy configuration; a ScanScope
# derives an immutable scan-specific boundary from the requested root domain.
# All matching reuses validate_target() above — no second validation system.
# ---------------------------------------------------------------------------


class ScanScope(BaseModel):
    """Immutable per-scan scope: exactly one authorized root domain boundary."""

    scan_id: str = Field(min_length=1)
    root_domain: str = Field(min_length=1)
    created_at: str = ""
    policy: ScopePolicy = Field(default_factory=ScopePolicy)
    allowed_ips: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    # Explicit active-scan approval recorded at creation (operator identity +
    # reason). Survives restarts so a resumed scan keeps its original,
    # explicitly granted authorization — never elevated silently.
    active_approval: Optional[dict[str, str]] = None

    def to_scope_config(self) -> ScopeConfig:
        """Expand to the single ScopeConfig every stage validates against."""
        return ScopeConfig(
            allowed_domains=[],
            allowed_subdomains=[],
            allowed_ips=list(self.allowed_ips),
            allowed_cidrs=list(self.allowed_cidrs),
            allowed_root_domains=[self.root_domain],
            policy=self.policy,
        )

    def describe(self) -> dict[str, str]:
        return {
            "scan_id": self.scan_id,
            "root_domain": self.root_domain,
            "allows": f"{self.root_domain} and *.{self.root_domain}",
            "boundary": f"exact match or dot-anchored subdomain of {self.root_domain}",
        }

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return target

    @classmethod
    def load(cls, path: str | Path) -> "ScanScope":
        try:
            return cls.model_validate_json(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ScopeConfigurationError(f"scan scope not found: {path}") from exc
        except ValidationError as exc:
            raise ScopeConfigurationError(f"invalid scan scope: {exc}") from exc


def create_scan_scope(
    raw_target: str,
    scan_id: str,
    global_config: Optional[ScopeConfig] = None,
) -> ScanScope:
    """Validate + normalize a requested root domain into an immutable ScanScope.

    Raises InvalidTargetError for anything that is not an acceptable lab root:
    malformed input, IP literals (unless explicitly allow-listed globally),
    single-label names such as localhost, or injection-shaped input.
    """
    from datetime import datetime, timezone

    cfg = global_config or load_scope_config()
    raw_stripped = raw_target.strip()
    if "://" in raw_stripped:
        # Credential/userinfo shapes never become scan roots, even though
        # urlsplit would silently drop the userinfo part.
        try:
            authority = urlsplit(raw_stripped).netloc
        except ValueError as exc:
            raise InvalidTargetError(f"malformed target: {raw_target!r}") from exc
        if "@" in authority:
            raise InvalidTargetError(
                f"userinfo in scan target is not allowed: {raw_target!r}")
    target = normalize_target(raw_target)  # raises InvalidTargetError when malformed
    if target.kind == "ip":
        # IP literals are authorized only through the explicit global lab lists.
        if not validate_target(target.host, cfg).allowed:
            raise InvalidTargetError(
                f"IP targets require explicit lab allow-listing: {target.host}")
        root = target.host
    else:
        if "." not in target.host:
            raise InvalidTargetError(
                f"scan root must be a fully qualified domain: {target.host}")
        if target.host == "localhost":
            raise InvalidTargetError("localhost is not an acceptable scan root")
        root = target.host
    return ScanScope(
        scan_id=scan_id,
        root_domain=root,
        created_at=datetime.now(timezone.utc).isoformat(),
        policy=cfg.policy,
        allowed_ips=list(cfg.allowed_ips),
        allowed_cidrs=list(cfg.allowed_cidrs),
    )
