"""Katana wrapper (Phase 7) — controlled endpoint discovery for live hosts.

Controlled crawling only (depth 2, compact JSONL, no aggressive flags).
Hosts originate from live_hosts.json and re-pass the scope gate per URL.
Argument lists only, never shell=True. Injectable runner for tests.
"""

from __future__ import annotations

import json
import subprocess
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

from backend.app.core.tool_manager import load_tools_config
from backend.app.evidence.evidence_id import EvidenceIdGenerator
from backend.app.evidence.models import Evidence, EvidenceSource, EvidenceType
from backend.app.evidence.normalizer import build_observed_evidence
from backend.app.safety.exceptions import ScopeViolationError
from backend.app.safety.gate import authorize_tool_execution
from backend.app.safety.scope_validator import ScopeConfig, validate_target

STAGE_NAME = "endpoint_discovery"
OPERATION = "passive_discovery"

# Fan-out guard: one katana crawl per URL at up to `timeout` seconds each.
# Deterministic (sorted) truncation; dropped URLs are recorded as rejected.
# Override with TRACEHOUND_MAX_URLS.
DEFAULT_MAX_URLS = 150


def fanout_cap() -> int:
    import os

    try:
        return max(1, int(os.environ.get("TRACEHOUND_MAX_URLS",
                                         DEFAULT_MAX_URLS)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_URLS


class Endpoint(BaseModel):
    url: str
    host: str
    path: str = "/"
    method: str = ""
    status_code: int = 0
    content_type: str = ""
    source: str = "katana"


class HostEndpoints(BaseModel):
    hostname: str
    endpoints: list[dict[str, Any]] = Field(default_factory=list)


class EndpointDiscoveryResult(BaseModel):
    scan_id: str
    target: str
    hosts: list[HostEndpoints] = Field(default_factory=list)
    rejected: list[dict[str, str]] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    checkpoint: dict[str, Any] = Field(default_factory=dict)


def get_katana_executable() -> str:
    for tool in load_tools_config():
        if tool.name == "katana":
            if not tool.enabled:
                raise ScopeViolationError("katana is disabled in tools.yaml")
            if not tool.executable:
                raise ScopeViolationError("katana has no configured executable")
            return tool.executable
    raise ScopeViolationError("katana is not configured in tools.yaml")


def build_katana_command(executable: str, url: str) -> list[str]:
    """Single-URL controlled crawl: depth 2, bodies/raw omitted."""
    return [executable, "-u", url, "-d", "2", "-silent", "-jsonl", "-ob", "-or"]


def normalize_url(value: str) -> Optional[str]:
    """Deterministic URL canonicalization; None when malformed."""
    s = (value or "").strip()
    if not s or " " in s:
        return None
    try:
        parts = urllib.parse.urlsplit(s)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower().rstrip(".")
    netloc = host
    if parts.port and not (
        (parts.scheme == "http" and parts.port == 80)
        or (parts.scheme == "https" and parts.port == 443)
    ):
        netloc = f"{host}:{parts.port}"
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme}://{netloc}{path}{query}"


def parse_katana_output(stdout: str) -> list[Endpoint]:
    """Parse katana JSONL tolerantly — values never invented."""
    out: list[Endpoint] = []
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            rec = json.loads(s)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, str):
            raw_url = rec
            rec = {}
        else:
            if not isinstance(rec, dict):
                continue
            raw_url = (
                rec.get("endpoint") or rec.get("url")
                or ((rec.get("request") or {}) if isinstance(rec.get("request"), dict) else {}).get("endpoint", "")
            )
        url = normalize_url(str(raw_url))
        if not url:
            continue
        # Data-URI embeds (e.g. base64 images crawled as "endpoints") and
        # absurdly long URLs are not crawlable endpoints; servers and
        # intermediaries reject them. Skip deterministically, never truncate
        # into a fake shorter URL.
        if len(url) > 2048 or ";base64," in url.lower():
            continue
        host = urllib.parse.urlsplit(url).hostname or ""
        method = ""
        req = rec.get("request") if isinstance(rec, dict) else None
        if isinstance(req, dict):
            method = str(req.get("method", "") or "").upper()
        try:
            status = int(rec.get("status_code", rec.get("status", 0)) or 0)
        except (TypeError, ValueError):
            status = 0
        out.append(Endpoint(
            url=url, host=host, path=urllib.parse.urlsplit(url).path or "/",
            method=method, status_code=status,
            content_type=str(rec.get("content_type", rec.get("content-type", "")) or "")))
    return out


def project_root() -> Path:
    return Path(__file__).resolve().parents[4]


def run_endpoint_discovery(
    scan_id: str,
    urls: list[str],
    config: Optional[ScopeConfig] = None,
    timeout: int = 120,
    runner=subprocess.run,
    base: Optional[Path] = None,
    generator: Optional[EvidenceIdGenerator] = None,
) -> EndpointDiscoveryResult:
    """Crawl gated URLs. One URL failure never destroys other results."""
    executable = get_katana_executable()
    gated: list[str] = []
    rejected: list[dict[str, str]] = []
    for url in urls or []:
        norm = normalize_url(url)
        if not norm:
            rejected.append({"value": url, "reason": "malformed URL"})
            continue
        try:
            decision = authorize_tool_execution(
                urllib.parse.urlsplit(norm).hostname or "", OPERATION, config=config)
        except Exception as exc:
            rejected.append({"value": url, "reason": str(exc)})
            continue
        gated.append(norm)
    gated = sorted(set(gated))
    cap = fanout_cap()
    if len(gated) > cap:
        for dropped in gated[cap:]:
            rejected.append({"value": dropped,
                             "reason": f"URL cap ({cap}): skipped for scan budget"})
        gated = gated[:cap]

    found: list[Endpoint] = []
    raw_parts: list[str] = []
    for url in gated:
        cmd = build_katana_command(executable, url)
        try:
            proc = runner(cmd, capture_output=True, text=True,
                          timeout=timeout, shell=False)
            if proc.returncode != 0:
                rejected.append({"value": url,
                                 "reason": f"katana failed (exit {proc.returncode})"})
                continue
            raw_parts.append(proc.stdout or "")
            found.extend(parse_katana_output(proc.stdout or ""))
        except subprocess.TimeoutExpired:
            rejected.append({"value": url, "reason": "katana timed out"})
        except FileNotFoundError as exc:
            raise RuntimeError(f"katana executable not found: {executable}") from exc

    # Dedup by URL, retain first observation.
    unique: dict[str, Endpoint] = {}
    for ep in found:
        unique.setdefault(ep.url, ep)
    # Scope re-check on DISCOVERED endpoint hosts: tool output is never
    # trusted blindly — out-of-scope discoveries become rejections, not assets.
    by_host: dict[str, list[Endpoint]] = {}
    for url in sorted(unique):
        ep = unique[url]
        decision = validate_target(ep.host, config)
        if decision.allowed:
            by_host.setdefault(ep.host, []).append(ep)
        else:
            rejected.append({"value": url,
                             "reason": f"endpoint outside scope: {decision.reason}"})

    gen = generator or EvidenceIdGenerator()
    hosts: list[HostEndpoints] = []
    evidence: list[Evidence] = []
    for hostname in sorted(by_host):
        eps: list[dict[str, Any]] = []
        for ep in by_host[hostname]:
            eid = gen.next()
            evidence.append(build_observed_evidence(
                id=eid, type=EvidenceType.ENDPOINT, source=EvidenceSource.KATANA,
                target=hostname, observed_value=ep.path,
                raw_reference=f"data/raw/endpoints/{scan_id}/katana.json",
                metadata={"tool": "katana", "scan_id": scan_id, "url": ep.url}))
            eps.append({"url": ep.url, "path": ep.path, "source": "katana",
                        "evidence_ids": [eid]})
        hosts.append(HostEndpoints(hostname=hostname, endpoints=eps))

    target = sorted(by_host)[0] if by_host else ""
    root = base or project_root()
    raw_dir = root / "data" / "raw" / "endpoints" / scan_id
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_file = raw_dir / "katana.json"
    raw_file.write_text(json.dumps(
        {"scan_id": scan_id, "urls": gated, "stdout": "\n".join(raw_parts)}, indent=2),
        encoding="utf-8")
    out_file = root / "data" / "processed" / "endpoint_data.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(
        {"scan_id": scan_id, "hosts": [h.model_dump() for h in hosts]}, indent=2),
        encoding="utf-8")
    return EndpointDiscoveryResult(
        scan_id=scan_id, target=target, hosts=hosts, rejected=rejected,
        evidence=evidence,
        checkpoint={"scan_id": scan_id, "stage": STAGE_NAME, "status": "completed",
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "output_files": [str(raw_file), str(out_file)]})
