"""Live-host aggregation (Phase 5): asset_list + DNS + HTTP -> live_hosts.json.

Only hosts supported by deterministic observations become live. A failed
HTTP probe never destroys successful DNS results (DNS evidence is kept).
Restartable via per-scan raw checkpoints. No active port scanning.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from backend.app.evidence.evidence_id import EvidenceIdGenerator
from backend.app.evidence.models import Evidence, EvidenceSource, EvidenceType
from backend.app.evidence.normalizer import build_observed_evidence
from backend.app.recon.discovery.httpx import HTTPProbeResult, run_httpx
from backend.app.recon.dns.dnsx import DNSResult, run_dnsx
from backend.app.safety.gate import authorize_tool_execution
from backend.app.safety.scope_validator import ScopeConfig, validate_target

STAGE_NAME = "dns_live_discovery"


class LiveHost(BaseModel):
    hostname: str
    resolved_addresses: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    status: str = "live"
    ports: list[int] = Field(default_factory=list)
    status_code: int = 0
    title: str = ""
    webserver: str = ""
    technologies: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class LiveDiscoveryResult(BaseModel):
    scan_id: str
    target: str
    hosts: list[LiveHost] = Field(default_factory=list)
    rejected: list[dict[str, str]] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    checkpoint: dict[str, Any] = Field(default_factory=dict)


def project_root() -> Path:
    return Path(__file__).resolve().parents[4]


def load_asset_hostnames(
    asset_list: dict[str, Any] | Path | str,
    base: Optional[Path] = None,
) -> tuple[str, str, list[str]]:
    """Return (scan_id, target, hostnames) from an asset_list payload or file."""
    if isinstance(asset_list, dict):
        data = asset_list
    else:
        p = Path(asset_list)
        if not p.is_absolute():
            p = (base or project_root()) / p
        data = json.loads(p.read_text(encoding="utf-8"))
    assets = data.get("assets", [])
    hostnames = [str(a.get("hostname", "")) for a in assets if a.get("hostname")]
    return str(data.get("scan_id", "")), str(data.get("target", "")), hostnames


def correlate_dns_http(
    dns_results: list[DNSResult], probes: list[HTTPProbeResult]
) -> list[LiveHost]:
    """A host is live only with an HTTP probe carrying a status code."""
    dns_by_host: dict[str, DNSResult] = {}
    for d in dns_results:
        if d.resolved:
            dns_by_host.setdefault(d.hostname, d)
    probes_by_host: dict[str, list[HTTPProbeResult]] = {}
    for p in probes:
        if p.host and p.status_code:
            probes_by_host.setdefault(p.host, []).append(p)

    hosts: list[LiveHost] = []
    for hostname in sorted(probes_by_host):
        dns = dns_by_host.get(hostname)
        group = sorted(probes_by_host[hostname], key=lambda r: r.url)
        urls = sorted({r.url for r in group if r.url})
        ports = sorted({r.port for r in group if r.port})
        first = group[0]
        techs = sorted({t for r in group for t in (r.technologies or [])})
        hosts.append(
            LiveHost(
                hostname=hostname,
                resolved_addresses=list((dns.addresses if dns else [])),
                urls=urls,
                status="live",
                ports=ports,
                status_code=first.status_code,
                title=first.title,
                webserver=first.webserver,
                technologies=techs,
            )
        )
    return hosts


def build_live_evidence(
    hosts: list[LiveHost],
    dns_results: list[DNSResult],
    probes: list[HTTPProbeResult],
    scan_id: str,
    generator: Optional[EvidenceIdGenerator] = None,
) -> list[Evidence]:
    gen = generator or EvidenceIdGenerator()
    dns_by_host = {d.hostname: d for d in dns_results if d.resolved}
    out: list[Evidence] = []
    for host in hosts:
        ids: list[str] = []
        dns = dns_by_host.get(host.hostname)
        if dns and dns.addresses:
            eid = gen.next()
            ids.append(eid)
            out.append(
                build_observed_evidence(
                    id=eid, type=EvidenceType.DNS, source=EvidenceSource.DNSX,
                    target=host.hostname, observed_value=dns.addresses[0],
                    raw_reference=f"data/raw/dns/{scan_id}/dnsx.json",
                    metadata={"tool": "dnsx", "scan_id": scan_id,
                              "addresses": dns.addresses},
                )
            )
        probe = next((p for p in probes if p.host == host.hostname and p.status_code), None)
        if probe is not None:
            eid = gen.next()
            ids.append(eid)
            out.append(
                build_observed_evidence(
                    id=eid, type=EvidenceType.HTTP, source=EvidenceSource.HTTPX,
                    target=host.hostname,
                    observed_value=probe.url or host.hostname,
                    raw_reference=f"data/raw/httpx/{scan_id}/httpx.json",
                    metadata={"tool": "httpx", "scan_id": scan_id,
                              "status_code": probe.status_code},
                )
            )
        host.evidence_ids = ids
    return out


def write_live_checkpoints(
    scan_id: str, target: str,
    dns_stdout: str, dns_results: list[DNSResult],
    httpx_stdout: str, probes: list[HTTPProbeResult],
    hosts: list[LiveHost],
    base: Optional[Path] = None,
) -> list[str]:
    root = base or project_root()
    dns_dir = root / "data" / "raw" / "dns" / scan_id
    http_dir = root / "data" / "raw" / "httpx" / scan_id
    dns_dir.mkdir(parents=True, exist_ok=True)
    http_dir.mkdir(parents=True, exist_ok=True)
    dns_file = dns_dir / "dnsx.json"
    http_file = http_dir / "httpx.json"
    live_file = root / "data" / "processed" / "live_hosts.json"
    live_file.parent.mkdir(parents=True, exist_ok=True)
    dns_file.write_text(json.dumps(
        {"scan_id": scan_id, "target": target, "stdout": dns_stdout,
         "results": [r.model_dump() for r in dns_results]}, indent=2), encoding="utf-8")
    http_file.write_text(json.dumps(
        {"scan_id": scan_id, "target": target, "stdout": httpx_stdout,
         "results": [p.model_dump() for p in probes]}, indent=2), encoding="utf-8")
    live_file.write_text(json.dumps(
        {"scan_id": scan_id, "target": target,
         "hosts": [h.model_dump() for h in hosts]}, indent=2), encoding="utf-8")
    return [str(dns_file), str(http_file), str(live_file)]


def run_live_discovery(
    scan_id: str,
    asset_list: dict[str, Any] | Path | str,
    config: Optional[ScopeConfig] = None,
    dns_runner=None,
    httpx_runner=None,
    base: Optional[Path] = None,
    generator: Optional[EvidenceIdGenerator] = None,
) -> LiveDiscoveryResult:
    """Full stage. Hostnames come from asset_list (already gated); re-validated."""
    started = datetime.now(timezone.utc).isoformat()
    _, asset_target, hostnames = load_asset_hostnames(asset_list, base)

    # Scope re-validation: asset_list entries failing current scope are rejected.
    in_scope: list[str] = []
    rejected: list[dict[str, str]] = []
    for name in hostnames:
        decision = validate_target(name, config)
        if decision.allowed:
            in_scope.append(decision.target)
        else:
            rejected.append({"value": name, "reason": decision.reason})
    in_scope = sorted(set(in_scope))
    anchor = asset_target or (in_scope[0] if in_scope else "")
    if anchor:
        authorize_tool_execution(anchor, "dns_resolution", config=config)

    dns_run = run_dnsx(in_scope, scan_id, config,
                       **({"runner": dns_runner} if dns_runner else {}))
    rejected += dns_run.rejected
    http_run = run_httpx(in_scope, scan_id, config,
                         **({"runner": httpx_runner} if httpx_runner else {}))
    rejected += http_run.rejected

    hosts = correlate_dns_http(dns_run.results, http_run.results)
    # Final scope filter: a tool result naming a host outside the current
    # scope (redirect, stale canonical output) NEVER becomes a live asset.
    scoped_hosts: list[LiveHost] = []
    for host in hosts:
        sweep = validate_target(host.hostname, config)
        if sweep.allowed:
            scoped_hosts.append(host)
        else:
            rejected.append({"value": host.hostname,
                             "reason": f"live host outside scope: {sweep.reason}"})
    hosts = scoped_hosts
    evidence = build_live_evidence(hosts, dns_run.results, http_run.results,
                                    scan_id, generator)
    files = write_live_checkpoints(
        scan_id, asset_target, dns_run.stdout, dns_run.results,
        http_run.stdout, http_run.results, hosts, base)
    return LiveDiscoveryResult(
        scan_id=scan_id, target=asset_target, hosts=hosts, rejected=rejected,
        evidence=evidence,
        checkpoint={"scan_id": scan_id, "stage": STAGE_NAME, "status": "completed",
                    "started_at": started,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "output_files": files},
    )
