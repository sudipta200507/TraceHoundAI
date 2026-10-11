"""Port/service aggregation (Phase 6): live_hosts -> Naabu -> Nmap -> evidence.

live_host -> port -> service correlation, only when port evidence supports it.
Per-host isolation: one host's Nmap failure never destroys Naabu results or
other hosts. Raw XML stays under data/raw/nmap/; processed stays compact.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

from backend.app.evidence.evidence_id import EvidenceIdGenerator
from backend.app.evidence.models import Evidence, EvidenceSource, EvidenceType
from backend.app.evidence.normalizer import build_observed_evidence
from backend.app.recon.ports.naabu import OpenPort, run_naabu
from backend.app.recon.ports.nmap import ServiceRecord, run_nmap
from backend.app.safety.scope_validator import ScopeConfig, ScopePolicy, validate_target

STAGE_NAME = "port_service_discovery"


class PortEntry(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


class HostPorts(BaseModel):
    hostname: str
    ports: list[PortEntry] = Field(default_factory=list)


class PortServiceResult(BaseModel):
    scan_id: str
    target: str
    hosts: list[HostPorts] = Field(default_factory=list)
    rejected: list[dict[str, str]] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    checkpoint: dict[str, Any] = Field(default_factory=dict)


def project_root() -> Path:
    return Path(__file__).resolve().parents[4]


def load_live_hostnames(
    live_hosts: dict[str, Any] | Path | str,
    base: Optional[Path] = None,
) -> tuple[str, str, list[str]]:
    if isinstance(live_hosts, dict):
        data = live_hosts
    else:
        p = Path(live_hosts)
        if not p.is_absolute():
            p = (base or project_root()) / p
        data = json.loads(p.read_text(encoding="utf-8"))
    hosts = data.get("hosts", [])
    names = [str(h.get("hostname", "")) for h in hosts if h.get("hostname")]
    return str(data.get("scan_id", "")), str(data.get("target", "")), names


def correlate_ports_services(
    ports: list[OpenPort], services: list[ServiceRecord]
) -> list[PortEntry]:
    """Join on (port, protocol). Service fields only from Nmap records."""
    svc_by_pp = {(s.port, s.protocol): s for s in services}
    out: list[PortEntry] = []
    for p in sorted(ports, key=lambda x: (x.port, x.protocol)):
        s = svc_by_pp.get((p.port, p.protocol))
        out.append(
            PortEntry(
                port=p.port, protocol=p.protocol, state=p.status,
                service=s.service_name if s else "",
                product=s.product if s else "",
                version=s.version if s else "",
            )
        )
    return out


def build_port_service_evidence(
    hostname: str, entries: list[PortEntry], scan_id: str,
    generator: EvidenceIdGenerator,
) -> list[Evidence]:
    out: list[Evidence] = []
    for entry in entries:
        eid = generator.next()
        entry.evidence_ids.append(eid)
        out.append(
            build_observed_evidence(
                id=eid, type=EvidenceType.PORT, source=EvidenceSource.NAABU,
                target=hostname, observed_value=f"{entry.port}/{entry.protocol}",
                raw_reference=f"data/raw/ports/{scan_id}/naabu.json",
                metadata={"tool": "naabu", "scan_id": scan_id, "port": entry.port},
            )
        )
        if entry.service:
            sid = generator.next()
            entry.evidence_ids.append(sid)
            observed = f"{entry.port}/{entry.protocol} {entry.service}".strip()
            if entry.product:
                observed += f" {entry.product}"
            if entry.version:
                observed += f" {entry.version}"
            out.append(
                build_observed_evidence(
                    id=sid, type=EvidenceType.SERVICE, source=EvidenceSource.NMAP,
                    target=hostname, observed_value=observed.strip(),
                    raw_reference=f"data/raw/nmap/{scan_id}/nmap.xml",
                    metadata={"tool": "nmap", "scan_id": scan_id,
                              "port": entry.port, "service": entry.service},
                )
            )
    return out


def write_port_checkpoints(
    scan_id: str, target: str,
    naabu_stdouts: dict[str, str], nmap_xmls: dict[str, str],
    hosts: list[HostPorts], base: Optional[Path] = None,
) -> list[str]:
    root = base or project_root()
    ports_dir = root / "data" / "raw" / "ports" / scan_id
    nmap_dir = root / "data" / "raw" / "nmap" / scan_id
    ports_dir.mkdir(parents=True, exist_ok=True)
    nmap_dir.mkdir(parents=True, exist_ok=True)
    naabu_file = ports_dir / "naabu.json"
    nmap_file = nmap_dir / "nmap.xml"
    out_file = root / "data" / "processed" / "port_service_data.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    naabu_file.write_text(json.dumps(
        {"scan_id": scan_id, "target": target, "outputs": naabu_stdouts},
        indent=2), encoding="utf-8")
    combined_xml = "\n".join(f"<!-- host: {h} -->\n{x}" for h, x in nmap_xmls.items())
    nmap_file.write_text(combined_xml or "<!-- no nmap output -->", encoding="utf-8")
    out_file.write_text(json.dumps(
        {"scan_id": scan_id, "target": target,
         "hosts": [h.model_dump() for h in hosts]}, indent=2), encoding="utf-8")
    return [str(naabu_file), str(nmap_file), str(out_file)]


def run_port_service_discovery(
    scan_id: str,
    live_hosts: dict[str, Any] | Path | str,
    config: Optional[ScopeConfig] = None,
    policy: Optional[ScopePolicy] = None,
    naabu_runner=None,
    nmap_runner=None,
    base: Optional[Path] = None,
    generator: Optional[EvidenceIdGenerator] = None,
) -> PortServiceResult:
    """Full stage. Hosts originate from live_hosts.json and are re-gated per host."""
    started = datetime.now(timezone.utc).isoformat()
    _, target, names = load_live_hostnames(live_hosts, base)

    naabu_run = run_naabu(names, scan_id, config, policy,
                          **({"runner": naabu_runner} if naabu_runner else {}))
    rejected: list[dict[str, str]] = list(naabu_run.rejected)
    ports_by_host = {r.hostname: r.ports for r in naabu_run.results}
    naabu_stdouts = {r.hostname: r.stdout for r in naabu_run.results}

    # Naabu -> Nmap handoff: only discovered ports are version-scanned.
    handoff = {
        h: [p.port for p in ports if p.status == "open"]
        for h, ports in ports_by_host.items()
    }
    handoff = {h: ports for h, ports in handoff.items() if ports}
    nmap_run = run_nmap(handoff, scan_id, config, policy,
                        **({"runner": nmap_runner} if nmap_runner else {}))
    rejected += nmap_run.rejected
    svc_by_host = {r.hostname: r.services for r in nmap_run.results}
    nmap_xmls = {r.hostname: r.stdout for r in nmap_run.results}

    gen = generator or EvidenceIdGenerator()
    hosts: list[HostPorts] = []
    evidence: list[Evidence] = []
    for hostname in sorted(set(list(ports_by_host) + list(svc_by_host))):
        if validate_target(hostname, config).allowed is False:
            rejected.append({"value": hostname, "reason": "scope revoked after scan"})
            continue
        entries = correlate_ports_services(
            ports_by_host.get(hostname, []), svc_by_host.get(hostname, []))
        evidence += build_port_service_evidence(hostname, entries, scan_id, gen)
        hosts.append(HostPorts(hostname=hostname, ports=entries))

    files = write_port_checkpoints(
        scan_id, target, naabu_stdouts, nmap_xmls, hosts, base)
    return PortServiceResult(
        scan_id=scan_id, target=target, hosts=hosts, rejected=rejected,
        evidence=evidence,
        checkpoint={"scan_id": scan_id, "stage": STAGE_NAME, "status": "completed",
                    "started_at": started,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "output_files": files},
    )
