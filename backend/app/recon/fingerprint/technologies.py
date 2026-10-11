"""Technology fingerprinting via ProjectDiscovery httpx -tech-detect (Phase 7).

Uses C:\\Users\\USER\\go\\bin\\httpx.exe from config/tools.yaml — never bare
`httpx` (Python httpx stays untouched). Hosts via stdin, JSONL parsed
tolerantly. Gate-enforced per hostname (passive_discovery, controlled).
Versions recorded only when explicitly reported, else empty.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

from backend.app.core.tool_manager import PROJECTDISCOVERY_HTTPX_EXE, load_tools_config
from backend.app.evidence.evidence_id import EvidenceIdGenerator
from backend.app.evidence.models import Evidence, EvidenceSource, EvidenceType
from backend.app.evidence.normalizer import build_observed_evidence
from backend.app.safety.exceptions import ScopeViolationError
from backend.app.safety.gate import authorize_tool_execution
from backend.app.safety.scope_validator import ScopeConfig, validate_target

STAGE_NAME = "technology_fingerprint"
OPERATION = "passive_discovery"


class TechObservation(BaseModel):
    hostname: str
    url: str = ""
    name: str
    version: str = ""
    source: str = "httpx"


class HostTechnologies(BaseModel):
    hostname: str
    technologies: list[dict[str, Any]] = Field(default_factory=list)


class FingerprintResult(BaseModel):
    scan_id: str
    target: str
    hosts: list[HostTechnologies] = Field(default_factory=list)
    rejected: list[dict[str, str]] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    checkpoint: dict[str, Any] = Field(default_factory=dict)


def get_tech_httpx_executable() -> str:
    for tool in load_tools_config():
        if tool.name == "httpx":
            if not tool.enabled:
                raise ScopeViolationError("httpx is disabled in tools.yaml")
            if tool.executable.strip() != PROJECTDISCOVERY_HTTPX_EXE:
                raise ScopeViolationError(
                    f"httpx must use {PROJECTDISCOVERY_HTTPX_EXE}"
                )
            return tool.executable.strip()
    raise ScopeViolationError("httpx is not configured in tools.yaml")


def build_tech_command(executable: str) -> list[str]:
    return [executable, "-json", "-silent", "-tech-detect",
            "-status-code", "-title", "-web-server"]


def _tech_entries(rec: dict[str, Any]) -> list[tuple[str, str]]:
    raw = rec.get("technologies") or rec.get("tech") or []
    items = [raw] if isinstance(raw, (str, dict)) else list(raw)
    out: list[tuple[str, str]] = []
    for item in items:
        if isinstance(item, dict):
            name = str(item.get("name", "") or "").strip()
            version = str(item.get("version", "") or "").strip()
        else:
            name, version = str(item).strip(), ""
        if name:
            out.append((name, version))
    return out


def parse_tech_output(stdout: str) -> list[TechObservation]:
    """Parse httpx JSONL. Never invents technologies or versions."""
    out: list[TechObservation] = []
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            rec = json.loads(s)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        host = str(rec.get("host", "") or "").strip().lower().rstrip(".")
        if not host:
            continue
        url = str(rec.get("url", "") or "")
        for name, version in _tech_entries(rec):
            out.append(TechObservation(
                hostname=host, url=url, name=name, version=version))
    return out


def project_root() -> Path:
    return Path(__file__).resolve().parents[4]


def run_fingerprint_discovery(
    scan_id: str,
    hostnames: list[str],
    config: Optional[ScopeConfig] = None,
    timeout: int = 180,
    runner=subprocess.run,
    base: Optional[Path] = None,
    generator: Optional[EvidenceIdGenerator] = None,
) -> FingerprintResult:
    """Fingerprint gated hosts. Partial failures never destroy other results."""
    authorized: list[str] = []
    rejected: list[dict[str, str]] = []
    for name in hostnames or []:
        try:
            decision = authorize_tool_execution(name, OPERATION, config=config)
        except Exception as exc:
            rejected.append({"value": name, "reason": str(exc)})
            continue
        authorized.append(decision.target)
    authorized = sorted(set(authorized))
    executable = get_tech_httpx_executable()
    target = authorized[0] if authorized else ""
    observations: list[TechObservation] = []
    stdout = ""
    if authorized:
        cmd = build_tech_command(executable)
        start = time.perf_counter()
        try:
            proc = runner(cmd, input="\n".join(authorized) + "\n",
                          capture_output=True, text=True,
                          timeout=timeout, shell=False)
            stdout = proc.stdout or ""
            if proc.returncode != 0:
                rejected.append({"value": ",".join(authorized),
                                 "reason": f"httpx tech-detect failed (exit {proc.returncode})"})
            else:
                observations = parse_tech_output(stdout)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("httpx tech-detect timed out") from exc
        except FileNotFoundError as exc:
            raise RuntimeError(f"httpx executable not found: {executable}") from exc

    # Scope re-check: observations for hosts outside current scope are
    # rejected (tool output is never trusted blindly).
    scoped: list[TechObservation] = []
    for obs in observations:
        decision = validate_target(obs.hostname, config)
        if decision.allowed:
            scoped.append(obs)
        else:
            rejected.append({"value": obs.hostname,
                             "reason": f"observation outside scope: {decision.reason}"})
    observations = scoped

    # Dedup per (host, tech): keep first non-empty version, retain provenance.
    merged: dict[tuple[str, str], TechObservation] = {}
    for obs in observations:
        key = (obs.hostname, obs.name.lower())
        cur = merged.get(key)
        if cur is None or (not cur.version and obs.version):
            merged[key] = obs
    by_host: dict[str, list[TechObservation]] = {h: [] for h in authorized}
    for (host, _), obs in sorted(merged.items()):
        by_host.setdefault(host, []).append(obs)

    gen = generator or EvidenceIdGenerator()
    hosts: list[HostTechnologies] = []
    evidence: list[Evidence] = []
    for hostname in sorted(by_host):
        techs: list[dict[str, Any]] = []
        for obs in by_host[hostname]:
            eid = gen.next()
            observed = obs.name if not obs.version else f"{obs.name} {obs.version}"
            evidence.append(build_observed_evidence(
                id=eid, type=EvidenceType.TECHNOLOGY, source=EvidenceSource.HTTPX,
                target=hostname, observed_value=observed,
                raw_reference=f"data/raw/fingerprint/{scan_id}/httpx_tech.json",
                metadata={"tool": "httpx", "scan_id": scan_id, "url": obs.url}))
            techs.append({"name": obs.name, "version": obs.version,
                          "source": "httpx", "evidence_ids": [eid]})
        hosts.append(HostTechnologies(hostname=hostname, technologies=techs))

    root = base or project_root()
    raw_dir = root / "data" / "raw" / "fingerprint" / scan_id
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_file = raw_dir / "httpx_tech.json"
    raw_file.write_text(json.dumps(
        {"scan_id": scan_id, "stdout": stdout,
         "observations": [o.model_dump() for o in observations]}, indent=2),
        encoding="utf-8")
    out_file = root / "data" / "processed" / "fingerprint_data.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(
        {"scan_id": scan_id, "hosts": [h.model_dump() for h in hosts]}, indent=2),
        encoding="utf-8")
    from datetime import datetime, timezone
    return FingerprintResult(
        scan_id=scan_id, target=target, hosts=hosts, rejected=rejected,
        evidence=evidence,
        checkpoint={"scan_id": scan_id, "stage": STAGE_NAME, "status": "completed",
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "output_files": [str(raw_file), str(out_file)]})
