"""Nmap wrapper (Phase 6) — service/version detection on Naabu-found ports.

Runs AFTER Naabu: only ports discovered by Naabu are supplied via -p.
Safe configuration: -sV only. No -A, no NSE scripts, no exploitation.
ACTIVE SCANNING — denied by default; explicit lab policy required.
XML output (-oX -) parsed deterministically. Injectable runner for tests.
"""

from __future__ import annotations

import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Optional

from pydantic import BaseModel, Field

from backend.app.core.tool_manager import load_tools_config
from backend.app.safety.exceptions import ScopeViolationError
from backend.app.safety.gate import authorize_tool_execution
from backend.app.safety.scope_validator import ScopeConfig, ScopePolicy

OPERATION = "active_port_scan"

# Same fan-out guard as Naabu: one nmap -sV per host. Override with
# TRACEHOUND_MAX_HOSTS.
DEFAULT_MAX_HOSTS = 100


def fanout_cap() -> int:
    import os

    try:
        return max(1, int(os.environ.get("TRACEHOUND_MAX_HOSTS",
                                         DEFAULT_MAX_HOSTS)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_HOSTS


class ServiceRecord(BaseModel):
    host: str = ""
    address: str = ""
    port: int = 0
    protocol: str = "tcp"
    state: str = ""
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""


class NmapHostResult(BaseModel):
    hostname: str
    services: list[ServiceRecord] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: float = 0.0
    executable: str = ""


class NmapRun(BaseModel):
    results: list[NmapHostResult] = Field(default_factory=list)
    rejected: list[dict[str, str]] = Field(default_factory=list)


def get_nmap_executable() -> str:
    for tool in load_tools_config():
        if tool.name == "nmap":
            if not tool.enabled:
                raise ScopeViolationError("nmap is disabled in tools.yaml")
            if not tool.executable:
                raise ScopeViolationError("nmap has no configured executable")
            return tool.executable
    raise ScopeViolationError("nmap is not configured in tools.yaml")


def build_nmap_command(executable: str, host: str, ports: list[int]) -> list[str]:
    """Service/version scan restricted to Naabu-supplied ports. No -A, no NSE."""
    port_spec = ",".join(str(p) for p in sorted(set(ports)))
    return [executable, "-sV", "-p", port_spec, "-oX", "-", host]


def parse_nmap_xml(xml_text: str, hostname: str = "") -> list[ServiceRecord]:
    """Parse Nmap XML deterministically. Missing info stays empty — never inferred."""
    try:
        root = ET.fromstring((xml_text or "").strip())
    except ET.ParseError as exc:
        raise ValueError(f"invalid Nmap XML: {exc}") from exc
    out: list[ServiceRecord] = []
    for h in root.findall("host"):
        addr_el = h.find("address")
        address = addr_el.get("addr", "") if addr_el is not None else ""
        ports_el = h.find("ports")
        if ports_el is None:
            continue
        for p in ports_el.findall("port"):
            try:
                port = int(p.get("portid", 0) or 0)
            except (TypeError, ValueError):
                continue
            protocol = p.get("protocol", "tcp") or "tcp"
            state_el = p.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            svc_el = p.find("service")
            out.append(
                ServiceRecord(
                    host=hostname or address,
                    address=address,
                    port=port,
                    protocol=protocol,
                    state=state,
                    service_name=svc_el.get("name", "") if svc_el is not None else "",
                    product=svc_el.get("product", "") if svc_el is not None else "",
                    version=svc_el.get("version", "") if svc_el is not None else "",
                    extra_info=svc_el.get("extrainfo", "") if svc_el is not None else "",
                )
            )
    return sorted(out, key=lambda s: (s.port, s.protocol))


def run_nmap(
    host_ports: dict[str, list[int]],
    scan_id: str,
    config: Optional[ScopeConfig] = None,
    policy: Optional[ScopePolicy] = None,
    timeout: int = 300,
    runner=subprocess.run,
) -> NmapRun:
    """Version-scan each gated host on its Naabu ports. Failures isolated per host."""
    executable = get_nmap_executable()
    results: list[NmapHostResult] = []
    rejected: list[dict[str, str]] = []
    ordered = sorted((host_ports or {}).keys())
    cap = fanout_cap()
    if len(ordered) > cap:
        for dropped in ordered[cap:]:
            rejected.append({"value": dropped,
                             "reason": f"host cap ({cap}): skipped for scan budget"})
        ordered = ordered[:cap]
    for name in ordered:
        ports = (host_ports or {}).get(name, [])
        try:
            decision = authorize_tool_execution(name, OPERATION, config, policy)
        except Exception as exc:
            rejected.append({"value": name, "reason": str(exc)})
            continue
        clean_ports = sorted({p for p in (ports or []) if isinstance(p, int) and 1 <= p <= 65535})
        if not clean_ports:
            rejected.append({"value": name, "reason": "no Naabu ports to version-scan"})
            continue
        cmd = build_nmap_command(executable, decision.target, clean_ports)
        start = time.perf_counter()
        try:
            proc = runner(
                cmd, capture_output=True, text=True, timeout=timeout, shell=False,
            )
            elapsed = (time.perf_counter() - start) * 1000.0
            stdout, stderr, code = proc.stdout or "", proc.stderr or "", proc.returncode
        except subprocess.TimeoutExpired:
            rejected.append({"value": name, "reason": "nmap timed out"})
            continue
        except FileNotFoundError as exc:
            raise RuntimeError(f"nmap executable not found: {executable}") from exc
        if code != 0:
            rejected.append(
                {"value": name, "reason": f"nmap failed (exit {code}): {stderr[:300]}"}
            )
            continue
        try:
            services = parse_nmap_xml(stdout, decision.target)
        except ValueError as exc:
            rejected.append({"value": name, "reason": str(exc)})
            continue
        results.append(
            NmapHostResult(
                hostname=decision.target, services=services,
                stdout=stdout, stderr=stderr, exit_code=code,
                duration_ms=elapsed, executable=executable,
            )
        )
    return NmapRun(results=results, rejected=rejected)
