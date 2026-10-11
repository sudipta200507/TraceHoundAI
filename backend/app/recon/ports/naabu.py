"""Naabu wrapper (Phase 6) — active port discovery for authorized live hosts.

ACTIVE SCANNING. Denied by default (dry_run=true). Callers must pass an
explicit lab policy from lab_active_scan_policy() — no hidden bypass.
Every host must come from live_hosts.json and re-pass the scope gate.
Argument lists only, never shell=True. Injectable runner for tests.
"""

from __future__ import annotations

import json
import subprocess
import time
from typing import Any, Optional

from pydantic import BaseModel, Field

from backend.app.core.tool_manager import load_tools_config
from backend.app.safety.exceptions import ScopeViolationError
from backend.app.safety.gate import authorize_tool_execution
from backend.app.safety.scope_validator import ScopeConfig, ScopePolicy

OPERATION = "active_port_scan"

# Fan-out guard: one naabu process per host at up to `timeout` seconds each.
# Without a cap a large asset list multiplies into hours. Deterministic
# (sorted) truncation; dropped hosts are recorded as rejected, never lost
# silently. Override with TRACEHOUND_MAX_HOSTS.
DEFAULT_MAX_HOSTS = 100


def fanout_cap() -> int:
    import os

    try:
        return max(1, int(os.environ.get("TRACEHOUND_MAX_HOSTS",
                                         DEFAULT_MAX_HOSTS)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_HOSTS


class OpenPort(BaseModel):
    host: str = ""
    ip: str = ""
    port: int = 0
    protocol: str = "tcp"
    status: str = "open"


class PortDiscoveryResult(BaseModel):
    hostname: str
    ports: list[OpenPort] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: float = 0.0
    executable: str = ""


class NaabuRun(BaseModel):
    results: list[PortDiscoveryResult] = Field(default_factory=list)
    rejected: list[dict[str, str]] = Field(default_factory=list)


def get_naabu_executable() -> str:
    for tool in load_tools_config():
        if tool.name == "naabu":
            if not tool.enabled:
                raise ScopeViolationError("naabu is disabled in tools.yaml")
            if not tool.executable:
                raise ScopeViolationError("naabu has no configured executable")
            return tool.executable
    raise ScopeViolationError("naabu is not configured in tools.yaml")


def build_naabu_command(executable: str, host: str) -> list[str]:
    """Controlled top-100 JSON scan of a single gate-approved host."""
    return [executable, "-host", host, "-json", "-silent", "-top-ports", "100"]


def parse_naabu_output(stdout: str, hostname: str) -> list[OpenPort]:
    """Parse naabu JSONL. Malformed lines skipped; fields never invented."""
    out: list[OpenPort] = []
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            rec: dict[str, Any] = json.loads(s)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        try:
            port = int(rec.get("port", 0) or 0)
        except (TypeError, ValueError):
            continue
        if not (1 <= port <= 65535):
            continue
        out.append(
            OpenPort(
                host=hostname,
                ip=str(rec.get("ip", "") or ""),
                port=port,
                protocol=str(rec.get("protocol", "tcp") or "tcp").lower(),
                status=str(rec.get("status", "open") or "open").lower(),
            )
        )
    seen: set[tuple] = set()
    unique: list[OpenPort] = []
    for entry in sorted(out, key=lambda p: (p.port, p.protocol)):
        key = (entry.port, entry.protocol, entry.status, entry.ip)
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return unique


def run_naabu(
    hostnames: list[str],
    scan_id: str,
    config: Optional[ScopeConfig] = None,
    policy: Optional[ScopePolicy] = None,
    timeout: int = 120,
    runner=subprocess.run,
) -> NaabuRun:
    """Scan authorized live hosts. Host-by-host gate; failures isolated."""
    executable = get_naabu_executable()
    results: list[PortDiscoveryResult] = []
    rejected: list[dict[str, str]] = []
    ordered = sorted(set(hostnames or []))
    cap = fanout_cap()
    if len(ordered) > cap:
        for dropped in ordered[cap:]:
            rejected.append({"value": dropped,
                             "reason": f"host cap ({cap}): skipped for scan budget"})
        ordered = ordered[:cap]
    for name in ordered:
        try:
            decision = authorize_tool_execution(name, OPERATION, config, policy)
        except Exception as exc:
            rejected.append({"value": name, "reason": str(exc)})
            continue
        cmd = build_naabu_command(executable, decision.target)
        start = time.perf_counter()
        try:
            proc = runner(
                cmd, capture_output=True, text=True, timeout=timeout, shell=False,
            )
            elapsed = (time.perf_counter() - start) * 1000.0
            stdout, stderr, code = proc.stdout or "", proc.stderr or "", proc.returncode
        except subprocess.TimeoutExpired as exc:
            rejected.append({"value": name, "reason": "naabu timed out"})
            continue
        except FileNotFoundError as exc:
            raise RuntimeError(f"naabu executable not found: {executable}") from exc
        if code != 0:
            rejected.append(
                {"value": name, "reason": f"naabu failed (exit {code}): {stderr[:300]}"}
            )
            continue
        results.append(
            PortDiscoveryResult(
                hostname=decision.target,
                ports=parse_naabu_output(stdout, decision.target),
                stdout=stdout, stderr=stderr, exit_code=code,
                duration_ms=elapsed, executable=executable,
            )
        )
    return NaabuRun(results=results, rejected=rejected)
