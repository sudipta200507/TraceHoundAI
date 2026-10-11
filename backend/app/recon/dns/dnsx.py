"""dnsx wrapper (Phase 5) — safe DNS resolution for authorized assets only.

Uses the configured executable from config/tools.yaml. Argument lists only,
never shell=True. Hosts are passed via stdin (never interpolated into a
shell string). Accepts only in-scope assets; out-of-scope names are
rejected without executing the tool. Injectable runner for tests.
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
from backend.app.safety.scope_validator import ScopeConfig


class DNSResult(BaseModel):
    hostname: str
    record_type: str = "A"
    record_value: str = ""
    resolved: bool = False
    addresses: list[str] = Field(default_factory=list)
    source: str = "dnsx"
    scan_id: str = ""


class DnsxRun(BaseModel):
    results: list[DNSResult] = Field(default_factory=list)
    rejected: list[dict[str, str]] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: float = 0.0
    executable: str = ""


def get_dnsx_executable() -> str:
    for tool in load_tools_config():
        if tool.name == "dnsx":
            if not tool.enabled:
                raise ScopeViolationError("dnsx is disabled in tools.yaml")
            if not tool.executable:
                raise ScopeViolationError("dnsx has no configured executable")
            return tool.executable
    raise ScopeViolationError("dnsx is not configured in tools.yaml")


def build_dnsx_command(executable: str) -> list[str]:
    """Hosts travel via stdin. Non-aggressive read-only flags only."""
    return [executable, "-json", "-silent", "-a", "-resp"]


def parse_dnsx_output(stdout: str, scan_id: str = "") -> list[DNSResult]:
    """Parse dnsx JSONL into DNSResults. Malformed lines are skipped."""
    out: list[DNSResult] = []
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
        host = str(rec.get("host", "") or "").strip().lower().rstrip(".")
        if not host:
            continue
        addresses = [str(a) for a in (rec.get("a") or []) if str(a).strip()]
        resolved = bool(addresses)
        out.append(
            DNSResult(
                hostname=host,
                record_type="A",
                record_value=addresses[0] if addresses else "",
                resolved=resolved,
                addresses=addresses,
                scan_id=scan_id,
            )
        )
    return out


def run_dnsx(
    hostnames: list[str],
    scan_id: str,
    config: Optional[ScopeConfig] = None,
    timeout: int = 120,
    runner=subprocess.run,
) -> DnsxRun:
    """Resolve authorized assets only. Gate-enforced per hostname (dns_resolution)."""
    authorized: list[str] = []
    rejected: list[dict[str, str]] = []
    for name in hostnames or []:
        try:
            decision = authorize_tool_execution(name, "dns_resolution", config=config)
        except Exception as exc:
            rejected.append({"value": name, "reason": str(exc)})
            continue
        authorized.append(decision.target)
    # Deterministic order, deduplicated.
    authorized = sorted(set(authorized))
    if not authorized:
        return DnsxRun(results=[], rejected=rejected, executable=get_dnsx_executable())

    executable = get_dnsx_executable()
    cmd = build_dnsx_command(executable)
    stdin_text = "\n".join(authorized) + "\n"
    start = time.perf_counter()
    try:
        proc = runner(
            cmd, input=stdin_text, capture_output=True, text=True,
            timeout=timeout, shell=False,
        )
        elapsed = (time.perf_counter() - start) * 1000.0
        stdout, stderr, code = proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("dnsx timed out") from exc
    except FileNotFoundError as exc:
        raise RuntimeError(f"dnsx executable not found: {executable}") from exc
    if code != 0:
        raise RuntimeError(f"dnsx failed (exit {code}): {stderr[:500]}")
    return DnsxRun(
        results=parse_dnsx_output(stdout, scan_id),
        rejected=rejected,
        stdout=stdout,
        stderr=stderr,
        exit_code=code,
        duration_ms=elapsed,
        executable=executable,
    )
