"""ProjectDiscovery httpx wrapper (Phase 5) — live HTTP/HTTPS discovery.

MUST use C:\\Users\\USER\\go\\bin\\httpx.exe from config/tools.yaml.
NEVER executes bare `httpx` (Python httpx also exists — it is untouched).
JSON output mode, non-aggressive field flags only. Hosts via stdin.
Gate-enforced per hostname. Injectable runner for tests.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any, Optional

from pydantic import BaseModel, Field

from backend.app.core.tool_manager import PROJECTDISCOVERY_HTTPX_EXE, load_tools_config
from backend.app.safety.exceptions import ScopeViolationError
from backend.app.safety.gate import authorize_tool_execution
from backend.app.safety.scope_validator import ScopeConfig


class HTTPProbeResult(BaseModel):
    url: str = ""
    scheme: str = ""
    host: str = ""
    port: int = 0
    status_code: int = 0
    title: str = ""
    webserver: str = ""
    content_type: str = ""
    technologies: list[str] = Field(default_factory=list)
    ip: str = ""
    final_url: str = ""
    response_time: str = ""


class HttpxRun(BaseModel):
    results: list[HTTPProbeResult] = Field(default_factory=list)
    rejected: list[dict[str, str]] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: float = 0.0
    executable: str = ""


def get_httpx_executable() -> str:
    """Return the configured PD httpx path; refuse anything else."""
    for tool in load_tools_config():
        if tool.name == "httpx":
            if not tool.enabled:
                raise ScopeViolationError("httpx is disabled in tools.yaml")
            if tool.executable.strip() != PROJECTDISCOVERY_HTTPX_EXE:
                raise ScopeViolationError(
                    f"httpx must use {PROJECTDISCOVERY_HTTPX_EXE}, "
                    f"got {tool.executable!r}"
                )
            expected = os.path.normcase(os.path.normpath(PROJECTDISCOVERY_HTTPX_EXE))
            actual = os.path.normcase(os.path.normpath(tool.executable.strip()))
            if actual != expected:
                raise ScopeViolationError("httpx executable failed safety check")
            return tool.executable.strip()
    raise ScopeViolationError("httpx is not configured in tools.yaml")


def build_httpx_command(executable: str) -> list[str]:
    """JSON mode with read-only metadata flags. Targets travel via stdin."""
    return [
        executable, "-json", "-silent",
        "-status-code", "-title", "-web-server", "-tech-detect", "-ip",
    ]


def _technologies_of(rec: dict[str, Any]) -> list[str]:
    tech = rec.get("technologies") or rec.get("tech") or []
    if isinstance(tech, str):
        return [tech] if tech else []
    return [str(t) for t in tech if str(t).strip()]


def parse_httpx_output(stdout: str) -> list[HTTPProbeResult]:
    """Parse httpx JSONL tolerantly — never assume a field exists."""
    out: list[HTTPProbeResult] = []
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
        host = str(rec.get("host", "") or rec.get("hostname", "") or "").strip().lower().rstrip(".")
        if not host:
            continue
        try:
            port = int(rec.get("port", 0) or 0)
        except (TypeError, ValueError):
            port = 0
        try:
            status = int(rec.get("status_code", rec.get("status-code", 0)) or 0)
        except (TypeError, ValueError):
            status = 0
        out.append(
            HTTPProbeResult(
                url=str(rec.get("url", "") or ""),
                scheme=str(rec.get("scheme", "") or ""),
                host=host,
                port=port,
                status_code=status,
                title=str(rec.get("title", "") or ""),
                webserver=str(rec.get("webserver", rec.get("web-server", "")) or ""),
                content_type=str(rec.get("content_type", rec.get("content-type", "")) or ""),
                technologies=_technologies_of(rec),
                ip=str(rec.get("ip", "") or ""),
                final_url=str(rec.get("final_url", rec.get("final-url", "")) or ""),
                response_time=str(rec.get("time", rec.get("response_time", "")) or ""),
            )
        )
    return out


def run_httpx(
    hostnames: list[str],
    scan_id: str,
    config: Optional[ScopeConfig] = None,
    timeout: int = 180,
    runner=subprocess.run,
) -> HttpxRun:
    """Probe authorized assets only. Gate-enforced per hostname (http_discovery)."""
    authorized: list[str] = []
    rejected: list[dict[str, str]] = []
    for name in hostnames or []:
        try:
            decision = authorize_tool_execution(name, "http_discovery", config=config)
        except Exception as exc:
            rejected.append({"value": name, "reason": str(exc)})
            continue
        authorized.append(decision.target)
    authorized = sorted(set(authorized))
    executable = get_httpx_executable()
    if not authorized:
        return HttpxRun(results=[], rejected=rejected, executable=executable)

    cmd = build_httpx_command(executable)
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
        raise RuntimeError("httpx timed out") from exc
    except FileNotFoundError as exc:
        raise RuntimeError(f"httpx executable not found: {executable}") from exc
    if code != 0:
        raise RuntimeError(f"httpx failed (exit {code}): {stderr[:500]}")
    return HttpxRun(
        results=parse_httpx_output(stdout),
        rejected=rejected,
        stdout=stdout,
        stderr=stderr,
        exit_code=code,
        duration_ms=elapsed,
        executable=executable,
    )
