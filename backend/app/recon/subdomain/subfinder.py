"""Subfinder wrapper (Phase 4) — passive subdomain discovery, gate-enforced.

Uses the configured executable from config/tools.yaml. Never uses an
unconfigured binary. Target must pass authorize_tool_execution() first.
Argument-list construction only (no shell). No shell injection possible.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from backend.app.core.tool_manager import load_tools_config
from backend.app.safety.exceptions import ScopeViolationError
from backend.app.safety.gate import authorize_tool_execution
from backend.app.safety.scope_validator import ScopeConfig, normalize_target


class SubfinderResult(BaseModel):
    target: str
    hostnames: list[str] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: float = 0.0
    executable: str = ""


def get_subfinder_executable() -> str:
    """Return the configured, enabled subfinder executable or raise."""
    for tool in load_tools_config():
        if tool.name == "subfinder":
            if not tool.enabled:
                raise ScopeViolationError("subfinder is disabled in tools.yaml")
            if not tool.executable:
                raise ScopeViolationError("subfinder has no configured executable")
            return tool.executable
    raise ScopeViolationError("subfinder is not configured in tools.yaml")


def build_subfinder_command(executable: str, target_host: str) -> list[str]:
    """Safe argument list. target_host must already be gate-normalized."""
    return [executable, "-d", target_host, "-silent"]


def parse_subfinder_output(stdout: str) -> list[str]:
    """Parse raw stdout lines into candidate hostname strings (unnormalized)."""
    out: list[str] = []
    for line in (stdout or "").splitlines():
        s = line.strip()
        if s:
            out.append(s)
    return out


def run_subfinder(
    target: str,
    config: Optional[ScopeConfig] = None,
    timeout: int = 120,
    runner=subprocess.run,
) -> SubfinderResult:
    """Run subfinder for an authorized target. Gate-enforced (passive_discovery).

    The `runner` parameter exists for deterministic unit tests (mocked).
    """
    decision = authorize_tool_execution(target, "passive_discovery", config=config)
    normalized = normalize_target(target)
    executable = get_subfinder_executable()
    cmd = build_subfinder_command(executable, normalized.host)

    start = time.perf_counter()
    try:
        proc = runner(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        elapsed = (time.perf_counter() - start) * 1000.0
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        elapsed = (time.perf_counter() - start) * 1000.0
        raise RuntimeError(f"subfinder timed out for {normalized.host}") from exc
    except FileNotFoundError as exc:
        raise RuntimeError(f"subfinder executable not found: {executable}") from exc

    if code != 0:
        raise RuntimeError(
            f"subfinder failed for {normalized.host} (exit {code}): {stderr[:500]}"
        )
    return SubfinderResult(
        target=decision.target,
        hostnames=parse_subfinder_output(stdout),
        stdout=stdout,
        stderr=stderr,
        exit_code=code,
        duration_ms=elapsed,
        executable=executable,
    )


def raw_checkpoint_dir(scan_id: str) -> Path:
    return (
        Path(__file__).resolve().parents[4]
        / "data"
        / "raw"
        / "subdomain"
        / scan_id
    )
