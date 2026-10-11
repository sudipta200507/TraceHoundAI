"""TraceHoundAI tool health foundation (Phase 1).

Only executes version/health commands. Never performs reconnaissance.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Literal, Optional

import yaml
from pydantic import BaseModel, Field

ToolStatus = Literal["ready", "missing", "disabled", "error"]

# Absolute ProjectDiscovery httpx binary. NEVER resolve via bare `httpx` from PATH.
PROJECTDISCOVERY_HTTPX_EXE = r"C:\Users\USER\go\bin\httpx.exe"

_VERSION_RE = re.compile(r"v?\d+\.\d+(?:\.\d+)?")


class ToolConfig(BaseModel):
    name: str
    executable: str = ""
    enabled: bool = True
    version_command: List[str] = Field(default_factory=list)
    purpose: str = ""


class ToolHealth(BaseModel):
    name: str
    available: bool = False
    version: Optional[str] = None
    status: ToolStatus = "missing"
    executable: str = ""
    stdout: str = ""
    stderr: str = ""
    execution_time_ms: float = 0.0
    error: Optional[str] = None


def get_default_config_path() -> Path:
    """Project-root config/tools.yaml (works regardless of CWD)."""
    return Path(__file__).resolve().parents[3] / "config" / "tools.yaml"


def load_tools_config(path: Optional[str | Path] = None) -> List[ToolConfig]:
    cfg_path = Path(path) if path else get_default_config_path()
    with open(cfg_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    tools = data.get("tools", [])
    return [ToolConfig(**t) for t in tools]


def _is_url(value: str) -> bool:
    v = value.strip().lower()
    return v.startswith("http://") or v.startswith("https://")


def resolve_executable(configured: str) -> Optional[str]:
    """Resolve a configured executable to an absolute path.

    Returns None when not found. Returns the URL itself for web APIs (crt.sh).
    Never falls back to Python httpx for ProjectDiscovery httpx.
    """
    configured = (configured or "").strip()
    if not configured:
        return None
    if _is_url(configured):
        return configured
    if os.path.isabs(configured):
        return configured if Path(configured).exists() else None
    found = shutil.which(configured)
    return found


def parse_version(output: str) -> Optional[str]:
    text = output or ""
    # Prefer version tokens on lines mentioning "version" (e.g. engine banners),
    # otherwise fall back to the first version-like token in the output.
    version_lines = [ln for ln in text.splitlines() if "version" in ln.lower()]
    for ln in version_lines:
        m = _VERSION_RE.search(ln)
        if m:
            return m.group(0)
    m = _VERSION_RE.search(text)
    return m.group(0) if m else None


def is_projectdiscovery_output(output: str) -> bool:
    return "projectdiscovery" in (output or "").lower()


def verify_httpx_safety(resolved_exe: Optional[str], combined_output: str) -> tuple[bool, str]:
    """Ensure the httpx binary is ProjectDiscovery, not Python httpx.

    Returns (ok, message).
    """
    if not resolved_exe:
        return False, "httpx executable could not be resolved"
    expected = os.path.normcase(os.path.normpath(PROJECTDISCOVERY_HTTPX_EXE))
    actual = os.path.normcase(os.path.normpath(resolved_exe))
    if actual != expected:
        return False, f"httpx must be {PROJECTDISCOVERY_HTTPX_EXE}, got {resolved_exe}"
    if not is_projectdiscovery_output(combined_output):
        return False, "httpx version output does not identify ProjectDiscovery"
    return True, "ProjectDiscovery httpx verified"


def check_tool(cfg: ToolConfig) -> ToolHealth:
    """Check a single tool using ONLY its configured version command."""
    # Disabled tools: never touch the filesystem or subprocess.
    if not cfg.enabled:
        return ToolHealth(
            name=cfg.name,
            available=False,
            version=None,
            status="disabled",
            executable=cfg.executable,
            error=None,
        )

    # Web API tools without a local binary (crt.sh).
    if _is_url(cfg.executable):
        return ToolHealth(
            name=cfg.name,
            available=True,
            version="api",
            status="ready",
            executable=cfg.executable,
            stdout="crt.sh web API — no local binary",
            error=None,
        )

    # Extra guard: never allow bare `httpx` from PATH for ProjectDiscovery httpx.
    if cfg.name == "httpx" and cfg.executable.strip() != PROJECTDISCOVERY_HTTPX_EXE:
        return ToolHealth(
            name=cfg.name,
            available=False,
            version=None,
            status="error",
            executable=cfg.executable,
            error=f"httpx must use absolute path {PROJECTDISCOVERY_HTTPX_EXE}",
        )

    resolved = resolve_executable(cfg.executable)
    if not resolved or (not _is_url(resolved) and not Path(resolved).exists()):
        return ToolHealth(
            name=cfg.name,
            available=False,
            version=None,
            status="missing",
            executable=cfg.executable,
            error=f"executable not found: {cfg.executable}",
        )

    cmd = [resolved, *list(cfg.version_command or [])]
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        combined = f"{stdout}\n{stderr}"
        version = parse_version(combined)

        # httpx-specific safety verification.
        if cfg.name == "httpx":
            ok, msg = verify_httpx_safety(resolved, combined)
            if not ok:
                return ToolHealth(
                    name=cfg.name,
                    available=False,
                    version=version,
                    status="error",
                    executable=resolved,
                    stdout=stdout[-4000:],
                    stderr=stderr[-4000:],
                    execution_time_ms=elapsed_ms,
                    error=msg,
                )

        if version:
            return ToolHealth(
                name=cfg.name,
                available=True,
                version=version,
                status="ready",
                executable=resolved,
                stdout=stdout[-4000:],
                stderr=stderr[-4000:],
                execution_time_ms=elapsed_ms,
            )
        if proc.returncode == 0:
            return ToolHealth(
                name=cfg.name,
                available=True,
                version="unknown",
                status="ready",
                executable=resolved,
                stdout=stdout[-4000:],
                stderr=stderr[-4000:],
                execution_time_ms=elapsed_ms,
            )
        return ToolHealth(
            name=cfg.name,
            available=False,
            version=None,
            status="error",
            executable=resolved,
            stdout=stdout[-4000:],
            stderr=stderr[-4000:],
            execution_time_ms=elapsed_ms,
            error=f"version command failed (exit {proc.returncode})",
        )
    except FileNotFoundError:
        return ToolHealth(
            name=cfg.name,
            available=False,
            version=None,
            status="missing",
            executable=cfg.executable,
            error=f"executable not found: {cfg.executable}",
        )
    except subprocess.TimeoutExpired:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return ToolHealth(
            name=cfg.name,
            available=False,
            version=None,
            status="error",
            executable=resolved,
            execution_time_ms=elapsed_ms,
            error="version command timed out",
        )
    except Exception as exc:  # noqa: BLE001 - health check must never crash
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return ToolHealth(
            name=cfg.name,
            available=False,
            version=None,
            status="error",
            executable=resolved,
            execution_time_ms=elapsed_ms,
            error=str(exc),
        )


def check_all_tools(config_path: Optional[str | Path] = None) -> List[ToolHealth]:
    configs = load_tools_config(config_path)
    return [check_tool(c) for c in configs]
