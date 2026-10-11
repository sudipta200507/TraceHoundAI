"""GoWitness wrapper (Phase 7) — controlled screenshot capture for live hosts.

Browser policy: detection only, never downloads. Chrome/Chromium/Edge is
looked up on PATH plus well-known Windows install paths. With no browser,
every capture reports unavailable (pipeline continues, nothing faked).
With a browser, one `scan single` per gated URL; per-host failures are
isolated and never delete other evidence. Injectable runner for tests.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
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
from backend.app.safety.scope_validator import ScopeConfig

STAGE_NAME = "screenshot_capture"
OPERATION = "passive_discovery"

# Fan-out guard: one gowitness capture per URL at up to `timeout` seconds
# each. Deterministic (sorted) truncation; dropped URLs are recorded as
# rejected. Override with TRACEHOUND_MAX_URLS.
DEFAULT_MAX_URLS = 150


def fanout_cap() -> int:
    import os

    try:
        return max(1, int(os.environ.get("TRACEHOUND_MAX_URLS",
                                         DEFAULT_MAX_URLS)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_URLS

_BROWSER_CANDIDATES = ("chrome", "chromium", "google-chrome", "msedge", "edge")
_WINDOWS_BROWSER_PATHS = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
)


class ScreenshotResult(BaseModel):
    hostname: str
    url: str = ""
    path: str = ""
    status: str = "failed"
    error: str = ""


class ScreenshotCaptureResult(BaseModel):
    scan_id: str
    browser_available: bool = False
    browser_path: str = ""
    screenshots: list[dict[str, Any]] = Field(default_factory=list)
    rejected: list[dict[str, str]] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    checkpoint: dict[str, Any] = Field(default_factory=dict)


def detect_browser() -> tuple[bool, str]:
    """Return (available, path). Detection only — never installs anything."""
    for candidate in _BROWSER_CANDIDATES:
        found = shutil.which(candidate)
        if found:
            return True, found
    for path in _WINDOWS_BROWSER_PATHS:
        if Path(path).exists():
            return True, path
    return False, ""


def get_gowitness_executable() -> str:
    for tool in load_tools_config():
        if tool.name == "gowitness":
            if not tool.enabled:
                raise ScopeViolationError("gowitness is disabled in tools.yaml")
            if not tool.executable:
                raise ScopeViolationError("gowitness has no configured executable")
            return tool.executable
    raise ScopeViolationError("gowitness is not configured in tools.yaml")


def build_gowitness_command(executable: str, url: str, shot_dir: str) -> list[str]:
    # -T 60: per-page capture budget. Pages needing longer are recorded as
    # failed for that URL instead of stalling the whole scan.
    return [executable, "scan", "single", "-u", url,
            "--screenshot-path", shot_dir, "--write-jsonl", "-T", "60"]


_IMAGE_PATTERNS = ("*.png", "*.jpeg", "*.jpg")


def _list_images(shot_dir: Path) -> set[str]:
    found: set[str] = set()
    for pattern in _IMAGE_PATTERNS:
        found.update(p.name for p in shot_dir.glob(pattern) if p.is_file())
    return found


def _confirmed_screenshot(shot_dir: Path, before: set[str], stdout: str,
                          hostname: str, scan_id: str) -> Optional[str]:
    """A screenshot counts as captured only with positive tool output AND a
    real new image file (PNG or JPEG — gowitness writes .jpeg). gowitness
    exits 0 even when headless capture fails (e.g. `have-screenshot=false`
    on its 60s default page timeout), so exit codes alone prove nothing."""
    if "have-screenshot=false" in (stdout or "").lower():
        return None
    after = _list_images(shot_dir)
    fresh = sorted(after - before)
    if "have-screenshot=true" in (stdout or "").lower() and fresh:
        return f"data/raw/screenshots/{scan_id}/{fresh[0]}"
    found = _image_from_output(stdout or "")
    if found:
        candidate = shot_dir / Path(found).name
        if candidate.is_file():
            return f"data/raw/screenshots/{scan_id}/{candidate.name}"
    if fresh:
        return f"data/raw/screenshots/{scan_id}/{fresh[0]}"
    return None


def _image_from_output(stdout: str) -> str:
    m = re.search(r"[\w\-./\\]*\.(?:png|jpe?g)", stdout or "", re.IGNORECASE)
    return m.group(0) if m else ""


def _safe_filename(hostname: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "_", hostname.lower()) + ".png"


def project_root() -> Path:
    return Path(__file__).resolve().parents[4]


def run_screenshot_capture(
    scan_id: str,
    urls: list[str],
    config: Optional[ScopeConfig] = None,
    timeout: int = 120,
    runner=subprocess.run,
    base: Optional[Path] = None,
    generator: Optional[EvidenceIdGenerator] = None,
    browser_override: Optional[tuple[bool, str]] = None,
) -> ScreenshotCaptureResult:
    """Capture gated URLs. Never fakes screenshots; failures stay per-host."""
    executable = get_gowitness_executable()
    browser_available, browser_path = (
        browser_override if browser_override is not None else detect_browser())
    root = base or project_root()
    shot_dir = root / "data" / "raw" / "screenshots" / scan_id
    shot_dir.mkdir(parents=True, exist_ok=True)

    gated: list[tuple[str, str]] = []  # (url, hostname)
    rejected: list[dict[str, str]] = []
    for url in urls or []:
        try:
            parts = urllib.parse.urlsplit(url.strip())
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError(f"malformed URL: {url!r}")
            decision = authorize_tool_execution(parts.hostname, OPERATION, config=config)
            gated.append((url.strip(), decision.target))
        except Exception as exc:
            rejected.append({"value": url, "reason": str(exc)})

    screenshots: list[dict[str, Any]] = []
    evidence: list[Evidence] = []
    gen = generator or EvidenceIdGenerator()
    if not browser_available:
        for url, hostname in gated:
            rejected.append({"value": url,
                             "reason": "screenshot unavailable: no Chrome/Chromium browser"})
            screenshots.append({"hostname": hostname, "url": url, "path": "",
                                "status": "unavailable", "evidence_ids": []})
    else:
        ordered = sorted(set(gated))
        cap = fanout_cap()
        if len(ordered) > cap:
            for dropped_url, dropped_host in ordered[cap:]:
                rejected.append({"value": dropped_url,
                                 "reason": f"URL cap ({cap}): skipped for scan budget"})
            ordered = ordered[:cap]
        for url, hostname in ordered:
            cmd = build_gowitness_command(executable, url, str(shot_dir))
            before = _list_images(shot_dir)
            try:
                proc = runner(cmd, capture_output=True, text=True,
                              timeout=timeout, shell=False)
            except subprocess.TimeoutExpired:
                rejected.append({"value": url, "reason": "gowitness timed out"})
                screenshots.append({"hostname": hostname, "url": url, "path": "",
                                    "status": "failed", "evidence_ids": []})
                continue
            except FileNotFoundError as exc:
                raise RuntimeError(
                    f"gowitness executable not found: {executable}") from exc
            if proc.returncode != 0:
                rejected.append({"value": url,
                                 "reason": f"gowitness failed (exit {proc.returncode})"})
                screenshots.append({"hostname": hostname, "url": url, "path": "",
                                    "status": "failed", "evidence_ids": []})
                continue
            path = _confirmed_screenshot(
                shot_dir, before, proc.stdout or "", hostname, scan_id)
            if path is None:
                rejected.append({"value": url,
                                 "reason": "gowitness reported no screenshot file "
                                           "(have-screenshot=false or no PNG written)"})
                screenshots.append({"hostname": hostname, "url": url, "path": "",
                                    "status": "failed", "evidence_ids": []})
                continue
            eid = gen.next()
            evidence.append(build_observed_evidence(
                id=eid, type=EvidenceType.SCREENSHOT, source=EvidenceSource.GOWITNESS,
                target=hostname, observed_value=path, raw_reference=path,
                metadata={"tool": "gowitness", "scan_id": scan_id, "url": url}))
            screenshots.append({"hostname": hostname, "url": url, "path": path,
                                "status": "captured", "evidence_ids": [eid]})

    out_file = root / "data" / "processed" / "screenshot_data.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(
        {"scan_id": scan_id, "screenshots": screenshots}, indent=2), encoding="utf-8")
    return ScreenshotCaptureResult(
        scan_id=scan_id, browser_available=browser_available,
        browser_path=browser_path, screenshots=screenshots, rejected=rejected,
        evidence=evidence,
        checkpoint={"scan_id": scan_id, "stage": STAGE_NAME, "status": "completed",
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "output_files": [str(out_file)]})
