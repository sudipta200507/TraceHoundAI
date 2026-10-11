"""Nuclei wrapper (Phase 8) — controlled vulnerability verification.

ACTIVE verification. Denied by default; explicit lab policy required
(lab_active_scan_policy). Targets via stdin, JSONL output, argument lists,
never shell=True. Conservative template scope documented below; no
intrusive/exploit/brute-force/DoS templates. Findings stay `observed` —
never auto-verified. Injectable runner for tests.
"""

from __future__ import annotations

import json
import subprocess
import time
import urllib.parse
from typing import Any, Optional

from pydantic import BaseModel, Field

from backend.app.core.tool_manager import load_tools_config
from backend.app.safety.exceptions import ScopeViolationError
from backend.app.safety.gate import authorize_tool_execution
from backend.app.safety.scope_validator import ScopeConfig, ScopePolicy

OPERATION = "vulnerability_verification"

# Conservative lab template scope: medium+ severities; intrusive, exploit,
# brute-force and DoS families excluded; low rate; no interactsh callbacks.
DEFAULT_SEVERITIES = ["medium", "high", "critical"]
DEFAULT_EXCLUDE_TAGS = ["intrusive", "dos", "brute-force", "exploit"]
DEFAULT_RATE_LIMIT = 50
DEFAULT_TIMEOUT = 10


class NucleiReference(BaseModel):
    cve_id: str = ""
    url: str = ""


class NucleiFinding(BaseModel):
    template_id: str = ""
    name: str = ""
    severity: str = ""
    host: str = ""
    matched_at: str = ""
    type: str = ""
    matcher_name: str = ""
    description: str = ""
    reference: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    timestamp: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class NucleiResult(BaseModel):
    target: str
    findings: list[NucleiFinding] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: float = 0.0
    executable: str = ""


class NucleiRun(BaseModel):
    results: list[NucleiResult] = Field(default_factory=list)
    rejected: list[dict[str, str]] = Field(default_factory=list)


def get_nuclei_executable() -> str:
    for tool in load_tools_config():
        if tool.name == "nuclei":
            if not tool.enabled:
                raise ScopeViolationError("nuclei is disabled in tools.yaml")
            if not tool.executable:
                raise ScopeViolationError("nuclei has no configured executable")
            return tool.executable
    raise ScopeViolationError("nuclei is not configured in tools.yaml")


def build_nuclei_command(
    executable: str,
    severities: Optional[list[str]] = None,
    exclude_tags: Optional[list[str]] = None,
) -> list[str]:
    """Conservative verification command. Targets travel via stdin."""
    sevs = severities if severities is not None else list(DEFAULT_SEVERITIES)
    excluded = exclude_tags if exclude_tags is not None else list(DEFAULT_EXCLUDE_TAGS)
    return [
        executable, "-jsonl", "-silent", "-nc", "-or",
        "-severity", ",".join(sevs),
        "-etags", ",".join(excluded),
        "-rate-limit", str(DEFAULT_RATE_LIMIT),
        "-timeout", str(DEFAULT_TIMEOUT),
        "-retries", "1", "-ni",
    ]


def _cve_candidates(rec: dict[str, Any]) -> list[str]:
    import re

    out: list[str] = []
    fields: list[str] = []
    for key in ("cve-id", "cve_id", "template-id", "templateID", "name",
                "description", "matcher-name"):
        value = rec.get(key, "")
        if isinstance(value, list):
            fields.extend(str(v) for v in value)
        elif value:
            fields.append(str(value))
    tags = rec.get("tags", [])
    if isinstance(tags, list):
        fields.extend(str(t) for t in tags)
    refs = rec.get("reference", [])
    if isinstance(refs, list):
        fields.extend(str(r) for r in refs)
    for text in fields:
        for match in re.findall(r"CVE-\d{4}-\d{4,7}", text.upper()):
            if match not in out:
                out.append(match)
    return out


def _normalize_finding_host(value: Any) -> str:
    """Nuclei may report a full URL in `host` — reduce to a bare hostname."""
    s = str(value or "").strip()
    if "://" in s:
        try:
            return (urllib.parse.urlsplit(s).hostname or s).lower().rstrip(".")
        except ValueError:
            return s.lower()
    return s.lower().rstrip(".")


def parse_nuclei_output(stdout: str, target: str) -> list[NucleiFinding]:
    """Parse Nuclei JSONL tolerantly. Missing fields stay empty — never invented."""
    out: list[NucleiFinding] = []
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
        info = rec.get("info", {}) if isinstance(rec.get("info"), dict) else {}
        refs = info.get("reference", rec.get("reference", []))
        if isinstance(refs, str):
            refs = [refs]
        tags = info.get("tags", rec.get("tags", []))
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        host = _normalize_finding_host(rec.get("host", ""))
        out.append(NucleiFinding(
            template_id=str(rec.get("template-id", rec.get("templateID", "")) or ""),
            name=str(info.get("name", rec.get("name", "")) or ""),
            severity=str(info.get("severity", rec.get("severity", "")) or "").lower(),
            host=host, matched_at=str(rec.get("matched-at", "") or ""),
            type=str(rec.get("type", "") or ""),
            matcher_name=str(rec.get("matcher-name", "") or ""),
            description=str(info.get("description", "") or ""),
            reference=[str(r) for r in (refs or []) if str(r).strip()],
            tags=[str(t) for t in (tags or []) if str(t).strip()],
            cve_ids=_cve_candidates({**rec, **info}),
            timestamp=str(rec.get("timestamp", "") or ""),
            raw=rec))
    for finding in out:
        if not finding.host:
            finding.host = target
    return out


def run_nuclei(
    targets: list[str],
    scan_id: str,
    config: Optional[ScopeConfig] = None,
    policy: Optional[ScopePolicy] = None,
    severities: Optional[list[str]] = None,
    exclude_tags: Optional[list[str]] = None,
    timeout: int = 1800,
    runner=subprocess.run,
) -> NucleiRun:
    """Verify gated targets. Per-target gate; failures isolated per target.

    Single batched run (targets via stdin) with partial-output salvage on
    timeout — large targets keep completed findings instead of losing the
    whole run.
    """
    executable = get_nuclei_executable()
    authorized: list[str] = []
    rejected: list[dict[str, str]] = []
    for name in targets or []:
        try:
            decision = authorize_tool_execution(name, OPERATION, config, policy)
        except Exception as exc:
            rejected.append({"value": name, "reason": str(exc)})
            continue
        authorized.append(decision.target)
    authorized = sorted(set(authorized))
    if not authorized:
        return NucleiRun(results=[], rejected=rejected)

    cmd = build_nuclei_command(executable, severities, exclude_tags)
    start = time.perf_counter()
    timed_out = False
    try:
        proc = runner(cmd, input="\n".join(authorized) + "\n",
                      capture_output=True, text=True, timeout=timeout, shell=False)
        elapsed = (time.perf_counter() - start) * 1000.0
        stdout, stderr, code = proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired as exc:
        # Salvage whatever findings streamed before the kill; record the rest.
        elapsed = (time.perf_counter() - start) * 1000.0
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        stdout, stderr, code = partial, "nuclei timed out; partial output kept", 0
        timed_out = True
    except FileNotFoundError as exc:
        raise RuntimeError(f"nuclei executable not found: {executable}") from exc
    if code != 0:
        raise RuntimeError(f"nuclei failed (exit {code}): {stderr[:500]}")
    findings = parse_nuclei_output(stdout, authorized[0] if authorized else "")
    by_host: dict[str, list[NucleiFinding]] = {}
    for finding in findings:
        by_host.setdefault(finding.host, []).append(finding)
    results = []
    for target in authorized:
        matched = by_host.pop(target, [])
        results.append(NucleiResult(
            target=target, findings=matched, stdout=stdout, stderr=stderr,
            exit_code=code, duration_ms=elapsed, executable=executable))
    for stray_host, stray in sorted(by_host.items()):
        rejected.append({"value": stray_host,
                         "reason": f"nuclei reported {len(stray)} finding(s) "
                                   "for a host outside the authorized set"})
    if timed_out:
        rejected.append({"value": ",".join(authorized),
                         "reason": "nuclei timed out; showing completed findings only"})
    return NucleiRun(results=results, rejected=rejected)
