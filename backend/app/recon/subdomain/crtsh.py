"""crt.sh client (Phase 4) — passive certificate-transparency discovery.

Uses only Python standard library HTTP (urllib). No new HTTP dependency.
The request happens ONLY after the target passes authorize_tool_execution().
Direct calls with out-of-scope domains are refused — no scope bypass.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Callable, Optional

from pydantic import BaseModel, Field

from backend.app.core.tool_manager import load_tools_config
from backend.app.safety.exceptions import ScopeViolationError
from backend.app.safety.gate import authorize_tool_execution
from backend.app.safety.scope_validator import ScopeConfig, normalize_target

CRTSH_BASE = "https://crt.sh"


class CrtshResult(BaseModel):
    target: str
    hostnames: list[str] = Field(default_factory=list)
    raw_text: str = ""
    record_count: int = 0


def _normalize_name(value: str) -> Optional[str]:
    s = (value or "").strip().lower().rstrip(".")
    while s.startswith("*."):
        s = s[2:].strip().rstrip(".")
    if not s or " " in s or "_" in s or ".." in s:
        return None
    return s


def parse_crtsh_response(raw_text: str) -> list[str]:
    """Parse crt.sh JSON into deduplicated normalized hostnames (sorted)."""
    try:
        records = json.loads(raw_text or "[]")
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid crt.sh response: {exc}") from exc
    if not isinstance(records, list):
        raise ValueError("invalid crt.sh response: expected a JSON list")
    seen: set[str] = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        name_value = rec.get("name_value", "")
        for line in str(name_value).splitlines():
            n = _normalize_name(line)
            if n:
                seen.add(n)
    return sorted(seen)


def _default_fetcher(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "TraceHoundAI-lab"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def query_crtsh(
    domain: str,
    config: Optional[ScopeConfig] = None,
    timeout: int = 30,
    fetcher: Optional[Callable[[str, int], str]] = None,
    max_attempts: int = 3,
) -> CrtshResult:
    """Query crt.sh for an authorized domain. Gate-enforced (passive_discovery).

    Transient network failures (crt.sh is famously flaky) are retried with a
    short backoff; only persistent failure raises.
    """
    import time as _time

    for tool in load_tools_config():
        if tool.name == "crtsh" and not tool.enabled:
            raise ScopeViolationError("crtsh is disabled in tools.yaml")
    decision = authorize_tool_execution(domain, "passive_discovery", config=config)
    normalized = normalize_target(domain)
    params = urllib.parse.urlencode({"q": f"%.{normalized.host}", "output": "json"})
    url = f"{CRTSH_BASE}/?{params}"
    do_fetch = fetcher or _default_fetcher
    last_exc: Exception | None = None
    for attempt in range(1, max(1, max_attempts) + 1):
        try:
            raw_text = do_fetch(url, timeout)
            break
        except Exception as exc:
            last_exc = exc
            if attempt < max(1, max_attempts):
                _time.sleep(min(5 * attempt, 15))
    else:
        raise RuntimeError(
            f"crt.sh query failed for {normalized.host}: {last_exc}") from last_exc
    hostnames = parse_crtsh_response(raw_text)
    try:
        count = len(json.loads(raw_text or "[]"))
    except json.JSONDecodeError:
        count = 0
    return CrtshResult(
        target=decision.target, hostnames=hostnames, raw_text=raw_text, record_count=count
    )
