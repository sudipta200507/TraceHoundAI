"""NVD client (Phase 8) — authoritative CVE enrichment, no invented data.

Uses https://services.nvd.nist.gov/rest/json/cves/2.0 (no key required;
optional NVD_API_KEY from the environment only — never in source).
A CVE is NVD-enriched only when NVD actually returns it, otherwise
nvd_status is not_found/unavailable. Injectable fetcher for tests.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDContext(BaseModel):
    cve_id: str
    nvd_status: str = "unknown"
    description: str = ""
    cvss_score: Optional[float] = None
    cvss_version: str = ""
    severity: str = ""
    references: list[str] = Field(default_factory=list)
    published: str = ""
    last_modified: str = ""
    affected_products: list[str] = Field(default_factory=list)


def build_nvd_url(cve_id: str) -> str:
    return f"{NVD_BASE}?{urllib.parse.urlencode({'cveId': cve_id.strip().upper()})}"


def _default_fetcher(url: str, timeout: int) -> str:
    headers = {"User-Agent": "TraceHoundAI-lab", "Accept": "application/json"}
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _first_english(descriptions: Any) -> str:
    if isinstance(descriptions, list):
        for entry in descriptions:
            if isinstance(entry, dict) and entry.get("lang") == "en":
                return str(entry.get("value", "") or "")
    return ""


def _best_cvss(cve: dict[str, Any]) -> tuple[Optional[float], str, str]:
    metrics = cve.get("metrics", {}) if isinstance(cve.get("metrics"), dict) else {}
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                         ("cvssMetricV2", "2.0")):
        entries = metrics.get(key, [])
        if isinstance(entries, list) and entries:
            data = (entries[0].get("cvssData", {})
                    if isinstance(entries[0], dict) else {})
            score = data.get("baseScore")
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None
            severity = str(data.get("baseSeverity", "") or "").lower()
            return score, version, severity
    return None, "", ""


def parse_nvd_response(cve_id: str, raw_text: str) -> NVDContext:
    """Parse an NVD response. Unknown CVE -> nvd_status not_found."""
    wanted = cve_id.strip().upper()
    try:
        payload = json.loads(raw_text or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid NVD response: {exc}") from exc
    vulns = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    for item in vulns:
        cve = item.get("cve", {}) if isinstance(item, dict) else {}
        if str(cve.get("id", "")).upper() != wanted:
            continue
        score, version, severity = _best_cvss(cve)
        refs = [str(r.get("url", "")) for r in (cve.get("references", []) or [])
                if isinstance(r, dict) and r.get("url")]
        products: list[str] = []
        for cfg in (cve.get("configurations", []) or []):
            for node in ((cfg.get("nodes", []) or []) if isinstance(cfg, dict) else []):
                for match in ((node.get("cpeMatch", []) or [])
                              if isinstance(node, dict) else []):
                    cpe = (match.get("criteria", "") if isinstance(match, dict) else "")
                    if cpe and cpe not in products:
                        products.append(cpe)
        return NVDContext(
            cve_id=wanted, nvd_status="confirmed_by_nvd",
            description=_first_english(cve.get("descriptions")),
            cvss_score=score, cvss_version=version, severity=severity,
            references=refs[:20], published=str(cve.get("published", "") or ""),
            last_modified=str(cve.get("lastModified", "") or ""),
            affected_products=products[:20])
    return NVDContext(cve_id=wanted, nvd_status="not_found")


def lookup_cve(
    cve_id: str,
    timeout: int = 15,
    fetcher: Optional[Callable[[str, int], str]] = None,
) -> tuple[NVDContext, str]:
    """Return (NVDContext, raw_text). Transport errors propagate for isolation."""
    url = build_nvd_url(cve_id)
    raw_text = (fetcher or _default_fetcher)(url, timeout)
    return parse_nvd_response(cve_id, raw_text), raw_text
