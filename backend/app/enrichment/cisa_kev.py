"""CISA KEV client (Phase 8) — Known Exploited Vulnerabilities lookup.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Absent from KEV means only "not listed" — never "not vulnerable".
Catalog is fetched once per run and cached to data/raw/cisa_kev/.
Injectable fetcher for tests.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Callable, Optional

from pydantic import BaseModel

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


class CISAKEVContext(BaseModel):
    cve_id: str
    known_exploited: bool = False
    kev_status: str = "unknown"
    date_added: str = ""
    due_date: str = ""
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""


def _default_fetcher(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "TraceHoundAI-lab",
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_kev_catalog(cve_id: str, raw_text: str) -> CISAKEVContext:
    wanted = cve_id.strip().upper()
    try:
        payload = json.loads(raw_text or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid KEV catalog: {exc}") from exc
    vulns = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    for item in vulns:
        if not isinstance(item, dict):
            continue
        if str(item.get("cveID", "")).upper() != wanted:
            continue
        return CISAKEVContext(
            cve_id=wanted, known_exploited=True, kev_status="listed",
            date_added=str(item.get("dateAdded", "") or ""),
            due_date=str(item.get("dueDate", "") or ""),
            vendor_project=str(item.get("vendorProject", "") or ""),
            product=str(item.get("product", "") or ""),
            vulnerability_name=str(item.get("vulnerabilityName", "") or ""))
    return CISAKEVContext(cve_id=wanted, known_exploited=False, kev_status="not_listed")


def check_kev(
    cve_id: str,
    catalog_text: Optional[str] = None,
    timeout: int = 30,
    fetcher: Optional[Callable[[str, int], str]] = None,
) -> tuple[CISAKEVContext, str]:
    """Return (KEVContext, catalog_text). Pass catalog_text to reuse one fetch."""
    raw_text = catalog_text if catalog_text is not None else (
        fetcher or _default_fetcher)(KEV_URL, timeout)
    return parse_kev_catalog(cve_id, raw_text), raw_text
