"""Report validator (Phase 10) — final_report.md is written only when clean.

Checks: finding IDs present; every finding cites evidence; every cited ID
exists in this scan; no cross-scan IDs; no invented CVEs; no false
`verified` claims; no out-of-scope assets listed as authorized; valid
severity/confidence; no secrets in rendered text.
"""

from __future__ import annotations

import re
from typing import Any

from backend.app.reporting.renderer import render_report
from backend.app.reporting.report_builder import SEVERITIES, ReportContext

_CVE_RE = re.compile(r"CVE-(?:19\d{2}|20\d{2})-\d{4,7}")
_SECRET_RES = (
    re.compile(r"api[_-]?key\s*[:=]", re.I),
    re.compile(r"\bapikey\b", re.I),
    re.compile(r"\bpasswd\b", re.I),
    re.compile(r"\bpassword\s*[:=]", re.I),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY", re.I),
    re.compile(r"\bbearer\s+[A-Za-z0-9._-]{8,}", re.I),
    re.compile(r"NVD_API_KEY", re.I),
)


def validate_report_context(ctx: ReportContext) -> list[str]:
    problems: list[str] = []
    known_ids = {row["id"] for row in ctx.evidence_table}
    allowed_hosts: set[str] = set()
    for domain in (ctx.scope.get("allowed_domains", []) or []):
        allowed_hosts.add(str(domain).lower())
    for sub in (ctx.scope.get("allowed_subdomains", []) or []):
        allowed_hosts.add(str(sub).lower())
    # Scan-root boundaries use the same dot-anchored rule as the safety gate:
    # exact root match or a proper ".root" subdomain — never naive endswith.
    root_domains = [str(r).lower()
                    for r in (ctx.scope.get("allowed_root_domains", []) or [])]

    def _in_scope(hostname: str) -> bool:
        host = hostname.lower()
        if host in allowed_hosts:
            return True
        return any(host == root or host.endswith("." + root) for root in root_domains)
    verified_cves = {v.cve_id.upper() for v in ctx.verified_cves}
    status_of = {row["id"]: str(row.get("status", "")).lower()
                 for row in ctx.evidence_table}
    scan_of = {row["id"]: str(row.get("scan", "") or "")
               for row in ctx.evidence_table}

    for finding in ctx.findings:
        if not finding.finding_id:
            problems.append("finding without an ID")
        if not finding.evidence_ids:
            problems.append(f"{finding.finding_id or '?'}: no evidence IDs")
        for eid in finding.evidence_ids:
            if eid not in known_ids:
                problems.append(f"{finding.finding_id}: nonexistent Evidence ID {eid}")
            elif scan_of.get(eid) and scan_of[eid] != ctx.metadata.scan_id:
                problems.append(f"{finding.finding_id}: cross-scan Evidence ID {eid}")
        if finding.severity not in SEVERITIES:
            problems.append(f"{finding.finding_id}: invalid severity {finding.severity}")
        if not (0.0 <= finding.confidence <= 1.0):
            problems.append(f"{finding.finding_id}: confidence out of range")
        text = " ".join([finding.title, finding.description, finding.reasoning]).upper()
        for cve in set(_CVE_RE.findall(text)):
            if cve not in verified_cves:
                problems.append(f"{finding.finding_id}: nonexistent CVE {cve}")
        if finding.verification_status == "verified" and not any(
                status_of.get(eid) == "verified" for eid in finding.evidence_ids):
            problems.append(f"{finding.finding_id}: false verified status")

    if allowed_hosts or root_domains:
        for asset in ctx.assets:
            if not _in_scope(asset.hostname):
                problems.append(f"out-of-scope asset listed: {asset.hostname}")

    try:
        rendered = render_report(ctx)
    except Exception as exc:
        return problems + [f"template rendering failed: {exc}"]
    for pattern in _SECRET_RES:
        if pattern.search(rendered):
            problems.append(f"possible secret in report: {pattern.pattern[:32]}")
            break
    void_markers = (re.compile(r"\btodo\b(?!s)", re.I),
                    re.compile(r"\blorem ipsum\b", re.I),
                    re.compile(r"\bfixme\b", re.I))
    if any(pattern.search(rendered) for pattern in void_markers):
        problems.append("placeholder text in report")
    return sorted(set(problems))


def assert_valid(ctx: ReportContext) -> ReportContext:
    problems = validate_report_context(ctx)
    if problems:
        raise ValueError("; ".join(problems))
    return ctx
