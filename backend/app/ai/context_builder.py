"""Bounded deterministic context builder (Phase 9) — evidence IDs preserved.

Priority order (highest first):
  1. verified vulnerability context
  2. vulnerability evidence
  3. services
  4. technologies
  5. endpoints
  6. other evidence
Raw scanner blobs are never dumped; raw_reference pointers are kept.
"""

from __future__ import annotations

from typing import Any, Optional

PRIORITY_ORDER = ("vulnerability", "service", "technology", "endpoint", "other")


def _evidence_line(evidence: dict[str, Any]) -> str:
    eid = evidence.get("id", "?")
    return (
        f"[{eid}] type: {evidence.get('type', '')} | "
        f"source: {evidence.get('source', '')} | "
        f"target: {evidence.get('target', '')} | "
        f"observed: {evidence.get('observed_value', '')} | "
        f"normalized: {evidence.get('normalized_value', '')} | "
        f"status: {evidence.get('status', '')}"
    )


def _priority_key(evidence: dict[str, Any]) -> int:
    etype = str(evidence.get("type", "")).lower()
    if etype == "vulnerability":
        return 0
    if etype == "service":
        return 1
    if etype == "technology":
        return 2
    if etype == "endpoint":
        return 3
    return 4


def build_context(
    scan_snapshot: dict[str, Any],
    max_chars: int = 12000,
) -> str:
    """Assemble a bounded analysis context from a deterministic scan snapshot."""
    scan_id = scan_snapshot.get("scan_id", "")
    target = scan_snapshot.get("target", "")
    scope = scan_snapshot.get("scope", {})
    evidence = list(scan_snapshot.get("evidence", []) or [])
    verified = scan_snapshot.get("verified_context", {}) or {}
    hosts = scan_snapshot.get("live_hosts", []) or []
    relations = scan_snapshot.get("relationships", []) or []

    sections: list[str] = [
        f"SCAN scan_id={scan_id} target={target}",
        f"SCOPE allowed_domains={scope.get('allowed_domains', [])}",
    ]
    findings = verified.get("findings", []) if isinstance(verified, dict) else []
    if findings:
        lines = ["VERIFIED SECURITY CONTEXT (deterministic, authoritative):"]
        for item in findings:
            lines.append(
                f"- {item.get('cve_id', '')} scanner_observed={item.get('scanner_observed', False)} "
                f"nvd_confirmed={item.get('nvd_confirmed', False)} "
                f"known_exploited={item.get('known_exploited', False)} "
                f"evidence={item.get('evidence_ids', [])}")
        sections.append("\n".join(lines))
    if hosts:
        sections.append("LIVE HOSTS: " + ", ".join(str(h) for h in hosts[:50]))

    ordered = sorted(evidence, key=_priority_key)
    ev_lines = ["EVIDENCE (authoritative; cite IDs for every factual claim):"]
    budget = max_chars - sum(len(s) for s in sections) - 500
    used = 0
    included = 0
    for item in ordered:
        line = _evidence_line(item)
        if used + len(line) > max(budget, 0):
            break
        ev_lines.append(line)
        used += len(line)
        included += 1
    if included < len(ordered):
        ev_lines.append(f"[... {len(ordered) - included} further evidence records "
                        "omitted by budget; available via raw_reference]")
    sections.append("\n".join(ev_lines))
    if relations:
        sections.append("RELATIONSHIPS: " + "; ".join(str(r) for r in relations[:30]))
    return "\n\n".join(sections)


def evidence_index(
    evidence: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Map Evidence ID -> record for validator lookups."""
    return {str(item.get("id")): item for item in evidence if item.get("id")}


def verified_cve_set(verified_context: Optional[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for item in ((verified_context or {}).get("findings", []) or []):
        cve = str(item.get("cve_id", "")).upper()
        if cve:
            out.add(cve)
    return out
