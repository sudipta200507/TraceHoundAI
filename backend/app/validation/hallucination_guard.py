"""Hallucination guard (Phase 9) — deterministic entity grounding checks.

Flags: nonexistent Evidence IDs, nonexistent CVEs, unsupported
technologies/services/ports/endpoints/versions, claims stronger than the
cited evidence status, and AI-created `verified` status without
verification evidence. Example: evidence says `nginx`, the model says
`nginx 1.18.0` with no evidence containing `1.18.0` -> REJECT/FLAG.
"""

from __future__ import annotations

import re
from typing import Any

from backend.app.ai.schemas.finding import AIFinding

_VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")
_EXPLOIT_TOKENS = ("exploit", "payload", "msfvenom", "sqlmap",
                   "reverse shell",
                   "rm -rf", "meterpreter", "ransomware")
# Traversal / sensitive-file examples are payload-adjacent content that must
# never appear in attack-path hypotheses (they also trip secret scanning).
_PAYLOAD_PATH_TOKENS = ("../", "etc/passwd", "etc/shadow", "<script>")

def _corpus(evidence: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for item in evidence:
        for key in ("observed_value", "normalized_value", "target", "type", "source"):
            value = item.get(key, "")
            if value:
                parts.append(str(value))
        metadata = item.get("metadata", {}) or {}
        for value in metadata.values():
            if isinstance(value, (str, int, float)):
                parts.append(str(value))
            elif isinstance(value, list):
                parts.extend(str(v) for v in value if isinstance(v, (str, int, float)))
    return "\n".join(parts).lower()


def _finding_text(finding: AIFinding) -> str:
    return "\n".join([finding.title, finding.description, finding.reasoning] +
                     list(finding.observed_facts))


def check_finding(
    finding: AIFinding,
    evidence_by_id: dict[str, dict[str, Any]],
    verified_cves: set[str],
) -> list[str]:
    """Return a list of hallucination flags; empty means grounded."""
    flags: list[str] = []
    cited = [evidence_by_id[e] for e in finding.evidence_ids if e in evidence_by_id]
    for eid in finding.evidence_ids:
        if eid not in evidence_by_id:
            flags.append(f"nonexistent Evidence ID: {eid}")
    if not cited:
        return flags or ["no citable evidence"]
    text = _finding_text(finding)
    body = _corpus(cited)
    verified = {c.upper() for c in verified_cves}

    for cve in sorted(set(re.findall(r"CVE-(?:19\d{2}|20\d{2})-\d{4,7}", text.upper()))):
        if cve not in verified:
            flags.append(f"nonexistent/unsupported CVE: {cve}")
    for cve in finding.cves:
        if cve.upper() not in verified:
            flags.append(f"unsupported CVE entity: {cve}")

    for field, label in ((finding.technologies, "technology"),
                         (finding.services, "service"),
                         (finding.endpoints, "endpoint")):
        for entity in field:
            if entity and entity.lower() not in body:
                flags.append(f"unsupported {label}: {entity}")
    for port in finding.ports:
        digits = re.sub(r"\D", "", str(port))
        if digits and digits not in body:
            flags.append(f"unsupported port: {port}")
    for version in finding.versions:
        if version and version not in body:
            flags.append(f"unsupported version: {version}")
    for version in sorted(set(_VERSION_RE.findall(text))):
        if version not in body:
            flags.append(f"hallucinated version detail: {version}")

    if finding.verification_status == "verified":
        backed = any(str(e.get("status", "")).lower() == "verified" for e in cited)
        if not backed:
            flags.append("AI-created verified status without verification evidence")
    if finding.classification == "verified_finding" and not any(
            str(e.get("status", "")).lower() == "verified" for e in cited):
        flags.append("claim stronger than evidence status: verified_finding "
                     "without verified evidence")

    lowered = text.lower()
    for token in _EXPLOIT_TOKENS:
        if token in lowered:
            flags.append(f"executable/exploit content forbidden: {token}")
            break
    return sorted(set(flags))
