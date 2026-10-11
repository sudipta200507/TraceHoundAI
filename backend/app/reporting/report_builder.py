"""Report data preparation (Phase 10) — deterministic, presentation-free.

All counting, sorting, priority derivation, and "Not available" handling
happens here in Python. Jinja2 templates only format precomputed values.
Nothing here invents findings, CVEs, severities, or Evidence IDs.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

SEVERITIES = ("info", "low", "medium", "high", "critical")
PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

PIPELINE_STAGES = (
    "Asset discovery",
    "DNS/live-host discovery",
    "Port/service discovery",
    "Technology fingerprinting",
    "Endpoint discovery",
    "Screenshot capture",
    "Vulnerability verification",
    "NVD/CISA KEV enrichment",
    "AI-assisted analysis",
    "Evidence validation",
    "Report generation",
)


class ReportMetadata(BaseModel):
    scan_id: str = ""
    target: str = ""
    generated_at: str = ""
    duration: str = ""
    model: str = "qwen3:8b"
    model_runtime: str = "Ollama"
    pipeline_version: str = "Phase 10"


class ReportAsset(BaseModel):
    hostname: str
    status: str = "in-scope"
    ip: str = ""
    urls: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list)
    port_details: list[dict[str, str]] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    technology_details: list[dict[str, str]] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)


class ReportFinding(BaseModel):
    finding_id: str = Field(min_length=1)
    title: str = ""
    classification: str = "hypothesis"
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    confidence: float = Field(ge=0.0, le=1.0)
    verification_status: str = "unverified"
    description: str = ""
    observed_facts: list[str] = Field(default_factory=list)
    reasoning: str = ""
    evidence_ids: list[str] = Field(min_length=1)
    evidence_rows: list[dict[str, str]] = Field(default_factory=list)
    next_manual_steps: list[str] = Field(default_factory=list)


class ReportRecommendation(BaseModel):
    recommendation_id: str = ""
    text: str = ""
    priority: Literal["Critical", "High", "Medium", "Low", "Informational"] = "Medium"
    rationale: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)


class ReportAttackPath(BaseModel):
    attack_path_id: str = ""
    title: str = ""
    starting_asset: str = ""
    steps: list[dict[str, str]] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    status: str = "hypothesis"


class VerifiedCVEEntry(BaseModel):
    cve_id: str
    scanner_observed: bool = False
    nvd_status: str = "unknown"
    cvss_score: Optional[float] = None
    severity: str = ""
    kev_status: str = "unknown"
    known_exploited: bool = False
    evidence_ids: list[str] = Field(default_factory=list)


class ReportContext(BaseModel):
    metadata: ReportMetadata = Field(default_factory=ReportMetadata)
    scope: dict[str, Any] = Field(default_factory=dict)
    methodology: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    assets: list[ReportAsset] = Field(default_factory=list)
    findings: list[ReportFinding] = Field(default_factory=list)
    evidence_table: list[dict[str, str]] = Field(default_factory=list)
    verified_cves: list[VerifiedCVEEntry] = Field(default_factory=list)
    attack_paths: list[ReportAttackPath] = Field(default_factory=list)
    recommendations: list[ReportRecommendation] = Field(default_factory=list)
    screenshots: list[dict[str, str]] = Field(default_factory=list)
    raw_references: list[str] = Field(default_factory=list)
    executive_summary: str = ""
    synthetic: bool = False
    # Concise-report additions (all deterministic summaries of the same
    # data — nothing invented, nothing dropped from the appendix/inventory).
    risk_overview: dict[str, Any] = Field(default_factory=dict)
    port_groups: list[dict[str, Any]] = Field(default_factory=list)
    tech_groups: list[dict[str, Any]] = Field(default_factory=list)
    endpoint_stats: dict[str, Any] = Field(default_factory=dict)
    security_endpoints: list[dict[str, str]] = Field(default_factory=list)
    security_endpoints_total: int = 0
    security_endpoints_truncated: bool = False
    cited_evidence: list[dict[str, str]] = Field(default_factory=list)
    linked_remediation: dict[str, list[dict[str, str]]] = Field(default_factory=dict)
    inventory_counts: dict[str, int] = Field(default_factory=dict)


# Ports whose mere exposure is worth calling out in the risk overview.
# Only listed when OBSERVED — presence here is a fact, not a verdict.
SENSITIVE_PORTS = {
    "21": "FTP", "23": "Telnet", "25": "SMTP", "110": "POP3", "143": "IMAP",
    "3306": "MySQL", "3389": "RDP", "5432": "PostgreSQL", "5900": "VNC",
    "6379": "Redis", "27017": "MongoDB", "9200": "Elasticsearch",
}

# URL-path tokens that make an endpoint security-relevant for the main
# report. Everything else stays in the appendix/inventory, byte-identical.
SENSITIVE_PATH_TOKENS = (
    "admin", "login", "wp-login", ".env", ".git", "actuator", "swagger",
    "graphql", "graphiql", "phpinfo", "console", "debug", "test", "backup",
    ".bak", ".old", ".sql", ".zip", ".rar", "credential", "token", "auth",
    "signin", "signup", "dashboard", "manage", "server-status", "server-info",
    "elmah", "trace.axd", "web.config", "_profiler", "api/", "api-docs",
    ".svn", ".hg", "composer.json", "package.json", "security.txt",
)

MAIN_REPORT_SECURITY_ENDPOINT_CAP = 100

_EXT_CATEGORY = {
    ".js": "scripts", ".mjs": "scripts", ".ts": "scripts",
    ".css": "styles", ".less": "styles", ".scss": "styles",
    ".png": "images", ".jpg": "images", ".jpeg": "images", ".gif": "images",
    ".svg": "images", ".ico": "images", ".webp": "images",
    ".json": "data", ".xml": "data",
    ".pdf": "documents", ".txt": "documents", ".md": "documents",
    ".zip": "archives", ".rar": "archives", ".tar": "archives", ".gz": "archives",
    ".bak": "archives", ".old": "archives", ".sql": "archives",
    ".php": "pages", ".asp": "pages", ".aspx": "pages", ".html": "pages",
    ".htm": "pages",
}


def _path_extension(path: str) -> str:
    lower = (path or "").lower().split("?")[0]
    if "." not in lower.rsplit("/", 1)[-1]:
        return "(no extension)"
    return "." + lower.rsplit(".", 1)[-1][:10]


def _sensitive_reason(path: str) -> str:
    lowered = (path or "").lower()
    for token in SENSITIVE_PATH_TOKENS:
        if token in lowered:
            return token
    return ""


def _group_ports(assets: list[ReportAsset]) -> list[dict[str, Any]]:
    buckets: dict[tuple, dict[str, Any]] = {}
    for asset in assets:
        details = asset.port_details or [
            {"port": p.split("/")[0],
             "protocol": (p.split("/")[1] if "/" in p else "tcp"),
             "service": "", "version": ""} for p in asset.ports]
        for entry in details:
            key = (str(entry.get("port", "")), str(entry.get("protocol", "") or "tcp"),
                   str(entry.get("service", "") or ""))
            bucket = buckets.setdefault(key, {
                "port": key[0], "protocol": key[1], "service": key[2],
                "versions": set(), "hosts": set()})
            if entry.get("version"):
                bucket["versions"].add(str(entry["version"]))
            bucket["hosts"].add(asset.hostname)
    groups = []
    for (port, _proto, _svc), bucket in sorted(
            buckets.items(), key=lambda kv: (kv[0][0].zfill(5), kv[0][1], kv[0][2])):
        hosts = sorted(bucket["hosts"])
        groups.append({"port": bucket["port"], "protocol": bucket["protocol"],
                       "service": bucket["service"] or "—",
                       "versions": sorted(bucket["versions"]) or ["—"],
                       "host_count": len(hosts), "sample_hosts": hosts[:5]})
    return groups


def _group_technologies(assets: list[ReportAsset]) -> list[dict[str, Any]]:
    buckets: dict[tuple, set[str]] = {}
    for asset in assets:
        details = asset.technology_details or [
            {"name": t, "version": ""} for t in asset.technologies]
        for tech in details:
            key = (str(tech.get("name", "") or ""), str(tech.get("version", "") or ""))
            if not key[0]:
                continue
            buckets.setdefault(key, set()).add(asset.hostname)
    groups = []
    for (name, version), hosts in sorted(buckets.items(),
                                         key=lambda kv: (-len(kv[1]), kv[0][0])):
        ordered = sorted(hosts)
        groups.append({"name": name, "version": version or "—",
                       "host_count": len(ordered), "sample_hosts": ordered[:5]})
    return groups


def _endpoint_statistics(assets: list[ReportAsset]) -> dict[str, Any]:
    total = 0
    by_ext: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    per_host: list[dict[str, Any]] = []
    for asset in assets:
        count = len(asset.endpoints)
        total += count
        per_host.append({"hostname": asset.hostname, "endpoints": count})
        for endpoint in asset.endpoints:
            ext = _path_extension(endpoint)
            by_ext[ext] = by_ext.get(ext, 0) + 1
            cat = _EXT_CATEGORY.get(ext, "other/dynamic")
            by_cat[cat] = by_cat.get(cat, 0) + 1
    per_host.sort(key=lambda r: (-r["endpoints"], r["hostname"]))
    return {
        "total": total,
        "by_extension": [{"extension": e, "count": c}
                         for e, c in sorted(by_ext.items(), key=lambda kv: -kv[1])[:12]],
        "by_category": [{"category": c, "count": n}
                        for c, n in sorted(by_cat.items(), key=lambda kv: -kv[1])],
        "top_hosts": per_host[:10],
    }


def _security_relevant_endpoints(assets: list[ReportAsset]) -> tuple[list[dict[str, str]], int, bool]:
    matched: list[dict[str, str]] = []
    for asset in assets:
        for endpoint in sorted(set(asset.endpoints)):
            reason = _sensitive_reason(endpoint)
            if reason:
                matched.append({"hostname": asset.hostname, "path": endpoint,
                                "reason": reason})
    matched.sort(key=lambda r: (r["hostname"], r["path"]))
    total = len(matched)
    truncated = total > MAIN_REPORT_SECURITY_ENDPOINT_CAP
    return matched[:MAIN_REPORT_SECURITY_ENDPOINT_CAP], total, truncated


def build_inventory_document(ctx: ReportContext) -> dict[str, Any]:
    """Complete raw inventories for appendix/downloads — every row the main
    report summarizes. Byte-identical source data, no filtering."""
    return {
        "scan_id": ctx.metadata.scan_id,
        "target": ctx.metadata.target,
        "generated_at": ctx.metadata.generated_at,
        "generator": "TraceHoundAI inventory export",
        "counts": dict(ctx.inventory_counts),
        "assets": [a.model_dump(mode="json") for a in ctx.assets],
        "evidence": list(ctx.evidence_table),
        "verified_cves": [v.model_dump(mode="json") for v in ctx.verified_cves],
        "screenshots": list(ctx.screenshots),
    }


def build_endpoints_csv_rows(ctx: ReportContext) -> list[list[str]]:
    """Flattened endpoint inventory: hostname, path, security-relevant flag.

    Faithful dump — every crawled endpoint row is preserved (no dedup), so
    the CSV matches inventory.json exactly.
    """
    security_paths = {(r["hostname"], r["path"]) for r in ctx.security_endpoints}
    rows = [["hostname", "path", "security_relevant"]]
    for asset in sorted(ctx.assets, key=lambda a: a.hostname):
        for endpoint in sorted(asset.endpoints):
            flag = "yes" if (asset.hostname, endpoint) in security_paths else "no"
            rows.append([asset.hostname, endpoint, flag])
    return rows


def _norm_list(value: Any) -> list[str]:
    if not value:
        return []
    return [str(v) for v in (value if isinstance(value, list) else [value])]


def _priority_for(
    ai_priority: str,
    rec_cves: set[str],
    kev_listed: set[str],
    nvd_confirmed: set[str],
) -> str:
    """Deterministic rule: KEV-linked -> Critical; NVD-confirmed -> High;
    otherwise map the AI priority. AI severity is never rewritten elsewhere."""
    if rec_cves & kev_listed:
        return "Critical"
    if rec_cves & nvd_confirmed:
        return "High"
    mapping = {"high": "High", "medium": "Medium", "low": "Low"}
    return mapping.get(ai_priority.strip().lower(), "Informational")


def build_report_context(snapshot: dict[str, Any]) -> ReportContext:
    """Assemble a sorted, counted, presentation-ready context from validated data."""
    scan_id = str(snapshot.get("scan_id", "") or "")
    if not scan_id:
        raise ValueError("scan snapshot requires scan_id")
    target = str(snapshot.get("target", "") or "")
    evidence = list(snapshot.get("evidence", []) or [])
    by_id = {str(e.get("id")): e for e in evidence if e.get("id")}
    scope = dict(snapshot.get("scope", {}) or {})
    verified = snapshot.get("verified_context", {}) or {}
    ai_analysis = snapshot.get("ai_analysis", {}) or {}

    assets = sorted(
        (ReportAsset(
            hostname=str(a.get("hostname", "")),
            status=str(a.get("status", "in-scope") or "in-scope"),
            ip=str(a.get("ip", "") or ""),
            urls=sorted(_norm_list(a.get("urls"))),
            ports=sorted(_norm_list(a.get("ports"))),
            technologies=sorted(_norm_list(a.get("technologies"))),
            endpoints=sorted(_norm_list(a.get("endpoints"))))
         for a in (snapshot.get("assets", []) or []) if a.get("hostname")),
        key=lambda a: a.hostname)

    findings: list[ReportFinding] = []
    for item in snapshot.get("findings", []) or ai_analysis.get("findings", []) or []:
        rows = [{"id": eid,
                 "type": str(by_id[eid].get("type", "")) if eid in by_id else "",
                 "source": str(by_id[eid].get("source", "")) if eid in by_id else "",
                 "target": str(by_id[eid].get("target", "")) if eid in by_id else "",
                 "observation": str(by_id[eid].get("observed_value", ""))
                 if eid in by_id else ""}
                for eid in _norm_list(item.get("evidence_ids"))]
        findings.append(ReportFinding(
            finding_id=str(item.get("finding_id", "")),
            title=str(item.get("title", "") or ""),
            classification=str(item.get("classification", "hypothesis") or "hypothesis"),
            severity=str(item.get("severity", "medium") or "medium").lower(),
            confidence=float(item.get("confidence", 0.0)),
            verification_status=str(item.get("verification_status", "unverified")
                                    or "unverified"),
            description=str(item.get("description", "") or ""),
            observed_facts=[str(f) for f in (item.get("observed_facts", []) or [])],
            reasoning=str(item.get("reasoning", "") or ""),
            evidence_ids=_norm_list(item.get("evidence_ids")),
            evidence_rows=rows,
            next_manual_steps=[str(s) for s in (item.get("next_manual_steps", []) or [])]))
    findings.sort(key=lambda f: f.finding_id)

    evidence_table = sorted(
        ({"id": str(e.get("id", "")), "type": str(e.get("type", "")),
          "source": str(e.get("source", "")), "target": str(e.get("target", "")),
          "observation": str(e.get("observed_value", "")),
          "status": str(e.get("status", "") or ""),
          "scan": str((e.get("metadata", {}) or {}).get("scan_id", ""))} for e in evidence),
        key=lambda r: r["id"])

    verified_cves = sorted(
        (VerifiedCVEEntry(
            cve_id=str(v.get("cve_id", "")),
            scanner_observed=bool(v.get("scanner_observed", False)),
            nvd_status=str(v.get("nvd_status", "unknown") or "unknown"),
            cvss_score=v.get("cvss_score"),
            severity=str(v.get("severity", "") or ""),
            kev_status=str(v.get("kev_status", "unknown") or "unknown"),
            known_exploited=bool(v.get("known_exploited", False)),
            evidence_ids=sorted(_norm_list(v.get("evidence_ids"))))
         for v in (verified.get("findings", []) or []) if v.get("cve_id")),
        key=lambda v: v.cve_id)
    kev_listed = {v.cve_id for v in verified_cves if v.known_exploited}
    nvd_confirmed = {v.cve_id for v in verified_cves
                     if v.nvd_status == "confirmed_by_nvd"}

    attack_paths = sorted(
        (ReportAttackPath(
            attack_path_id=str(p.get("attack_path_id", "")),
            title=str(p.get("title", "") or ""),
            starting_asset=str(p.get("starting_asset", "") or ""),
            steps=[{k: str(v) for k, v in (s or {}).items()}
                   for s in (p.get("steps", []) or [])],
            evidence_ids=sorted(_norm_list(p.get("evidence_ids"))),
            confidence=float(p.get("confidence", 0.0)),
            status="hypothesis")
         for p in (snapshot.get("attack_paths", []) or []) if p.get("attack_path_id")),
        key=lambda p: p.attack_path_id)

    cve_of_evidence: dict[str, set[str]] = {}
    for v in verified_cves:
        for eid in v.evidence_ids:
            cve_of_evidence.setdefault(eid, set()).add(v.cve_id)
    recommendations: list[ReportRecommendation] = []
    for item in ai_analysis.get("recommendations", []) or []:
        eids = sorted(_norm_list(item.get("evidence_ids")))
        rec_cves = set().union(*(cve_of_evidence.get(e, set()) for e in eids))
        recommendations.append(ReportRecommendation(
            recommendation_id=str(item.get("recommendation_id", "")),
            text=str(item.get("text", "") or ""),
            priority=_priority_for(str(item.get("priority", "medium") or "medium"),
                                   rec_cves, kev_listed, nvd_confirmed),
            rationale=str(item.get("rationale", "") or ""),
            evidence_ids=eids, finding_ids=[]))
    recommendations.sort(key=lambda r: (PRIORITY_ORDER[r.priority], r.recommendation_id))

    screenshots = sorted(
        ({"hostname": str(s.get("hostname", "")),
          "url": str(s.get("url", "") or ""),
          "path": str(s.get("path", "") or ""),
          "status": str(s.get("status", "") or "")}
         for s in (snapshot.get("screenshots", []) or []) if s.get("hostname")),
        key=lambda s: s["hostname"])

    raw_references = sorted({str(e.get("raw_reference", ""))
                             for e in evidence if e.get("raw_reference")})
    # Methodology is authoritative from the scan snapshot (per-stage
    # checkpoints). The static PIPELINE_STAGES list is only the fallback for
    # legacy snapshots that already carry finished "stages_run" names.
    provided = snapshot.get("methodology") or []
    if provided:
        methodology = list(provided)
    else:
        stages_run = set(snapshot.get("stages_run", []) or [])
        methodology = [{"stage": stage, "ran": stage in stages_run}
                       for stage in PIPELINE_STAGES]

    def _as_count(value: Any) -> Any:
        """Numeric zero is a real result; only None/missing means unavailable."""
        if value is None:
            return "Not available"
        try:
            return int(value)
        except (TypeError, ValueError):
            return "Not available"

    summary = {
        "assets": len(assets),
        # A present zero (the pipeline always computes counts) is a real
        # result rendered as 0; only a missing key means "Not available".
        "live_hosts": _as_count(snapshot.get("live_host_count")),
        "open_ports": _as_count(snapshot.get("open_port_count")),
        "technologies": _as_count(snapshot.get("technology_count")),
        "endpoints": _as_count(snapshot.get("endpoint_count")),
        "vulnerabilities_observed": len(verified_cves),
        "nvd_confirmed": len([v for v in verified_cves
                              if v.nvd_status == "confirmed_by_nvd"]),
        "kev_listed": len([v for v in verified_cves if v.known_exploited]),
        "ai_findings": len(findings),
    }

    # Concise-report summaries — deterministic views of the same data.
    port_groups = _group_ports(assets)
    tech_groups = _group_technologies(assets)
    endpoint_stats = _endpoint_statistics(assets)
    security_endpoints, security_total, security_truncated = \
        _security_relevant_endpoints(assets)

    sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    highest = "none"
    for finding in findings:
        if sev_rank.get(finding.severity, 0) > sev_rank.get(highest, 0):
            highest = finding.severity
    observed_sensitive_ports = []
    for group in port_groups:
        label = SENSITIVE_PORTS.get(str(group["port"]))
        if label:
            observed_sensitive_ports.append({
                "port": group["port"], "protocol": group["protocol"],
                "service": group["service"], "label": label,
                "host_count": group["host_count"]})
    risk_overview = {
        "highest_severity": highest,
        "finding_count": len(findings),
        "hypothesis_count": len([f for f in findings
                                 if f.classification == "hypothesis"]),
        "kev_cves": sorted(v.cve_id for v in verified_cves if v.known_exploited),
        "nvd_cves": sorted(v.cve_id for v in verified_cves
                           if v.nvd_status == "confirmed_by_nvd"),
        "sensitive_ports": observed_sensitive_ports,
    }

    # Evidence cited anywhere in the main report (findings, recommendations,
    # attack paths, verified CVEs) — the only rows the main report prints.
    # The full table stays in the context for the validator + appendix.
    cited_ids: set[str] = set()
    for finding in findings:
        cited_ids.update(finding.evidence_ids)
    for rec in recommendations:
        cited_ids.update(rec.evidence_ids)
    for path in attack_paths:
        cited_ids.update(path.evidence_ids)
    for entry in verified_cves:
        cited_ids.update(entry.evidence_ids)
    cited_evidence = [row for row in evidence_table if row["id"] in cited_ids]

    # Deterministic finding -> remediation links via shared evidence IDs.
    # Only the LLM's own recommendation text is reused; nothing is invented.
    finding_eids = {f.finding_id: set(f.evidence_ids) for f in findings}
    linked_remediation: dict[str, list[dict[str, str]]] = {}
    for finding in findings:
        links = [{"recommendation_id": r.recommendation_id, "text": r.text,
                  "priority": r.priority}
                 for r in recommendations
                 if set(r.evidence_ids) & finding_eids.get(finding.finding_id, set())]
        links.sort(key=lambda r: (PRIORITY_ORDER.get(r["priority"], 9),
                                  r["recommendation_id"]))
        linked_remediation[finding.finding_id] = links

    inventory_counts = {
        "assets": len(assets),
        "evidence_rows": len(evidence_table),
        "endpoints": int(endpoint_stats["total"]),
        "screenshots": len(screenshots),
    }
    return ReportContext(
        metadata=ReportMetadata(
            scan_id=scan_id, target=target,
            generated_at=str(snapshot.get("generated_at", "") or ""),
            duration=str(snapshot.get("duration", "") or ""),
            model=str(snapshot.get("model", "qwen3:8b") or "qwen3:8b")),
        scope=scope, methodology=methodology, summary=summary, assets=assets,
        findings=findings, evidence_table=evidence_table,
        verified_cves=verified_cves, attack_paths=attack_paths,
        recommendations=recommendations, screenshots=screenshots,
        raw_references=raw_references,
        executive_summary=str(snapshot.get("executive_summary", "") or ""),
        synthetic=bool(snapshot.get("synthetic", False)),
        risk_overview=risk_overview, port_groups=port_groups,
        tech_groups=tech_groups, endpoint_stats=endpoint_stats,
        security_endpoints=security_endpoints,
        security_endpoints_total=security_total,
        security_endpoints_truncated=security_truncated,
        cited_evidence=cited_evidence,
        linked_remediation=linked_remediation,
        inventory_counts=inventory_counts)
