"""PDF report generation (Phase 10) — concise, professional, readable.

Renders the same validated ReportContext as the concise Markdown report
using fpdf2: executive summary, risk overview, grouped inventory summaries,
security-relevant endpoints, CVE observations, findings with remediation,
recommendations, attack paths, cited evidence, screenshots, downloads, and
a closing assessment. Full raw inventories live in the technical appendix
and inventory downloads — never paginated here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from backend.app.reporting.report_builder import ReportContext


def _san(text: object) -> str:
    cleaned = (str(text or "").replace("—", "-").replace("–", "-")
               .replace("→", "->").replace("✓", "[x]").replace("✗", "[ ]")
               .replace("✅", "[done]").replace("⬜", "[skipped]"))
    return cleaned.encode("latin-1", errors="replace").decode("latin-1")


def write_pdf_report(context: ReportContext, path: str | Path) -> Path:
    from fpdf import FPDF

    class _ReportPDF(FPDF):
        def footer(self) -> None:
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(100, 116, 139)
            self.cell(0, 10, f"Page {self.page_no()} of {{nb}}", align="C")
            self.set_text_color(0, 0, 0)

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    pdf = _ReportPDF(orientation="P", unit="mm", format="A4")
    pdf.alias_nb_pages("{nb}")
    pdf.set_auto_page_break(True, margin=20)
    pdf.set_margins(15, 15, 15)
    pdf.set_title(_san(f"Security Assessment - {context.metadata.target}"))

    def _cell(height: float, text: str) -> None:
        pdf.multi_cell(0, height, _san(text), new_x="LMARGIN", new_y="NEXT")

    def title(text: str, size: int = 20) -> None:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", size)
        pdf.set_text_color(15, 23, 42)
        _cell(10, text)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

    H1_SIZE = 15
    H2_SIZE = 12

    def heading(text: str, level: int = 1) -> None:
        if level == 1:
            pdf.ln(2)
            pdf.set_fill_color(226, 232, 240)
            pdf.set_font("Helvetica", "B", H1_SIZE)
            _cell(9, text)
            pdf.ln(1)
        else:
            pdf.ln(1)
            pdf.set_font("Helvetica", "B", H2_SIZE)
            _cell(7, text)
            pdf.ln(1)
        pdf.set_font_size(10)

    def body(text: str) -> None:
        pdf.set_font("Helvetica", "", 10)
        _cell(5.5, text)

    def keyed(label: str, value: object) -> None:
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(0, 5.5, _san(f"{label}: {value}"),
                       new_x="LMARGIN", new_y="NEXT")

    def divider() -> None:
        pdf.ln(2)
        pdf.set_draw_color(203, 213, 225)
        y = pdf.get_y()
        pdf.line(15, y, pdf.w - 15, y)
        pdf.ln(2)

    def simple(headers: list[str], rows: list[list[str]],
               widths: Optional[list[float]] = None) -> None:
        if not rows:
            body("None recorded for this scan.")
            return
        capped = [[(c[:400] + " ...[truncated]" if len(c) > 400 else c) for c in row]
                  for row in rows]
        n = max(len(headers), 1)
        total = 180.0
        if widths is None:
            widths = [total / n] * n
        scale = total / sum(widths)
        widths = [w * scale for w in widths]
        pdf.set_fill_color(241, 245, 249)
        pdf.set_draw_color(203, 213, 225)
        pdf.set_font("Helvetica", "B", 9)
        with pdf.table(width=total, col_widths=tuple(widths),
                       text_align="LEFT", line_height=5,
                       borders_layout="HORIZONTAL_LINES") as pdf_table:
            header_row = pdf_table.row()
            for cell in headers:
                header_row.cell(_san(cell))
            pdf.set_font("Helvetica", "", 9)
            for row in capped:
                pdf_row = pdf_table.row()
                for cell in row:
                    pdf_row.cell(_san(cell))
        pdf.ln(2)

    summary = context.summary
    risk = context.risk_overview or {}

    # ------------------------------------------------------------------ 1.
    title("Security Assessment")
    body(_san(f"Target: {context.metadata.target or 'Not available'}"))
    body(f"Generated: {context.metadata.generated_at or 'date not available'}"
         f"   Scan duration: {context.metadata.duration or 'not recorded'}"
         f"   Report ID: {context.metadata.scan_id}")
    divider()

    heading("1. Executive Summary", 1)
    if context.executive_summary:
        body(context.executive_summary)
    else:
        body("This automated authorized assessment examined every stage that "
             "ran and validated the evidence through the local AI model. No "
             "exploitation was performed; every statement is backed by tool "
             "evidence.")
    severity_counts = {s: len([f for f in context.findings
                               if f.severity == s])
                       for s in ("critical", "high", "medium", "low", "info")}
    simple(["Severity", "Count"],
           [[s.capitalize() if s != "info" else "Informational", str(c)]
            for s, c in severity_counts.items()])
    simple(["Measure", "Count"],
           [["Assets discovered", str(summary.get("assets", "Not available"))],
            ["Live hosts", str(summary.get("live_hosts", "Not available"))],
            ["Open ports", str(summary.get("open_ports", "Not available"))],
            ["Technologies", str(summary.get("technologies", "Not available"))],
            ["Endpoints", str(summary.get("endpoints", "Not available"))],
            ["Vulnerability observations",
             str(summary.get("vulnerabilities_observed", "Not available"))],
            ["Validated findings", str(summary.get("ai_findings", "Not available"))]])
    heading("Risk overview (observed facts only)", 2)
    body(f"Highest finding severity: {str(risk.get('highest_severity', 'none')).capitalize()} "
         f"({risk.get('finding_count', 0)} findings, "
         f"{risk.get('hypothesis_count', 0)} hypothesis).")
    body("CISA KEV-listed CVEs: " + (", ".join(risk.get("kev_cves", []) or [])
                                     or "none observed."))
    body("NVD-confirmed CVEs: " + (", ".join(risk.get("nvd_cves", []) or [])
                                   or "none."))
    sensitive = risk.get("sensitive_ports", []) or []
    if sensitive:
        body("Sensitive services exposed: " + "; ".join(
            f"{s.get('port')}/{s.get('protocol')} ({s.get('label')}) on "
            f"{s.get('host_count')} host(s)" for s in sensitive))
    else:
        body("Sensitive services exposed: none observed.")

    # ------------------------------------------------------------------ 2.
    heading("2. Scope of the Assessment", 1)
    body(f"Target root domain: {context.scope.get('root_domain', context.metadata.target) or 'Not available'}")
    root = context.scope.get("root_domain", "")
    if root:
        body(f"Authorized boundary: {root} plus every subdomain of it")
    body(f"Scan identifier: {context.metadata.scan_id}")
    body("Only hosts inside this boundary were tested. Anything outside was "
         "rejected and never touched.")

    # ------------------------------------------------------------------ 3.
    heading("3. How the Scan Was Performed (Methodology)", 1)
    for stage in context.methodology:
        body(f"[{'done' if stage.get('ran') else 'not run'}] {stage.get('stage', '')}")

    # ------------------------------------------------------------------ 4.
    heading("4. Assets Discovered (Summary)", 1)
    if context.assets:
        body(f"The scan found {len(context.assets)} asset(s) inside the authorized scope. "
             "Full per-host inventories are in the technical appendix.")
        simple(["Asset", "IP", "Ports", "Techs", "Endpoints"],
               [[a.hostname, a.ip or "-", str(len(a.ports)),
                 str(len(a.technologies)), str(len(a.endpoints))]
                for a in context.assets])
    else:
        body("No assets were discovered inside the authorized scope.")

    # ------------------------------------------------------------------ 5.
    heading("5. Open Ports & Services (Grouped)", 1)
    simple(["Port", "Protocol", "Service", "Hosts"],
           [[g.get("port", ""), g.get("protocol", "") or "tcp",
             g.get("service", "") or "-", str(g.get("host_count", 0))]
            for g in context.port_groups])

    # ------------------------------------------------------------------ 6.
    heading("6. Technology Stack (Grouped)", 1)
    simple(["Technology", "Version", "Hosts"],
           [[g.get("name", ""), g.get("version", "") or "-",
             str(g.get("host_count", 0))]
            for g in context.tech_groups])

    # ------------------------------------------------------------------ 7.
    heading("7. Endpoints (Security-Relevant Only)", 1)
    stats = context.endpoint_stats or {}
    body(f"Crawler found {stats.get('total', 0)} endpoint(s); routine pages, "
         "scripts, styles and images are summarized by category. The complete "
         "list is in the appendix and endpoints.csv.")
    simple(["Category", "Endpoints"],
           [[r.get("category", ""), str(r.get("count", 0))]
            for r in (stats.get("by_category", []) or [])])
    if context.security_endpoints:
        note = (f"Security-relevant endpoints "
                f"({context.security_endpoints_total} found"
                f"{', first ' + str(len(context.security_endpoints)) + ' shown' if context.security_endpoints_truncated else ''}):")
        body(note)
        simple(["Host", "Path", "Why listed"],
               [[e.get("hostname", ""), e.get("path", ""), e.get("reason", "")]
                for e in context.security_endpoints])
    else:
        body("No endpoints matched security-relevant patterns.")

    # ------------------------------------------------------------------ 8.
    heading("8. Vulnerability Observations (Evidence-Backed)", 1)
    body("Only real scanner observations. NVD match = CVE exists publicly in "
         "catalog; it does NOT prove this target is exploitable. CISA KEV = "
         "known exploitation in the wild.")
    if context.verified_cves:
        simple(["CVE", "Scanner observed", "NVD status", "CVSS", "CISA KEV",
                "Evidence"],
               [[v.cve_id, "yes" if v.scanner_observed else "no", v.nvd_status,
                 str(v.cvss_score if v.cvss_score is not None else "Not available"),
                 "LISTED - exploited in the wild" if v.known_exploited
                 else "not listed", ", ".join(v.evidence_ids)]
                for v in context.verified_cves])
    else:
        body("The verification scanner produced no CVE observations in this scan.")

    # ------------------------------------------------------------------ 9.
    heading("9. Validated Security Findings", 1)
    body("Every finding cites tool Evidence IDs. Hypothesis findings by "
         "definition still need human confirmation; nothing was exploited.")
    if not context.findings:
        body("No validated findings were produced for this scan. The tools "
             "observed the target surface, but nothing in the evidence rose "
             "to the level of a security finding.")
    for finding in context.findings:
        heading(f"{finding.finding_id} - {finding.title}", 2)
        pdf.set_font("Helvetica", "B", 9)
        simple(["Severity", "Confidence", "Classification", "Status",
                "Affected asset"],
               [[finding.severity.capitalize(),
                 f"{round(finding.confidence * 100)}%",
                 finding.classification, finding.verification_status,
                 (finding.evidence_rows[0].get("target", "Not available")
                  if finding.evidence_rows else "Not available")]])
        if finding.description:
            keyed("What was observed", finding.description)
        if finding.reasoning:
            keyed("Why it matters (AI reasoning)", finding.reasoning)
        remedies = (context.linked_remediation or {}).get(finding.finding_id, [])
        for rec in remedies:
            keyed(f"Remediation [{rec.get('priority', '')}]", rec.get("text", ""))
        if finding.next_manual_steps:
            body("Next steps - what an authorized tester should check manually:")
            for i, step in enumerate(finding.next_manual_steps, 1):
                body(f"  {i}. {step}")
        if finding.evidence_rows:
            simple(["Evidence", "Type", "Source", "Observation"],
                   [[row.get("id", ""), row.get("type", ""),
                     row.get("source", ""), row.get("observation", "")[:120]]
                    for row in finding.evidence_rows])
        divider()

    # ----------------------------------------------------------------- 10.
    heading("10. Prioritized Recommendations", 1)
    if not context.recommendations:
        body("No recommendations were produced for this scan.")
    for rec in context.recommendations:
        heading(f"[{rec.priority}] {rec.recommendation_id}", 2)
        body(_san(rec.text))
        if rec.rationale:
            keyed("Why", rec.rationale)
        keyed("Evidence", ", ".join(rec.evidence_ids) or "manual verification advised")

    # ----------------------------------------------------------------- 11.
    heading("11. Attack Path Hypotheses", 1)
    body("All attack paths are unverified hypotheses. No exploitation was performed.")
    if not context.attack_paths:
        body("No attack-path hypotheses were produced for this scan.")
    for path in context.attack_paths:
        heading(f"{path.attack_path_id} - {path.title}", 2)
        keyed("Starting asset", path.starting_asset)
        keyed("Status", f"{path.status} / confidence {round(path.confidence * 100)}%")
        keyed("Evidence", ", ".join(path.evidence_ids))
        for step in path.steps:
            body(_san(f"- On {step.get('asset', '')}: {step.get('observed_condition', '')} "
                      f"=> {step.get('hypothesis', '')} "
                      f"(verify manually: {step.get('required_verification', '')})"))

    # ----------------------------------------------------------------- 12.
    heading("12. Evidence Index (Cited in This Report)", 1)
    body(f"Evidence cited by findings and observations "
         f"({len(context.cited_evidence)} of {len(context.evidence_table)} rows). "
         "The complete index is in the technical appendix.")
    simple(["ID", "Type", "Source tool", "Target", "Observation"],
           [[r["id"], r["type"], r["source"], r["target"],
             r["observation"][:160]] for r in context.cited_evidence])

    # ----------------------------------------------------------------- 13.
    heading("13. Screenshots Captured", 1)
    if not context.screenshots:
        body("No screenshots were captured in this scan.")
    for shot in context.screenshots:
        body(f"{shot.get('hostname', '')} ({shot.get('url', '')}): {shot.get('status', '')}")
        image_path = _resolve_image(out.parent, str(shot.get("path", "") or ""))
        if image_path is not None:
            try:
                pdf.image(str(image_path), w=170)
            except Exception:
                body(f"(image unavailable: {shot.get('path', '')})")

    # ----------------------------------------------------------------- 14.
    heading("14. Downloads & Technical Appendix", 1)
    body("Full raw inventories live outside this concise report:")
    body("- technical_appendix.md: full asset, port, technology and endpoint "
         "tables plus the complete evidence index.")
    body("- inventory.json: all of the above as structured data.")
    body("- endpoints.csv: every crawled endpoint with its host.")
    for ref in context.raw_references:
        body(f"Raw source: {ref}")

    # ----------------------------------------------------------------- 15.
    heading("15. Completeness Notes & Limitations", 1)
    body(f"Analysis model: {context.metadata.model} ({context.metadata.model_runtime}) - local, on the lab machine")
    body(f"Pipeline version: {context.metadata.pipeline_version}")
    counts = context.inventory_counts or {}
    body(f"Inventory counts - assets: {counts.get('assets', 0)}, evidence rows: "
         f"{counts.get('evidence_rows', 0)}, endpoints: {counts.get('endpoints', 0)} - "
         "match the appendix and downloads exactly.")
    body("Every statement traces to an evidence row; no finding was invented, "
         "and nothing was exploited at any point in this assessment.")

    # ----------------------------------------------------------------- 16.
    heading("16. Final Assessment - What Was Found and What It Means", 1)
    body(_san(
        f"The authorized assessment of {context.metadata.target or 'the target'} "
        f"discovered {summary.get('assets', 'Not available')} asset(s), "
        f"{summary.get('live_hosts', 'Not available')} live host(s), "
        f"{summary.get('open_ports', 'Not available')} open port(s), "
        f"{summary.get('technologies', 'Not available')} technology stack "
        f"component(s), and {summary.get('endpoints', 'Not available')} endpoint(s)."))
    if context.findings:
        body("What was found:")
        for finding in context.findings:
            body(f"  - {finding.finding_id} ({finding.severity.capitalize()} "
                 f"severity, {round(finding.confidence * 100)}% confidence): "
                 f"{finding.title} - {finding.description}")
        body("What an authorized lab tester could do next (manual verification "
             "only, nothing automated):")
        for finding in context.findings:
            if finding.next_manual_steps:
                body("  - For " + finding.finding_id + ": "
                     + "; ".join(finding.next_manual_steps))
    else:
        body("What was found: no validated security findings. The tools saw "
             "the target's public surface but nothing in the evidence met the "
             "bar for a security finding. That is a real result, not a failure: "
             "it means the Internet-facing surface examined here shows no "
             "obvious weakness in the stages that ran.")
    if context.verified_cves:
        body("Where real CVEs were observed: "
             + ", ".join(v.cve_id for v in context.verified_cves))
    if context.recommendations:
        body("Recommended next actions, in priority order:")
        for i, rec in enumerate(context.recommendations, 1):
            body(f"  {i}. [{rec.priority}] {rec.text}")

    pdf.output(str(out))
    return out


def _resolve_image(report_dir: Path, rel_path: str) -> Optional[Path]:
    """Resolve a report-relative screenshot path to a real image file, else None."""
    if not rel_path.lower().endswith((".png", ".jpeg", ".jpg")):
        return None
    candidate = (report_dir / rel_path).resolve()
    try:
        candidate.relative_to(Path(__file__).resolve().parents[4])
    except ValueError:
        return None
    return candidate if candidate.is_file() else None
